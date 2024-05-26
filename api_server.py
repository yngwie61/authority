from flask import Flask, request, jsonify
import jwt
import requests
import ssl
from jwcrypto import jwk
import json
import base64
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

AUTH_SERVER_INTROSPECTION_ENDPOINT = "https://auth_server:5002/introspect"
AUTH_SERVER_JWKS_ENDPOINT = "https://auth_server.local:5002/.well-known/jwks.json"
CLIENT_ID = "client_id"

def validate_inclueded_meta(access_token):
    try:
        header_b64, payload_b64, signature_b64 = access_token.split(".")
        header = base64.b64decode(header_b64)
        header_json = json.loads(header.decode('utf-8'))
        
    except Exception as e:
        return None

    try:
        response = requests.get(AUTH_SERVER_JWKS_ENDPOINT, verify='certs/ca.crt')
        if not response.status_code == 200:
            return None
        jwks = response.json()
        if not jwks.get("keys"):
            return None
        # app.logger.info(jwks["keys"][0])
        for jwk_json in jwks["keys"]:
            jwk_key = jwk.JWK.from_json(jwk_json)
            if jwk_key.kid == header_json["kid"]:
                # JWTの署名を検証する
                public_pem_key = jwk_key.export_to_pem(private_key=False, password=None)
                decoded_token= jwt.decode(access_token, public_pem_key, algorithms=[header_json["alg"]], options={"verify_aud": False})
                return decoded_token

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def validate_introspection(access_token):
    try:
        # 認可サーバにトークンのインスペクションを依頼する        
        response = requests.post(AUTH_SERVER_INTROSPECTION_ENDPOINT, data={
            'token': access_token,
            'client_id': CLIENT_ID
        }, verify='certs/ca.crt')

        if response.status_code == 200:
            token_info = response.json()
            if token_info.get('active'):
                return token_info
        
        return None
    
    except Exception as e:
        return None

@app.route('/secure-data', methods=['GET'])
def secure_data():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Missing token"}), 401

    parts = auth_header.split()
    if parts[0].lower() != 'bearer' or len(parts) != 2:
        return jsonify({"message": "Invalid token format"}), 401

    access_token = parts[1]
    verified_token = validate_inclueded_meta(access_token)
    if not verified_token:
        return jsonify({"message": "Invalid token"}), 401

    return jsonify({"message": "Access granted", "verified_token": verified_token})

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(certfile='certs/api_server.crt', keyfile='certs/api_server.key')
    app.run(host='0.0.0.0', port=5001, ssl_context=context, debug=True)
