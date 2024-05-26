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
AUTH_SERVER_OPENID_CONFIGURATION_PATH = ".well-known/openid-configuration"
CLIENT_ID = "app1"
API_ENDPOINT = "https://api_server.local:5001"

def validate_inclueded_meta(access_token):
    try:
        header_json = jwt.get_unverified_header(access_token)
        payload_json = jwt.decode(access_token, options={"verify_signature": False})

    except Exception as e:
        return None

    try:
        iss = payload_json["iss"]
        AUTH_SERVER_OPENID_CONFIGURATION_URL = iss + AUTH_SERVER_OPENID_CONFIGURATION_PATH
        openid_configuration_response = requests.get(AUTH_SERVER_OPENID_CONFIGURATION_URL, verify='certs/ca.crt')
        if not openid_configuration_response.status_code == 200:
            return None
        openid_configurations = openid_configuration_response.json()
        app.logger.info(openid_configurations)
        jwks_uri_response = requests.get(openid_configurations["jwks_uri"], verify='certs/ca.crt')
        if not jwks_uri_response.status_code == 200:
            return None
        jwks = jwks_uri_response.json()
        if not jwks.get("keys"):
            return None
        for jwk_json in jwks["keys"]:
            jwk_key = jwk.JWK.from_json(jwk_json)
            if jwk_key.kid == header_json["kid"]:
                public_pem_key = jwk_key.export_to_pem(private_key=False, password=None)
                if not API_ENDPOINT in payload_json["aud"]:
                    app.logger.error(f"Audience does not includedes: {API_ENDPOINT}")
                    raise jwt.InvalidTokenError
                
                if not "secure-data:read" in payload_json["permissions"]:
                    app.logger.error(f"Permissions does not includes read role")
                    raise jwt.InvalidTokenError              

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
    app.logger.info(verified_token)
    if not verified_token:
        return jsonify({"message": "Invalid token"}), 401

    return jsonify({"message": "Access granted", "verified_token": verified_token})

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(certfile='certs/api_server.crt', keyfile='certs/api_server.key')
    app.run(host='0.0.0.0', port=5001, ssl_context=context, debug=True)
