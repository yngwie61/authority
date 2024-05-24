from flask import Flask, request, jsonify
import jwt
import requests
import ssl
from jwcrypto import jwk
import json
import base64

app = Flask(__name__)

AUTH_SERVER_INTROSPECTION_ENDPOINT = "https://auth_server:5002/introspect"
AUTH_SERVER_JWKS_ENDPOINT = "https://auth_server.local:5002/.well-known/jwks.json"
CLIENT_ID = "client_id"

def validate_access_token_locally(access_token):
    try:
        # JWTの署名を検証する
        decoded_token = jwt.decode(access_token, jwks_url=AUTH_SERVER_JWKS_ENDPOINT)

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def validate_access_token(access_token):
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
        
        print("Introspection response code is not 200")
        return None
    
    except Exception as e:
        print("Request Error")
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
    header_b64, payload_b64, signature_b64 = access_token.split(".")
    header = base64.b64decode(header_b64)
    header_json = json.loads(header.decode('utf-8'))

    token_data = validate_access_token(access_token)
    if not token_data:
        return jsonify({"message": "Invalid token"}), 401

    return jsonify({"message": "Access granted", "validated_token": token_data})

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(certfile='certs/api_server.crt', keyfile='certs/api_server.key')
    app.run(host='0.0.0.0', port=5001, ssl_context=context)
