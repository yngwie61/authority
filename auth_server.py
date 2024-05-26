from flask import Flask, request, jsonify, redirect
import jwt
from jwcrypto import jwk
import datetime
import hashlib
import base64
import ssl
import json
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# JWKセットを生成
key = jwk.JWK.generate(kty='RSA', size=2048)
key.kid = "auth_key1"  # 一意なkid値を設定
public_key = key.export(private_key=False)
private_key = key.export(private_key=True)
public_pem_key = key.export_to_pem(private_key=False, password=None)
private_pem_key = key.export_to_pem(private_key=True, password=None)
key_dict = {}
key_dict[key.kid] = {"pub":public_pem_key, "pri":private_pem_key}
jwks = {"keys": [public_key]}

# access token のヘッダー設定
access_token_header = {
    "kid": "auth_key1",
    "alg": "RS256",
    "typ": "JWT"
}

TENANT_DOMAIN = "https://auth_server.local:5002"
ISSUER = "https://auth_server.local:5002/"

# Client Application Settings
clients = {
    "app1": {
        "iss": ISSUER,
        "aud": ["https://api_server.local:5001"],
        "redirect_uri": "https://client.local:5003/callback"
    }
}

# User Settings
users = {
    "user1": {
        "password": "password",
        "permissions": ["secure-data:read"]
    }
}

codes = {}  # Store the authorization codes along with code challenges for PKCE

def generate_code_challenge(code_verifier):
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode('utf-8').replace('=', '')
    return code_challenge

@app.route('/.well-known/openid-configuration')
def openid_configuration():
    config = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{TENANT_DOMAIN}/authorize",
        "token_endpoint": f"{TENANT_DOMAIN}/token",
        "jwks_uri": f"{TENANT_DOMAIN}/.well-known/jwks.json",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name"]
    }
    return jsonify(config)


@app.route('/.well-known/jwks.json')
def jwks_endpoint():
    return jsonify(jwks)

@app.route('/authorize', methods=['GET'])
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    code_challenge = request.args.get('code_challenge')
    code_challenge_method = request.args.get('code_challenge_method', 'S256')

    if client_id in clients and clients[client_id]['redirect_uri'] == redirect_uri:
        return f'''
            <form method="post" action="/login?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&code_challenge={code_challenge}&code_challenge_method={code_challenge_method}">
                <input type="text" name="username" placeholder="Username" required />
                <input type="password" name="password" placeholder="Password" required />
                <button type="submit">Login</button>
            </form>
        '''
    return jsonify({"error": "Invalid client"}), 400

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    code_challenge = request.args.get('code_challenge')
    code_challenge_method = request.args.get('code_challenge_method')

    if username in users and users[username]["password"] == password:
        authorized_user_info = users[username]
        code = jwt.encode({"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=3)}, "secret", algorithm="HS256")
        codes[code] = {"code_challenge": code_challenge, "code_challenge_method": code_challenge_method, "authorized_user_info": authorized_user_info}
        return redirect(f"{redirect_uri}?code={code}&state={state}")

    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/token', methods=['POST'])
def token():
    code = request.form['code']
    client_id = request.form['client_id']
    redirect_uri = request.form['redirect_uri']
    code_verifier = request.form['code_verifier']

    if code in codes and client_id in clients and clients[client_id]['redirect_uri'] == redirect_uri:
        code_challenge = codes[code]['code_challenge']
        code_challenge_method = codes[code]['code_challenge_method']
        
        if code_challenge_method == 'S256':
            expected_code_challenge = generate_code_challenge(code_verifier)
            if expected_code_challenge != code_challenge:
                return jsonify({"error": "Invalid code verifier"}), 401

        access_token_payload = {
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
            "scope": "",
            "aud": clients[client_id]["aud"],
            "iss": clients[client_id]["iss"],
            "permissions": codes[code]["authorized_user_info"]["permissions"]
        }
        del codes[code]  # Remove used code
        access_token = jwt.encode(access_token_payload, private_pem_key, algorithm="RS256", headers=access_token_header)
        return jsonify({"access_token": access_token})

    return jsonify({"error": "Invalid client credentials"}), 401

@app.route('/introspect', methods=['POST'])
def introspect():
    token = request.form['token']
    client_id = request.form['client_id']

    header_b64, payload_b64, signature_b64 = token.split(".")
    header = base64.b64decode(header_b64)
    header_json = json.loads(header.decode('utf-8'))

    if client_id in clients and header_json["typ"] == "JWT":
        try:
            if header_json["kid"] in key_dict:
                token_data = jwt.decode(token, public_pem_key, algorithms=[header_json["alg"]], options={"verify_aud": False})
                return jsonify({
                    'active': True,
                    'exp': token_data['exp']
                })
        except jwt.ExpiredSignatureError:
            return jsonify({'active': False}), 402
        except jwt.InvalidTokenError:
            return jsonify({'active': False}), 403

    return jsonify({'active': False}), 401

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain(certfile='certs/auth_server.crt', keyfile='certs/auth_server.key')
    app.run(host='0.0.0.0', port=5002, ssl_context=context, debug=True)
