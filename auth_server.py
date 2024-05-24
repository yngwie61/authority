from flask import Flask, request, jsonify, redirect
import jwt
from jwcrypto import jwk
import datetime
import hashlib
import base64
import ssl
import json

app = Flask(__name__)

# JWKセットを生成
key = jwk.JWK.generate(kty='RSA', size=2048)
key.kid = "auth_key1"  # 一意なkid値を設定
public_key = key.export(private_key=False)
private_key = key.export(private_key=True)
public_pem_key = key.export_to_pem(private_key=False, password=None)
private_pem_key = key.export_to_pem(private_key=True, password=None)
key_dict = {}
key_dict[key.kid] = {"pub":public_pem_key, "pri":private_pem_key}
jwks = {"keys": [json.dumps(public_key)]}

# access token のヘッダー設定
access_token_header = {
    "kid": "auth_key1",
    "alg": "RS256",
    "typ": "JWT"
}

# Mock data
clients = {
    "client_id": {
        "scope": "secure-data:read",
        "aud": ["https://api_server.local:5001"],
        "redirect_uri": "https://client.local:5003/callback"
    }
}

users = {
    "user": "password"
}

codes = {}  # Store the authorization codes along with code challenges for PKCE

def generate_code_challenge(code_verifier):
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode('utf-8').replace('=', '')
    return code_challenge

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

    if username in users and users[username] == password:
        code = jwt.encode({"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=3)}, "secret", algorithm="HS256")
        codes[code] = {"code_challenge": code_challenge, "code_challenge_method": code_challenge_method}
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
        
        del codes[code]  # Remove used code
        access_token_payload = {
            "username": "test_client",
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
            "scope": "secure-data:read",
            "aud": ["https://api_server.local:5001"],
            "iss": "https://auth_server.local:5002"
        }
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
                    'username': token_data['username'],
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
    app.run(host='0.0.0.0', port=5002, ssl_context=context)
