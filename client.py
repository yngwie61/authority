import requests
import base64
import hashlib
import os
import time
import bs4
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib.parse


# Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def generate_code_verifier():
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').replace('=', '')
    return code_verifier

def generate_code_challenge(code_verifier):
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode('utf-8').replace('=', '')
    return code_challenge

code_verifier = generate_code_verifier()
code_challenge = generate_code_challenge(code_verifier)

# Step 1: Direct user to auth server
authorize_url = 'https://auth_server.local:5002/authorize'
authorize_params = {
    'response_type': 'code',
    'client_id': 'app1',
    'redirect_uri': 'https://client.local:5003/callback',
    'code_challenge': code_challenge,
    'code_challenge_method': 'S256',
    'state': 'xyz'
}

# Simulate user login and authorization
session = requests.Session()
response = session.get(authorize_url, params=authorize_params, verify='/app/certs/ca.crt')

# Simulate user filling out the login form
soup = bs4.BeautifulSoup(response.text, 'html.parser')
form = soup.find('form')
login_url = f"https://auth_server.local:5002{form.get('action')}"
login_data = {
    'username': 'user1',
    'password': 'password'
}

response = session.post(login_url, data=login_data, verify='/app/certs/ca.crt', allow_redirects=False)
redirect_location = response.headers['Location']

# Extract the authorization code from the redirect URL
parsed_url = urllib.parse.urlparse(redirect_location)
query_params = urllib.parse.parse_qs(parsed_url.query)
auth_code = query_params["code"][0]

# Step 2: Exchange authorization code for access token
token_url = 'https://auth_server.local:5002/token'
token_data = {
    'grant_type': 'authorization_code',
    'code': auth_code,
    'redirect_uri': 'https://client.local:5003/callback',
    'client_id': 'app1',
    'code_verifier': code_verifier
}

response = requests.post(token_url, data=token_data, verify='/app/certs/ca.crt')
token = response.json().get('access_token')
print("Access Token:", token)

# Step 3: Access secure API endpoint
headers = {'Authorization': f'Bearer {token}'}
response = requests.get('https://api_server.local:5001/secure-data', headers=headers, verify='certs/ca.crt')
print(response.json())
