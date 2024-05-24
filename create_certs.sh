#!/bin/bash

mkdir -p certs

# Create CA Key
openssl genpkey -algorithm RSA -out certs/ca.key

# Create CA Certificate
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 1024 -out certs/ca.crt -subj "/CN=ca.local"

# Create Server Key and CSR for auth_server
openssl genpkey -algorithm RSA -out certs/auth_server.key
openssl req -new -key certs/auth_server.key -out certs/auth_server.csr -subj "/CN=auth_server.local"
openssl x509 -req -in certs/auth_server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/auth_server.crt -days 500 -sha256 -extfile <(printf "subjectAltName=DNS:auth_server.local,DNS:auth_server")

# Create Server Key and CSR for api_server
openssl genpkey -algorithm RSA -out certs/api_server.key
openssl req -new -key certs/api_server.key -out certs/api_server.csr -subj "/CN=api_server.local"
openssl x509 -req -in certs/api_server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/api_server.crt -days 500 -sha256 -extfile <(printf "subjectAltName=DNS:api_server.local,DNS:api_server")

# Create Server Key and CSR for client
openssl genpkey -algorithm RSA -out certs/client.key
openssl req -new -key certs/client.key -out certs/client.csr -subj "/CN=client.local"
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client.crt -days 500 -sha256 -extfile <(printf "subjectAltName=DNS:client.local,DNS:client")

# Combine key and cert for server
cat certs/auth_server.key certs/auth_server.crt > certs/auth_server.pem
cat certs/api_server.key certs/api_server.crt > certs/api_server.pem
cat certs/client.key certs/client.crt > certs/client.pem
