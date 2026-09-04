#!/bin/bash

# Create a clean directory for certs
mkdir -p certs
cd certs

echo "Generating Root CA Private Key and Self-Signed Certificate..."
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=MyCA/CN=My Root CA" -addext "basicConstraints=critical,CA:TRUE"

echo "Generating Server Private Key and CSR (Common Name = 192.168.1.10)..."
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/C=US/ST=State/L=City/O=MyServer/CN=192.168.1.10"

echo "Signing Server CSR with Root CA to produce server.crt..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

echo "Certificates generated successfully in the certs/ directory!"

