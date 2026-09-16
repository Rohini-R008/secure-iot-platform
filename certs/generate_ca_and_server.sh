#!/usr/bin/env bash
set -euo pipefail

OUT="$(dirname "$0")/out"
mkdir -p "$OUT"
cd "$OUT"

# 1. Root Certificate Authority (our own private CA)
if [ ! -f ca.crt ]; then
  openssl req -new -x509 -days 3650 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=SecureIoT/CN=SecureIoT-Root-CA"
  echo "Created root CA."
else
  echo "CA already exists — reusing it."
fi

# 2. Broker (server) certificate. CN + SAN = localhost so TLS hostname
#    verification succeeds when clients connect to localhost.
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=SecureIoT/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 3650 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# The broker runs as a non-root user inside the container and must read this key.
chmod 644 server.key
rm -f server.csr
echo "Created broker server certificate."