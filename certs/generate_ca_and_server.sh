#!/usr/bin/env bash
set -euo pipefail

# Stop MinGW/Git Bash from rewriting the -subj argument into a Windows path.
export MSYS2_ARG_CONV_EXCL="*"

OUT="$(dirname "$0")/out"
mkdir -p "$OUT"
cd "$OUT"

# 1. Root Certificate Authority (our own private CA)
if [ ! -f ca.crt ]; then
  openssl req -new -x509 -days 3650 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "//C=IN/ST=Karnataka/L=Bengaluru/O=SecureIoT/CN=SecureIoT-Root-CA"
  echo "Created root CA."
else
  echo "CA already exists — reusing it."
fi

# 2. Broker (server) certificate. CN + SAN = localhost so TLS hostname
#    verification succeeds when clients connect to localhost.
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "//C=IN/ST=Karnataka/L=Bengaluru/O=SecureIoT/CN=localhost"

cat > server_ext.cnf <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 3650 -extfile server_ext.cnf

# The broker runs as a non-root user inside the container and must read this key.
chmod 644 server.key
rm -f server.csr server_ext.cnf
echo "Created broker server certificate."