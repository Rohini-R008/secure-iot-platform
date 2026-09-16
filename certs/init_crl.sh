#!/usr/bin/env bash
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="*"

OUT="$(dirname "$0")/out"
cd "$OUT"

if [ ! -f ca.key ] || [ ! -f ca.crt ]; then
  echo "CA not found. Run generate_ca_and_server.sh first."
  exit 1
fi

# OpenSSL CA bookkeeping files (needed to track revocations).
touch index.txt
[ -f crlnumber ] || echo "1000" > crlnumber

# Minimal CA config used for CRL operations.
cat > ca_crl.cnf <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
database          = ./index.txt
crlnumber         = ./crlnumber
certificate       = ./ca.crt
private_key       = ./ca.key
default_md        = sha256
default_crl_days  = 3650
crl_extensions    = crl_ext

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

# Generate an initial (empty) CRL.
openssl ca -config ca_crl.cnf -gencrl -out crl.pem
echo "Initialized CRL (empty). Devices are all currently valid."