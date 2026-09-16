#!/usr/bin/env bash
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="*"

OUT="$(dirname "$0")/out"
cd "$OUT"

if [ ! -f ca.key ] || [ ! -f ca.crt ]; then
  echo "CA not found. Run generate_ca_and_server.sh first."
  exit 1
fi

# Fresh CA bookkeeping.
rm -f index.txt index.txt.attr crlnumber crl.pem
touch index.txt
echo "1000" > crlnumber

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
default_days      = 3650
policy            = policy_any
email_in_dn       = no
rand_serial       = no
unique_subject    = no
crl_extensions    = crl_ext

[ policy_any ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

# Register each existing device cert by importing it into the CA database
# using OpenSSL itself, so the stored subject format matches exactly.
for crt in *.crt; do
  name="${crt%.crt}"
  case "$name" in
    ca|server) continue ;;
  esac
  # 'openssl ca -valid' adds an existing cert to the database as valid.
  openssl ca -config ca_crl.cnf -valid "$crt" >/dev/null 2>&1 \
    && echo "Registered $name" \
    || echo "Could not register $name (may already be present)"
done

# Generate a fresh empty CRL.
openssl ca -config ca_crl.cnf -gencrl -out crl.pem >/dev/null 2>&1
echo "CA database rebuilt; empty CRL generated."