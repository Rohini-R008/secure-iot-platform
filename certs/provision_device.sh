#!/usr/bin/env bash
set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: bash provision_device.sh <device-id>   (e.g. sensor-001)"
  exit 1
fi

DEVICE="$1"
OUT="$(dirname "$0")/out"
cd "$OUT"

if [ ! -f ca.crt ]; then
  echo "CA not found. Run: bash generate_ca_and_server.sh first."
  exit 1
fi

# Per-device key + certificate. The CN IS the device identity.
openssl genrsa -out "${DEVICE}.key" 2048
openssl req -new -key "${DEVICE}.key" -out "${DEVICE}.csr" \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=SecureIoT/CN=${DEVICE}"
openssl x509 -req -in "${DEVICE}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out "${DEVICE}.crt" -days 3650
rm -f "${DEVICE}.csr"
echo "Provisioned identity for device: ${DEVICE} (CN=${DEVICE})"