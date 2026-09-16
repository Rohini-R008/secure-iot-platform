#!/usr/bin/env bash
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="*"

if [ -z "${1:-}" ]; then
  echo "Usage: bash revoke_device.sh <device-id>"
  exit 1
fi

DEVICE="$1"
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
OUT="${SCRIPT_DIR}/out"

# Locate openssl explicitly (works even with a minimal PATH).
OPENSSL=""
for cand in openssl /usr/bin/openssl /mingw64/bin/openssl \
            "/c/Program Files/Git/usr/bin/openssl.exe" \
            "/c/Program Files/Git/mingw64/bin/openssl.exe"; do
  if command -v "$cand" >/dev/null 2>&1; then OPENSSL="$cand"; break; fi
  if [ -x "$cand" ]; then OPENSSL="$cand"; break; fi
done
[ -z "$OPENSSL" ] && { echo "openssl not found"; exit 1; }

cd "$OUT" || { echo "cannot cd to $OUT"; exit 1; }
[ -f "${DEVICE}.crt" ] || { echo "Certificate ${DEVICE}.crt not found in $(pwd)"; exit 1; }

# Get this cert's serial number (uppercase, no colons).
SERIAL=$("$OPENSSL" x509 -in "${DEVICE}.crt" -noout -serial | cut -d= -f2)
[ -z "$SERIAL" ] && { echo "could not read serial from ${DEVICE}.crt"; exit 1; }

# If already revoked in index.txt, treat as success (idempotent).
if grep -qi "^R.*${SERIAL}" index.txt 2>/dev/null; then
  echo "REVOKED ${DEVICE} (already revoked, serial ${SERIAL}) — regenerating CRL."
  "$OPENSSL" ca -config ca_crl.cnf -gencrl -out crl.pem
  exit 0
fi

# Revoke by pointing at the cert file. Capture output to inspect on failure.
if ! "$OPENSSL" ca -config ca_crl.cnf -revoke "${DEVICE}.crt" >revoke_out.log 2>&1; then
  # Fallback: flip the index.txt entry to Revoked by serial, then regen.
  echo "Standard revoke failed; applying serial-based fallback for ${SERIAL}."
  TS=$(date -u +%y%m%d%H%M%SZ)
  # Change the line starting with V that contains this serial into an R line.
  awk -v s="$SERIAL" -v ts="$TS" '
    $0 ~ s && $1=="V" {
      # index.txt columns: status, expiry, [revoke-date], serial, filename, subject
      # Rebuild as revoked: R <expiry> <ts> <serial> <filename> <subject>
      print "R\t" $2 "\t" ts "\t" $3 "\t" $4 "\t" $5;
      next
    }
    { print }
  ' index.txt > index.txt.new && mv index.txt.new index.txt
fi
rm -f revoke_out.log

# Regenerate the CRL from the (now updated) database.
"$OPENSSL" ca -config ca_crl.cnf -gencrl -out crl.pem
echo "REVOKED ${DEVICE} — CRL updated (serial ${SERIAL})."