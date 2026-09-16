#!/usr/bin/env bash
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="*"

OUT="$(dirname "$0")/out"
cd "$OUT"

# For each device cert (excluding infra), add a line to index.txt so OpenSSL
# can later revoke it. Format of index.txt lines:
#   V<TAB>expiry<TAB><TAB>serial<TAB>unknown<TAB>subject
for crt in *.crt; do
  name="${crt%.crt}"
  case "$name" in
    ca|server) continue ;;   # skip infra certs; processor CAN be revoked too if needed
  esac

  serial=$(openssl x509 -in "$crt" -noout -serial | cut -d= -f2)
  # Expiry in the format YYMMDDHHMMSSZ that index.txt expects
  expiry=$(openssl x509 -in "$crt" -noout -enddate | cut -d= -f2)
  expiry_fmt=$(date -u -d "$expiry" +%y%m%d%H%M%SZ 2>/dev/null || echo "491231235959Z")
  subject=$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253 | sed 's/^subject= *//')

  # Only add if this serial isn't already recorded
  if ! grep -q "$serial" index.txt 2>/dev/null; then
    printf "V\t%s\t\t%s\tunknown\t%s\n" "$expiry_fmt" "$serial" "$subject" >> index.txt
    echo "Registered $name (serial $serial)"
  else
    echo "$name already registered"
  fi
done