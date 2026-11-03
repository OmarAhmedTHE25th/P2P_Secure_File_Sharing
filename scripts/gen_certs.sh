#!/usr/bin/env bash
set -euo pipefail

# Keep generated development credentials out of the repository. Callers such as
# the end-to-end test can set CERT_DIR to place them in a temporary directory.
cert_dir="${CERT_DIR:-.}"
mkdir -p "$cert_dir"

key="$cert_dir/identity.key"
cert="$cert_dir/identity.crt"
trust="$cert_dir/trusted_peers.txt"

openssl ecparam -name prime256v1 -genkey -noout -out "$key"
chmod 600 "$key"
openssl req -new -x509 -sha256 -days 3650 \
    -key "$key" \
    -out "$cert" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

fingerprint="$(
    openssl x509 -in "$cert" -outform DER |
        openssl dgst -sha256 |
        awk '{print $NF}'
)"
printf '# Peers I trust: <SHA-256 fingerprint> <name>\n%s  local\n' "$fingerprint" > "$trust"

echo "Generated identity and trust list in $cert_dir"
