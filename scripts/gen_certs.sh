#!/usr/bin/env bash
# Generates a self-signed DEVELOPMENT certificate (server.crt + server.key).
#
# Usage:  bash scripts/gen_certs.sh [--force] [extra-hostname-or-ip ...]
#   --force   replace existing certificate files
#   extras    names/IPs the certificate must also be valid for, e.g. a LAN address:
#             bash scripts/gen_certs.sh 192.168.1.20 my-laptop.local
#
# Files go in the project root, or in $CERT_DIR if that is set.
# The certificate is always valid for "localhost" and 127.0.0.1.
set -euo pipefail

force=0
extra=()
for arg in "$@"; do
    if [[ "$arg" == "--force" ]]; then force=1; else extra+=("$arg"); fi
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="${CERT_DIR:-$root}"
crt="$dir/server.crt"
key="$dir/server.key"

if [[ ( -e "$crt" || -e "$key" ) && $force -eq 0 ]]; then
    echo "server.crt / server.key already exist in $dir (use --force to replace them)." >&2
    exit 1
fi

# The name the client connects to must appear in this list, or the handshake is refused
san="DNS:localhost,IP:127.0.0.1"
for name in ${extra[@]+"${extra[@]}"}; do
    if [[ "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then san+=",IP:$name"; else san+=",DNS:$name"; fi
done

mkdir -p "$dir"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$key" -out "$crt" -days 365 \
    -subj "/CN=localhost" -addext "subjectAltName=$san" 2>/dev/null
chmod 600 "$key" 2>/dev/null || true

echo "Created $crt and $key"
echo "Valid for: $san"
