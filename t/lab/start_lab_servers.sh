#!/usr/bin/env bash
# Start three local TLS targets used for manual verification of the
# tlsbaseline tooling:
#   127.0.0.1:14443  modern: TLS 1.2 only, ECDHE-GCM suites
#   127.0.0.1:14444  legacy: TLS 1.0 only, ALL suites at SECLEVEL=0
#   127.0.0.1:14445  TLS 1.3 only
# Port 14446 is deliberately left closed for the handshake-failure case.
#
# Usage: utils/../t/lab/start_lab_servers.sh ; stop with: pkill -f s_server

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$LAB_DIR/pki"
mkdir -p "$PKI_DIR"

make_pki() {
     local name="$1" cn="$2"
     if [[ ! -s "$PKI_DIR/$name.pem" ]]; then
          openssl req -x509 -newkey rsa:2048 \
               -keyout "$PKI_DIR/$name-key.pem" -out "$PKI_DIR/$name-cert.pem" \
               -days 2 -nodes -subj "/CN=$cn" >/dev/null 2>&1
          cat "$PKI_DIR/$name-key.pem" "$PKI_DIR/$name-cert.pem" \
               > "$PKI_DIR/$name.pem"
     fi
}

make_pki modern modern.local
make_pki legacy legacy.local

start() {
     local port="$1"; shift
     if ss -ltn | grep -q ":$port\s"; then
          echo "port $port already in use, skipping"
          return
     fi
     setsid openssl s_server -accept "$port" "$@" \
          > "$LAB_DIR/server-$port.log" 2>&1 < /dev/null &
     disown
     echo "started listener on 127.0.0.1:$port"
}

start 14443 -cert "$PKI_DIR/modern.pem" -tls1_2 \
     -cipher "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384" -www
start 14444 -cert "$PKI_DIR/legacy.pem" -tls1 \
     -cipher "ALL:@SECLEVEL=0" -www -legacy_renegotiation
start 14445 -cert "$PKI_DIR/modern.pem" -tls1_3 \
     -ciphersuites "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256" -www

# Bare "openssl s_client" capability checks in testssl.sh default to
# 127.0.0.1:4433; provide a listener so they return immediately.
start 4433 -cert "$PKI_DIR/modern.pem" -www

sleep 1
ss -ltn | grep -E ':(14443|14444|14445|4433)\s' || true
