#!/usr/bin/env bash
#
# gen-certs.sh — generate the bake-once proxy CA certificate + key.
#
# Why this exists: Warden terminates TLS so it can read URLs/headers/bodies and
# swap placeholder secrets for real ones. To do that, the wrapped agent must
# TRUST a cert that Warden holds. The flow per deployment shape:
#
#   1. Generate a CA cert/key here (once, baked into the image / mounted).
#   2. Warden presents leaf certs signed by this CA when terminating TLS.
#   3. The agent container trusts this CA (added to its trust store / env), so
#      its HTTPS clients accept Warden as the endpoint.
#
# The CA private key NEVER leaves the proxy boundary and is written to a
# gitignored location (default: ./certs, ignored in .gitignore). Do not commit
# generated keys.
set -euo pipefail

cd "$(dirname "$0")/.."

OUT_DIR="${OUT_DIR:-certs}"
CERT="${OUT_DIR}/proxy-ca.crt"
KEY="${OUT_DIR}/proxy-ca.key"
DAYS="${DAYS:-3650}"
SUBJECT="${SUBJECT:-/CN=Warden Proxy CA/O=Warden}"

mkdir -p "$OUT_DIR"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
	echo "cert/key already exist at ${OUT_DIR} — refusing to overwrite."
	echo "delete them first if you intend to regenerate."
	exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
	echo "openssl not found; install it or generate the CA via 'go run' equivalent." >&2
	exit 1
fi

openssl req -x509 -newkey rsa:4096 -nodes \
	-keyout "$KEY" -out "$CERT" \
	-days "$DAYS" -subj "$SUBJECT" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign"

chmod 600 "$KEY"

echo "generated bake-once proxy CA:"
echo "  cert: $CERT  (distribute to agent trust store)"
echo "  key : $KEY   (proxy-only; gitignored; never commit)"
