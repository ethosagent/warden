#!/usr/bin/env bash
#
# gen.sh — generate every cert/key the e2e compose stack mounts, into this
# directory (gitignored). Run by `make e2e-up` when the certs are missing.
#
#   1. proxy-ca.crt/key          — the bake-once Warden CA (via the same
#                                  scripts/gen-certs.sh production path), so
#                                  agents trust the workers' TLS termination
#                                  and the CP can mint its server cert from it.
#   2. upstream-ca.crt/key +
#      upstream-server.crt      — a second, separate CA for the FAKE upstream
#                                  (api/llm/mcp/evil.example.test). Separate on
#                                  purpose: the fake upstream must never hold
#                                  the proxy CA's key.
#   3. upstream-ca-bundle.crt    — upstream-ca.crt PREPENDED to the host's
#                                  system CA bundle. Workers point
#                                  SSL_CERT_FILE at it (Go's system pool honors
#                                  SSL_CERT_FILE on Linux), so they verify the
#                                  fake upstream's leaf WITHOUT any Warden
#                                  config key for upstream trust, while still
#                                  trusting real CAs should a scenario dial out.
#
# Keys are written 0644 ON PURPOSE and never leave this directory (gitignored):
# the stack runs as the image's non-root `warden` user, and a bind-mount keeps
# host ownership, so a 0600 key owned by the host user would be unreadable by
# the container. These are throwaway lab keys minted for this harness only —
# gen-certs.sh's production 0600 rule does not apply here. Do not commit them.
set -euo pipefail

# Resolve this script's directory ONCE, absolutely, before any cd — the paths
# below must not depend on how the script was invoked.
E2E_CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$E2E_CERT_DIR"

DAYS="${DAYS:-3650}"

if ! command -v openssl >/dev/null 2>&1; then
	echo "openssl not found; it is required to generate the e2e certs." >&2
	exit 1
fi

# --- 1. proxy CA (shared production script; refuses to overwrite) ----------
# gen-certs.sh cd's to the repo root before writing, so OUT_DIR must be
# ABSOLUTE or the CA lands in the wrong place.
OUT_DIR="$E2E_CERT_DIR" "$E2E_CERT_DIR/../../../scripts/gen-certs.sh"

# --- 2. fake-upstream CA + leaf -------------------------------------------
SUBJ_UP_CA="/CN=Warden E2E Fake Upstream CA/O=Warden E2E"
LEAF_KEY="upstream-server.key"
LEAF_CRT="upstream-server.crt"
UP_CA_CRT="upstream-ca.crt"
UP_CA_KEY="upstream-ca.key"

if [ ! -f "$UP_CA_CRT" ] || [ ! -f "$UP_CA_KEY" ]; then
	openssl req -x509 -newkey rsa:4096 -nodes \
		-keyout "$UP_CA_KEY" -out "$UP_CA_CRT" \
		-days "$DAYS" -subj "$SUBJ_UP_CA" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign,cRLSign"
	echo "generated fake-upstream CA: $UP_CA_CRT / $UP_CA_KEY"
else
	echo "$UP_CA_CRT already exists — keeping it."
fi

# One leaf covers every name the fake upstream serves, plus its container name
# and pinned IP on the egress network (see docker-compose.e2e.yml).
if [ ! -f "$LEAF_CRT" ] || [ ! -f "$LEAF_KEY" ]; then
	openssl req -newkey rsa:2048 -nodes \
		-keyout "$LEAF_KEY" -out "$LEAF_KEY.csr" \
		-subj "/CN=api.example.test/O=Warden E2E"
	openssl x509 -req -in "$LEAF_KEY.csr" \
		-CA "$UP_CA_CRT" -CAkey "$UP_CA_KEY" -CAcreateserial \
		-days "$DAYS" -out "$LEAF_CRT" \
		-extfile <(cat <<EXT
subjectAltName = DNS:api.example.test,DNS:llm.example.test,DNS:mcp.example.test,DNS:evil.example.test,DNS:fakeupstream,IP:10.200.0.10,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EXT
		)
	rm -f "$LEAF_KEY.csr"
	echo "generated fake-upstream leaf: $LEAF_CRT (api/llm/mcp/evil.example.test + fakeupstream)"
else
	echo "$LEAF_CRT already exists — keeping it."
fi

# --- 3. the bundle workers see via SSL_CERT_FILE ---------------------------
SYSTEM_BUNDLE="${SSL_CERT_FILE:-}"
if [ -z "$SYSTEM_BUNDLE" ]; then
	# Common system bundle locations: Debian/Ubuntu, Fedora/RHEL, Alpine/macOS.
	for candidate in \
		/etc/ssl/certs/ca-certificates.crt \
		/etc/pki/tls/certs/ca-bundle.crt \
		/etc/ssl/cert.pem; do
		if [ -f "$candidate" ]; then
			SYSTEM_BUNDLE="$candidate"
			break
		fi
	done
fi

if [ -n "$SYSTEM_BUNDLE" ] && [ -f "$SYSTEM_BUNDLE" ]; then
	cat "$SYSTEM_BUNDLE" "$UP_CA_CRT" > upstream-ca-bundle.crt
	echo "built upstream-ca-bundle.crt = system bundle ($SYSTEM_BUNDLE) + fake CA"
else
	# No system bundle on this host: the fake CA alone still verifies every
	# in-stack upstream (DNS resolves only the fake names). Real-internet
	# verification would fail — acceptable for the hermetic harness, but say so.
	cat "$UP_CA_CRT" > upstream-ca-bundle.crt
	echo "WARNING: no system CA bundle found; upstream-ca-bundle.crt contains the fake CA only." >&2
fi

# 0644, not 0600 — see the header comment (non-root containers must read them).
chmod 644 ./*.key
echo "e2e certs ready in $(pwd)"
