#!/usr/bin/env bash
# Fetch an ID token for a seeded user from the reference Dex and check its claims.
#
#   scripts/dex-token.sh <user> [--raw]
#
# DEV ONLY. It uses the OAuth2 password grant, which only the dev Dex config
# (deploy/compose/dex/config.dev.yaml) enables; the prod config refuses it.
#
#   DEX_TEST_PASSWORD          the user's password (required)
#   HARNESS_DEX_CLIENT_SECRET  secret of the agent-harness client (required)
#   DEX_URL                    issuer base. Default is the published dev issuer,
#                              reachable from the host. A container that runs
#                              this script sets DEX_URL=http://dex:5556/dex,
#                              because localhost is itself there.
#
# Prints the decoded claims (sub, email, groups, aud, azp, exp, iat). --raw
# prints only the token on stdout. The password, client secret, refresh token
# and (without --raw) the token are never printed.
set -euo pipefail

# Recipe values for the dev Dex.
DEX_URL="${DEX_URL:-http://localhost:5556/dex}"
CLIENT_ID=agent-harness
AUDIENCE=warden
SCOPE="openid email profile groups offline_access audience:server:client_id:warden"

die() {
	echo "dex-token: $*" >&2
	exit 1
}

usage() {
	echo "usage: dex-token.sh <user> [--raw]   (DEX_URL default: http://localhost:5556/dex)" >&2
	exit 2
}

user=""
raw=0
for a in "$@"; do
	case "$a" in
	--raw) raw=1 ;;
	-*) usage ;;
	*) [ -z "$user" ] && user="$a" || usage ;;
	esac
done
[ -n "$user" ] || usage

[ -n "${DEX_TEST_PASSWORD:-}" ] || die "DEX_TEST_PASSWORD is not set"
[ -n "${HARNESS_DEX_CLIENT_SECRET:-}" ] || die "HARNESS_DEX_CLIENT_SECRET is not set"
export DEX_TEST_PASSWORD HARNESS_DEX_CLIENT_SECRET

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
chmod 600 "$tmp"

# Secrets are read from the environment inside jq and sent on stdin, so none
# is ever on an argv.
code=$(jq -jn --arg u "$user" --arg c "$CLIENT_ID" --arg sc "$SCOPE" \
	'"grant_type=password&username=\($u|@uri)&password=\(env.DEX_TEST_PASSWORD|@uri)&client_id=\($c|@uri)&client_secret=\(env.HARNESS_DEX_CLIENT_SECRET|@uri)&scope=\($sc|@uri)"' |
	curl -sS -o "$tmp" -w '%{http_code}' -X POST \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		--data-binary @- "$DEX_URL/token") || die "token request to $DEX_URL/token failed"

if [ "$code" != 200 ]; then
	err=$(jq -r '.error // "unknown"' "$tmp" 2>/dev/null || echo unknown)
	die "token request failed: HTTP $code, error=$err"
fi

id=$(jq -r '.id_token // empty' "$tmp")
[ -n "$id" ] || die "response has no id_token"

seg=$(cut -d. -f2 <<<"$id" | tr '_-' '/+')
while [ $((${#seg} % 4)) -ne 0 ]; do seg="$seg="; done
payload=$(base64 -d <<<"$seg" 2>/dev/null) || die "id_token payload is not valid base64"
jq -e . >/dev/null 2>&1 <<<"$payload" || die "id_token payload is not JSON"

jq -e --arg a "$AUDIENCE" '(.aud | if type == "array" then . else [.] end) | index($a) != null' \
	>/dev/null 2>&1 <<<"$payload" || die "claim check failed: aud does not contain $AUDIENCE (aud=$(jq -c .aud <<<"$payload"))"
jq -e --arg c "$CLIENT_ID" '.azp == $c' >/dev/null 2>&1 <<<"$payload" ||
	die "claim check failed: azp is $(jq -c .azp <<<"$payload"), want $CLIENT_ID"
jq -e '(.exp - .iat) == 3600' >/dev/null 2>&1 <<<"$payload" ||
	die "claim check failed: exp-iat is $(jq -c '.exp - .iat' <<<"$payload"), want 3600"

if [ "$raw" -eq 1 ]; then
	printf '%s\n' "$id"
else
	jq '{sub, email, groups, aud, azp, exp, iat}' <<<"$payload"
fi
