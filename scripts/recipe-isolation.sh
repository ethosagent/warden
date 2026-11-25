#!/usr/bin/env bash
#
# recipe-isolation.sh - prove the isolation of an identity compose recipe (W-P2-RCP-05).
#
#   scripts/recipe-isolation.sh <claude-code|codex>
#
# Brings the recipe's merged stack up from a clean state, hands alice's Dex token to
# the sidecar, and proves that the agent container
#   - has no route out except the forwarder (and through it the worker),
#   - holds no identity material, no JWT, no private key and no real vendor key,
#   - is attributed to the logged-in user, and is refused when its agent is disabled.
# Every check prints "PASS <name>" or "FAIL <name>"; the first failure prints the
# worker's last 50 log lines (JWT-shaped strings redacted) and exits non-zero. The
# stack is always removed on exit (docker compose down -v).
#
# It needs Docker with Compose v2, network access (images, npm, the vendor API host
# for one 401) and no real vendor key: the worker holds a sentinel and the upstream
# answers 401. The dev Dex placeholders of deploy/compose/dex/.env.example are used
# for any variable the caller has not set.
#
# The stack publishes fixed host ports (7070, 5556, 9091, 9092, 9094, 9095) and shares
# them with `make e2e`: hold the shared lock around a run,
#   flock /tmp/warden-e2e.lock scripts/recipe-isolation.sh codex
#
# Environment:
#   RECIPE_ISOLATION_COMPOSE_EXTRA  space-separated extra compose files merged last
#                                   (the negative self-tests use this)
#   RECIPE_ISOLATION_KEEP=1         INTERACTIVE DEBUGGING ONLY: leave the stack running on
#                                   exit. The stack holds fixed host ports (7070 ...) after
#                                   the lock is released, so it breaks every other run: never
#                                   use it while other stacks run, and tear it down yourself
#                                   (docker compose -p warden-recipe-<recipe> down -v).
#                                   The default always runs `docker compose down -v`.
#   RECIPE_ISOLATION_READY_TIMEOUT  seconds to wait for the first token exchange
#                                   (default 420: a fresh control plane holds back
#                                   its first token key for a few minutes)
#
# Never `set -x`: nothing here may echo a token.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RECIPE="${1:-}"
case "$RECIPE" in
claude-code)
	ALLOWED_HOST=api.anthropic.com
	KEY_ENV=ANTHROPIC_API_KEY
	REAL_KEY_SENTINEL=sk-ant-api03-recipeisolationsentinelnotarealkey
	PLACEHOLDER=anthropic_secret_001
	;;
codex)
	ALLOWED_HOST=api.openai.com
	KEY_ENV=OPENAI_API_KEY
	REAL_KEY_SENTINEL=sk-proj-recipeisolationsentinelnotarealkey
	PLACEHOLDER=openai_secret_001
	;;
*)
	echo "usage: scripts/recipe-isolation.sh <claude-code|codex>" >&2
	exit 2
	;;
esac
AGENT="$RECIPE"
AGENT_EMAIL=alice@example.org
PROJECT="warden-recipe-$RECIPE"
CA_PATH=/etc/warden/certs/proxy-ca.crt
READY_TIMEOUT="${RECIPE_ISOLATION_READY_TIMEOUT:-420}"
COMPOSE_DIR="$ROOT/deploy/compose"

JWT_RE='eyJ[A-Za-z0-9_-]{20,}'

for tool in docker jq curl openssl; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "recipe-isolation: $tool is required" >&2
		exit 2
	}
done

# Dev placeholders for every Dex variable the caller has not set.
while IFS='=' read -r k v; do
	case "$k" in '' | '#'*) continue ;; esac
	[ -n "$(printenv "$k" || true)" ] || export "$k=$v"
done <"$COMPOSE_DIR/dex/.env.example"
export "$KEY_ENV=$REAL_KEY_SENTINEL"

FILES=(
	-f "$COMPOSE_DIR/docker-compose.control-plane.yml"
	-f "$COMPOSE_DIR/docker-compose.identity.yml"
	-f "$COMPOSE_DIR/docker-compose.$RECIPE.yml"
)
EXTRA_FILES=()
for f in ${RECIPE_ISOLATION_COMPOSE_EXTRA:-}; do
	EXTRA_FILES+=(-f "$f")
done
SUBJECT_FILE=(-f "$COMPOSE_DIR/docker-compose.$RECIPE.subject-token.yml")
USE_SUBJECT_FILE=0

compose() {
	if [ "$USE_SUBJECT_FILE" = 1 ]; then
		docker compose -p "$PROJECT" "${FILES[@]}" "${SUBJECT_FILE[@]}" "${EXTRA_FILES[@]}" "$@"
	else
		docker compose -p "$PROJECT" "${FILES[@]}" "${EXTRA_FILES[@]}" "$@"
	fi
}

# ---- output, failure report, teardown ------------------------------------------

WORK="$(mktemp -d)"
OUT="$WORK/output.log"
: >"$OUT"
CREATED_CERTS=0
STACK_UP=0

say() {
	printf '%s\n' "$*" | tee -a "$OUT"
}

redact() {
	sed -E "s/$JWT_RE(\.[A-Za-z0-9_-]+)*/[REDACTED_JWT]/g"
}

worker_log() {
	compose logs --no-color --no-log-prefix --tail "${1:-5000}" warden 2>&1 || true
}

cleanup() {
	local rc=$?
	trap - EXIT
	if [ "$STACK_UP" = 1 ] && [ "${RECIPE_ISOLATION_KEEP:-0}" != 1 ]; then
		compose down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	if [ "$CREATED_CERTS" = 1 ] && [ "${RECIPE_ISOLATION_KEEP:-0}" != 1 ]; then
		rm -rf "$COMPOSE_DIR/certs"
	fi
	rm -rf "$WORK"
	exit "$rc"
}
trap cleanup EXIT

fail() {
	say "FAIL $1${2:+: $2}"
	say "--- last 50 worker log lines (JWT-shaped strings redacted) ---"
	worker_log 50 | tail -n 50 | redact | tee -a "$OUT"
	exit 1
}

# check <name> <function>: runs the function; it prints a reason to stdout and
# returns non-zero on failure.
check() {
	local name="$1" fn="$2" why
	if why="$("$fn" 2>&1)"; then
		say "PASS $name"
	else
		fail "$name" "$(printf '%s' "$why" | redact | tr '\n' ' ' | cut -c1-300)"
	fi
}

# ---- helpers inside the stack ----------------------------------------------------

# agent <cmd...>: run in the agent container as the image user.
agent() { compose exec -T "$AGENT" "$@"; }

# agent_sh <script>: run a POSIX shell script given on stdin... as an argument.
agent_sh() { compose exec -T "$AGENT" sh -c "$1"; }

# Allow decisions with a valid identity in the worker log for the allowed host.
allow_lines() {
	worker_log | jq -c --arg d "$ALLOWED_HOST" \
		'select(.domain == $d and .decision == "allow" and .identity_status == "valid")' 2>/dev/null || true
}

# ---- setup ----------------------------------------------------------------------

setup() {
	if [ ! -f "$COMPOSE_DIR/certs/proxy-ca.crt" ]; then
		OUT_DIR="$COMPOSE_DIR/certs" "$ROOT/scripts/gen-certs.sh" >/dev/null 2>&1
		# Dev only, throwaway CA: the worker's user (uid 100) must read the key.
		chmod 644 "$COMPOSE_DIR/certs/proxy-ca.key"
		CREATED_CERTS=1
	fi

	say "recipe-isolation: $RECIPE, clean state"
	compose down -v --remove-orphans >/dev/null 2>&1 || true
	STACK_UP=1
	compose up -d --build "$AGENT" >/dev/null 2>&1 || {
		compose logs --no-color --tail 40 2>&1 | redact >&2 || true
		fail stack-up "compose up failed"
	}

	# The sidecar must be running before the token can go on its volume.
	local i=0
	until compose exec -T warden-identity true >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -le 120 ] || fail stack-up "warden-identity did not start"
		sleep 2
	done

	# The seeded user's token goes from stdin to a file on the sidecar's own
	# volume: never through argv, never in a shell variable, never echoed.
	if ! "$ROOT/scripts/dex-token.sh" alice --raw |
		compose exec -T warden-identity sh -c 'umask 077; cat > /data/subject-token'; then
		fail token-handoff "could not fetch alice's token from Dex or write it to the sidecar"
	fi
	compose exec -T warden-identity test -s /data/subject-token || fail token-handoff "the token file is empty"
	USE_SUBJECT_FILE=1
	compose up -d warden-identity >/dev/null 2>&1 || fail stack-up "could not restart the sidecar with --subject-token-file"
}

# Wait until a request through the forwarder gets an upstream answer: the first
# token exchange only works once the control plane's first key is published.
wait_ready() {
	local deadline=$((SECONDS + READY_TIMEOUT)) code
	while [ "$SECONDS" -lt "$deadline" ]; do
		code="$(through_forwarder "https://$ALLOWED_HOST/v1/models" || true)"
		case "$code" in 200 | 401) return 0 ;; esac
		sleep 5
	done
	fail ready "no upstream answer through the forwarder within ${READY_TIMEOUT}s (last status: ${code:-none})"
}

# through_forwarder <url>: HTTP status of GET url through the agent's own proxy
# settings, or the CONNECT status when the tunnel is refused.
through_forwarder() {
	agent sh -c "curl -sS -m 30 --cacert $CA_PATH -o /dev/null -w '%{http_code} %{http_connect}' \"\$1\"" _ "$1" 2>/dev/null |
		awk '{ if ($1 == "000") print $2; else print $1 }'
}

# ---- checks: from inside the agent -------------------------------------------------

c_direct_egress_blocked() {
	if agent curl --noproxy '*' -sS -m 10 -o /dev/null https://example.com >/dev/null 2>&1; then
		echo "the agent reached https://example.com without the proxy"
		return 1
	fi
}

c_idp_and_cp_unreachable() {
	local target
	for target in dex/5556 control-plane/7070; do
		if agent timeout 6 bash -c "exec 3<>/dev/tcp/${target}" >/dev/null 2>&1; then
			echo "TCP to ${target%/*}:${target#*/} succeeded from the agent"
			return 1
		fi
	done
	if agent test -e /data || agent test -e /cp-data; then
		echo "an identity or control-plane volume path exists in the agent"
		return 1
	fi
}

# A plain HTTP request to the forwarder (credential included, so a 407 does not
# hide the method check) is not a CONNECT and gets 405.
c_forwarder_405() {
	local code
	code="$(agent sh -s 2>&1 <<'EOS'
cred=${HTTPS_PROXY#http://wx:}; cred=${cred%%@*}
auth=$(printf "wx:%s" "$cred" | base64 | tr -d "\n")
curl --noproxy "*" -sS -m 10 -o /dev/null -w "%{http_code}" \
	-H "Proxy-Authorization: Basic $auth" http://warden-identity:3128/
EOS
)" || true
	[ "$code" = 405 ] || {
		echo "plain HTTP to warden-identity:3128 answered ${code:-nothing}, want 405"
		return 1
	}
}

c_no_secrets_in_agent() {
	agent sh -s "$REAL_KEY_SENTINEL" "$PLACEHOLDER" <<'EOS' || return 1
sentinel=$1; placeholder=$2
dump() {
	env
	cat /proc/[0-9]*/environ 2>/dev/null | tr '\0' '\n'
	grep -rIs . "$HOME" 2>/dev/null || true
}
out=$(dump)
if printf '%s' "$out" | grep -qE 'eyJ[A-Za-z0-9_-]{20,}'; then echo "a JWT-shaped string is visible in the agent"; exit 1; fi
if printf '%s' "$out" | grep -q -- '-----BEGIN [A-Z ]*PRIVATE KEY-----'; then echo "a PEM private key is visible in the agent"; exit 1; fi
if printf '%s' "$out" | grep -qF -- "$sentinel"; then echo "the worker's key is visible in the agent"; exit 1; fi
# A vendor key shape other than the placeholder: sk-ant-..., sk-proj-..., sk-<20+>.
if printf '%s' "$out" | grep -qE 'sk-(ant|proj)-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9]{20,}'; then echo "a vendor-key-shaped string is visible in the agent"; exit 1; fi
printf '%s' "$out" | grep -qF -- "$placeholder" || { echo "the placeholder key is not set in the agent"; exit 1; }
# Hardening of the recipe: no capability and no way to gain one.
grep -q '^CapEff:[[:space:]]*0*$' /proc/self/status || { echo "the agent holds a capability"; exit 1; }
grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status || { echo "the agent can gain privileges (no-new-privileges unset)"; exit 1; }
EOS
}

# ---- checks: from a probe container on the worker network ------------------------

c_no_token_407() {
	local hdr
	hdr="$(docker run --rm --network "${PROJECT}_cp-net" curlimages/curl:8.22.0 \
		-sS -m 15 -o /dev/null -D - -x http://warden:8080 "https://$ALLOWED_HOST/" 2>&1 || true)"
	printf '%s' "$hdr" | tr -d '\r' | grep -qE '^HTTP/[0-9.]+ 407' || {
		echo "a request to the worker with no credentials did not get 407"
		return 1
	}
	printf '%s' "$hdr" | tr -d '\r' | grep -qi '^Proxy-Authenticate: Basic realm="warden"' || {
		echo "the 407 has no Proxy-Authenticate: Basic realm=\"warden\""
		return 1
	}
}

# ---- checks: attribution and policy ----------------------------------------------

alice_sub() {
	# dex-token.sh without --raw prints the decoded claims as JSON, never the token.
	"$ROOT/scripts/dex-token.sh" alice | jq -r '.sub // empty'
}

c_attributed_allow() {
	local code sub
	code="$(through_forwarder "https://$ALLOWED_HOST/v1/models")"
	case "$code" in 200 | 401) ;; *)
		echo "the allowed host answered ${code:-nothing}, want an upstream 200 or 401"
		return 1
		;;
	esac
	sub="$(alice_sub)"
	[ -n "$sub" ] || {
		echo "could not read alice's sub from dex-token.sh"
		return 1
	}
	# The worker's log line carries the user (user_sub) but not the agent; the agent
	# (act) is on the stored event and is checked in cp-attribution.
	allow_lines | jq -e --arg s "$sub" 'select(.user_sub == $s)' >/dev/null || {
		echo "no allow decision with identity_status valid and user_sub of alice in the worker log"
		return 1
	}
}

c_header_replaced() {
	# The agent's own Proxy-Authorization (wx:<credential>) is what the forwarder
	# checks. The worker must see only the forwarder's Warden token: a new request
	# is attributed to alice with a valid identity (the worker refuses anything
	# else with 407), and the credential never reaches the worker log.
	local before after code
	before="$(allow_lines | wc -l)"
	code="$(through_forwarder "https://$ALLOWED_HOST/v1/models")"
	case "$code" in 200 | 401) ;; *)
		echo "request through the forwarder answered ${code:-nothing}"
		return 1
		;;
	esac
	after="$(allow_lines | wc -l)"
	[ "$after" -gt "$before" ] || {
		echo "the request through the forwarder produced no attributed allow decision"
		return 1
	}
	local cred
	cred="$(agent sh -s <<'EOS'
c=${HTTPS_PROXY#http://wx:}; printf %s "${c%%@*}"
EOS
)"
	if [ -n "$cred" ] && worker_log | grep -qF -- "$cred"; then
		echo "the client's forwarder credential reached the worker"
		return 1
	fi
}

c_policy_deny() {
	local code
	code="$(agent sh -c "curl -sS -m 20 -o /dev/null -w '%{http_connect}' https://example.com/ 2>/dev/null" || true)"
	[ "$code" = 403 ] || {
		echo "CONNECT to example.com answered ${code:-nothing}, want a 403 refusal"
		return 1
	}
	worker_log | jq -e -s 'any(.[]; .domain == "example.com" and .decision == "deny")' >/dev/null 2>&1 || {
		echo "no deny decision for example.com in the worker log"
		return 1
	}
}

c_cp_attribution() {
	local hdr="$WORK/cp-auth" started=$SECONDS deadline=$((SECONDS + 120)) body
	umask 077
	printf 'Authorization: Bearer %s\n' "${WARDEN_CP_ADMIN_TOKEN:-dev-cp-admin-token}" >"$hdr"
	while [ "$SECONDS" -lt "$deadline" ]; do
		body="$(curl -ksS -m 10 -H "@$hdr" \
			"https://localhost:7070/dashboard/api/traffic?user=$AGENT_EMAIL&act=$AGENT" 2>/dev/null || true)"
		if printf '%s' "$body" | jq -e --arg d "$ALLOWED_HOST" --arg a "$AGENT" --arg e "$AGENT_EMAIL" \
			'[.[] | select(.Domain == $d and .Decision == "allow" and .identity_status == "valid" and .user_act == $a and .user_email == $e)] | length > 0' >/dev/null 2>&1; then
			echo "$((SECONDS - started))" >"$WORK/cp-delay"
			return 0
		fi
		sleep 3
	done
	echo "the control plane's traffic API has no valid event for $AGENT_EMAIL / act=$AGENT after 120s"
	return 1
}

c_agent_disabled() {
	# The offline CLI wants the agent's current revision (as `agent list` shows it).
	local rev
	rev="$(compose exec -T control-plane warden control-plane agent list --json --state-dir /data 2>/dev/null |
		jq -r --arg id "$AGENT" '[.. | objects | select(.id? == $id)] | .[0].revision // empty')"
	[ -n "$rev" ] || {
		echo "could not read the revision of agent $AGENT from agent list"
		return 1
	}
	compose exec -T control-plane warden control-plane agent disable --id "$AGENT" --revision "$rev" --state-dir /data >/dev/null 2>&1 || {
		echo "warden control-plane agent disable failed"
		return 1
	}
	local deadline=$((SECONDS + 10)) code
	while [ "$SECONDS" -lt "$deadline" ]; do
		code="$(agent sh -c "curl -sS -m 8 -o /dev/null -w '%{http_connect}' https://$ALLOWED_HOST/ 2>/dev/null" || true)"
		case "$code" in 403 | 407 | 502 | 503) return 0 ;; esac
		sleep 1
	done
	echo "a new CONNECT was still accepted 10s after the agent was disabled (last CONNECT status: ${code:-none})"
	return 1
}

c_no_token_in_logs() {
	local n svc
	n="$(grep -cE "$JWT_RE" "$OUT" || true)"
	[ "$n" = 0 ] || {
		echo "$n JWT-shaped strings in the script output"
		return 1
	}
	for svc in warden warden-identity control-plane; do
		n="$(compose logs --no-color --no-log-prefix "$svc" 2>&1 | grep -cE "$JWT_RE" || true)"
		[ "$n" = 0 ] || {
			echo "$n JWT-shaped strings in the logs of $svc"
			return 1
		}
	done
}

# ---- run -------------------------------------------------------------------------

setup
wait_ready

check direct-egress-blocked c_direct_egress_blocked
check idp-and-cp-unreachable c_idp_and_cp_unreachable
check forwarder-405 c_forwarder_405
check no-secrets-in-agent c_no_secrets_in_agent
check no-token-407 c_no_token_407
check attributed-allow c_attributed_allow
check header-replaced c_header_replaced
check policy-deny c_policy_deny
check cp-attribution c_cp_attribution
check agent-disabled c_agent_disabled
check no-token-in-logs c_no_token_in_logs

[ ! -f "$WORK/cp-delay" ] || say "note: the control plane showed the event $(cat "$WORK/cp-delay")s into cp-attribution polling (central sync delay)"
say "recipe-isolation: $RECIPE ok"
