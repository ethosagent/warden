#!/usr/bin/env bash
#
# hermeticity.sh — the e2e stack's self-check. `make e2e-up` runs it right
# after `up --wait`; a non-zero exit fails the up.
#
# What the stack guarantees (the wiring is docker-compose.e2e.yml):
#   - agent-1/2 are attached to internal networks only: their ONLY route out
#     is their worker.
#   - control-plane, worker-1/2 and fakeupstream ride the non-internal
#     `published` bridge with masquerading off: on a host whose network does
#     not NAT or route foreign source addresses they cannot complete a round
#     trip to the internet. Their packets may leave the host un-NATed, and
#     they can open connections to the Docker host itself; they and the
#     workers are the system under test, so that is acceptable here.
#
# Per container the check first proves the PROBE PATH WORKS — the container is
# up with a shell, has a probe tool, and can fetch a positive control that
# must SUCCEED (the fake upstream recorder for the workers, worker-1's admin
# /healthz over cp-net for the control plane, the agent's own worker admin
# /healthz for the agents, the recorder's own control port for the fake
# upstream) — and only then requires the NEGATIVE probes to fail: TCP to
# 1.1.1.1:80/:443 must not complete an HTTP exchange, and a UDP DNS query to
# 1.1.1.1:53 must get no answer. Anything broken in the first part fails the
# check with the container name and the reason — a missing service, a stopped
# container, no shell or no probe tool can never count as "hermetic". A
# negative probe passes only by failing: a timeout, a refused/unreachable
# network, a TLS error or a resolver timeout all count as hermetic; the one
# failing outcome is a clean HTTP exchange or a DNS answer.
#
# All probes run with the proxy environment unset, so they measure the
# container's own network path and never the worker's deny path.
#
# HERMETICITY_SERVICES overrides the service list (red-path drills:
# HERMETICITY_SERVICES="ghost agent-1" ./test/e2e/hermeticity.sh).
set -uo pipefail

cd "$(dirname "$0")/../.."
E2E_COMPOSE=(-f deploy/compose/docker-compose.control-plane.yml -f deploy/compose/docker-compose.e2e.yml)

TIMEOUT=5
NEG_TARGETS=(http://1.1.1.1/ https://1.1.1.1/)
DNS_SERVER=1.1.1.1
SERVICES=(control-plane worker-1 worker-2 worker-3 fakeupstream agent-1 agent-2 agent-3)
[ -n "${HERMETICITY_SERVICES:-}" ] && read -ra SERVICES <<<"$HERMETICITY_SERVICES"

problems=()

# positive_control prints a URL the container must be able to fetch, or ""
# when no control is defined (which is itself a failure — a container whose
# probe path cannot be proven must not be trusted on the negatives below).
positive_control() {
	case "$1" in
	control-plane) echo "http://worker-1:9090/healthz" ;;           # cp-net → worker admin
	worker-1 | worker-2 | worker-3) echo "http://10.200.0.10:8081/_health" ;;  # egress → fake recorder
	fakeupstream) echo "http://127.0.0.1:8081/_health" ;;           # its own recorder
	agent-1) echo "http://worker-1:9090/healthz" ;;                 # its only neighbor
	agent-2) echo "http://worker-2:9090/healthz" ;;
	agent-3) echo "http://worker-3:9090/healthz" ;;                 # its only neighbor
	*) echo "" ;;
	esac
}

exec_svc() { docker compose "${E2E_COMPOSE[@]}" exec -T "$1" sh -c "$2"; }

for svc in "${SERVICES[@]}"; do
	# 1. The container must be running with a shell — anything else is a
	#    failure naming the service, never a pass.
	if ! exec_svc "$svc" "true" >/dev/null 2>&1; then
		problems+=("$svc: cannot exec a shell (no such service, stopped container, or no shell in the image)")
		continue
	fi

	# 2. A probe tool must exist (curl in the agent images, busybox wget in
	#    warden's alpine images).
	tool="$(exec_svc "$svc" 'command -v curl >/dev/null 2>&1 && echo curl || { command -v wget >/dev/null 2>&1 && echo wget || true; }' 2>/dev/null | head -n1)"
	if [ -z "$tool" ]; then
		problems+=("$svc: no probe tool (curl/wget) in the container — the probes cannot run")
		continue
	fi

	# The UDP DNS negative needs nslookup too: without it the probe would exit
	# non-zero and silently read as "no answer", so require it up front.
	if ! exec_svc "$svc" "command -v nslookup" >/dev/null 2>&1; then
		problems+=("$svc: no nslookup in the container — the UDP DNS probe cannot run")
		continue
	fi

	# fetch URL — exit 0 only on a completed HTTP fetch. Proxy variables are
	# unset first: an agent's proxies point at its worker, and through them
	# even the negatives would be answered (denied) by the worker instead of
	# exercising the agent's own network path.
	fetch() {
		local tool_flags
		if [ "$tool" = curl ]; then
			tool_flags="curl -m $TIMEOUT -fsS -o /dev/null"
		else
			tool_flags="wget -T $TIMEOUT -q -O /dev/null"
		fi
		exec_svc "$svc" "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; $tool_flags '$1'"
	}

	# 3. The positive control must SUCCEED.
	ctrl="$(positive_control "$svc")"
	if [ -z "$ctrl" ]; then
		problems+=("$svc: no positive control defined in positive_control() — refusing to trust the negative results")
		continue
	fi
	if ! fetch "$ctrl" >/dev/null 2>&1; then
		problems+=("$svc: positive control $ctrl FAILED — the probe path is broken, so a failed probe below would prove nothing")
		continue
	fi

	# 4. The negative probes must ALL fail: no TCP HTTP exchange with a public
	#    IP, and no answer to a UDP DNS query against a public resolver.
	leaks=()
	for target in "${NEG_TARGETS[@]}"; do
		if fetch "$target" >/dev/null 2>&1; then
			leaks+=("TCP $target completed an HTTP exchange")
		fi
	done
	# example.com is a name a real resolver answers; an answer here is a leak.
	if exec_svc "$svc" "nslookup -type=A -retry=1 -timeout=$TIMEOUT example.com $DNS_SERVER" >/dev/null 2>&1; then
		leaks+=("UDP DNS query to $DNS_SERVER:53 got an answer")
	fi

	if [ "${#leaks[@]}" -eq 0 ]; then
		printf '  %-14s probe path ok (%s, %s); no TCP 1.1.1.1:80/:443, no UDP DNS answer — hermetic\n' "$svc" "$tool" "$ctrl"
	else
		for l in "${leaks[@]}"; do
			problems+=("$svc: LEAK: $l")
		done
	fi
done

if [ "${#problems[@]}" -gt 0 ]; then
	echo "HERMETICITY FAILURE — the stack is not proven hermetic:" >&2
	for p in "${problems[@]}"; do
		echo "  $p" >&2
	done
	echo "Fix the network wiring (docker-compose.e2e.yml) or the stack state before running scenarios." >&2
	exit 1
fi
echo "hermeticity check passed: every container's probe path works and none can reach the public internet"
