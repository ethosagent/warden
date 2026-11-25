#!/bin/sh
# One-shot bootstrap shared by the identity recipes (identity-bootstrap service).
# The recipe's compose file sets the environment:
#   AGENT_ID                 the registered agent id (claude-code, codex)
#   AGENT_DISPLAY_NAME       the registry display name
#   WORKER_TOKEN_ENV         NAME of the variable holding the worker's wwt_ token
#   (the sidecar volume is identity-$AGENT_ID, named in the recovery hint)
# Idempotent: every step checks before it writes, so a second `up` changes no
# row and no file. Runs as the image's warden user on three volumes:
#   /cp-data  the control plane's state dir (agent registry, worker tokens)
#   /data     the sidecar's volume (agent key, token cache); the agent never mounts it
#   /var/tmp  the exported bundle JWKS, mounted read-only by the worker
# Never prints a key, a token or the worker token value.
set -eu

AGENT_ID=${AGENT_ID:?AGENT_ID is not set}
DISPLAY_NAME=${AGENT_DISPLAY_NAME:-$AGENT_ID}
WORKER_TOKEN_ENV=${WORKER_TOKEN_ENV:?WORKER_TOKEN_ENV is not set}
KEY=/data/${AGENT_ID}.key
JWK=/data/${AGENT_ID}.jwk
BUNDLE=/var/tmp/bundle-jwks.json
STATE=/cp-data
CFG=/etc/warden/config.yaml

# 1. Worker token for the recipe's worker (same name and value is a no-op). The
#    value comes from the environment, never argv. Changing
#    the worker token variable later makes this step fail (same name,
#    different value) and so the whole bootstrap: the stack fails closed instead of
#    running two tokens. Rotate it with `warden control-plane token revoke/create`.
warden control-plane token create --from-env "$WORKER_TOKEN_ENV" \
	--name "$AGENT_ID" --proxy-id "$AGENT_ID" --state-dir "$STATE"

# 2. Is the agent registered? Exact match on the id field of the JSON listing.
registered() {
	warden control-plane agent list --json --state-dir "$STATE" | grep -q "\"id\": \"$AGENT_ID\","
}

# 3. Agent key: enroll only when the key is missing. A key whose public JWK file
#    is gone is replaced ONLY while the agent is unregistered (nothing trusts the
#    old key yet). Once registered, replacing the key would leave the registry
#    holding a key the sidecar no longer has (every token fails cnf_mismatch), so
#    stop and say how to recover instead.
if [ ! -f "$KEY" ] || [ ! -f "$JWK" ]; then
	if registered; then
		echo "bootstrap: agent $AGENT_ID is registered but its key or public JWK is missing from the sidecar volume." >&2
		echo "bootstrap: recover with a NEW key: delete the agent (or run 'warden control-plane agent update' with the new JWK)," >&2
		echo "bootstrap: remove the volume identity-$AGENT_ID, then run the bootstrap again. See docs/recipes/README.md." >&2
		exit 1
	fi
	warden identity enroll --agent-id "$AGENT_ID" --key-file "$KEY" --force >"$JWK.tmp"
	mv "$JWK.tmp" "$JWK"
fi

# 4. Register the agent only when the registry does not hold it.
if ! registered; then
	warden control-plane agent register --id "$AGENT_ID" --display-name "$DISPLAY_NAME" \
		--jwk-file "$JWK" --groups eng --state-dir "$STATE"
fi

# 5. Export the bundle JWKS the worker pins. The control plane creates its keys
#    on first start, so wait for them (up to about 3 minutes). Written through a
#    temp file so the worker never sees a partial document.
i=0
until warden control-plane keys export --purpose bundle --state-dir "$STATE" --config "$CFG" >"$BUNDLE.tmp" 2>/dev/null; do
	i=$((i + 1))
	if [ "$i" -gt 90 ]; then
		echo "bootstrap: the control plane has not created its bundle key; is it running?" >&2
		exit 1
	fi
	sleep 2
done
mv "$BUNDLE.tmp" "$BUNDLE"
echo "bootstrap: ok"
