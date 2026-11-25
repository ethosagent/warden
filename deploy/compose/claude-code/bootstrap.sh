#!/bin/sh
# One-shot bootstrap for the Claude Code recipe (identity-bootstrap service).
# Idempotent: every step checks before it writes, so a second `up` changes no
# row and no file. Runs as the image's warden user on three volumes:
#   /cp-data  the control plane's state dir (agent registry, worker tokens)
#   /data     the sidecar's volume (agent key, token cache); the agent never mounts it
#   /var/tmp  the exported bundle JWKS, mounted read-only by the worker
# Never prints a key, a token or the worker token value.
set -eu

AGENT_ID=claude-code
KEY=/data/${AGENT_ID}.key
JWK=/data/${AGENT_ID}.jwk
BUNDLE=/var/tmp/bundle-jwks.json
STATE=/cp-data
CFG=/etc/warden/config.yaml

# 1. Worker token for the recipe's worker (register-only: same name and value is
#    a no-op). The value comes from the environment, never argv.
warden control-plane token create --from-env WARDEN_CLAUDE_CODE_WORKER_TOKEN \
	--name claude-code --proxy-id claude-code --state-dir "$STATE"

# 2. Agent key: enroll only when the key is missing. A key without its public
#    JWK file is a crash between the two writes; it was never registered, so it
#    is replaced.
if [ ! -f "$KEY" ]; then
	warden identity enroll --agent-id "$AGENT_ID" --key-file "$KEY" >"$JWK.tmp"
	mv "$JWK.tmp" "$JWK"
elif [ ! -f "$JWK" ]; then
	warden identity enroll --agent-id "$AGENT_ID" --key-file "$KEY" --force >"$JWK.tmp"
	mv "$JWK.tmp" "$JWK"
fi

# 3. Register the agent only when the registry does not hold it.
if ! warden control-plane agent list --state-dir "$STATE" | awk 'NR > 1 { print $1 }' | grep -qx "$AGENT_ID"; then
	warden control-plane agent register --id "$AGENT_ID" --display-name "Claude Code" \
		--jwk-file "$JWK" --groups eng --state-dir "$STATE"
fi

# 4. Export the bundle JWKS the worker pins. The control plane creates its keys
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
