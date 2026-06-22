# Warden on EC2 / VM

The VM shape runs Warden as a long-lived process on the instance (systemd
service or a container) while the agent runs in a container whose egress is
routed through the proxy. Same architecture as the Compose and Kubernetes
shapes: **the agent has no internet route; the proxy is the only thing with
internet access.**

> Status: documentation only for milestone 0. The serving binary and a hardened
> systemd unit land with Milestone 1.

## Isolation contract

Whatever the host setup, these invariants must hold:

1. **Agent container has no default route to the internet.** Run it on an
   internal Docker network (`--internal`) or a network namespace with no NAT to
   the outside.
2. **Proxy is the only egress.** The agent is configured (`HTTPS_PROXY` /
   routing rules) to send all outbound traffic to Warden.
3. **Real secrets live with the proxy, not the agent.** The agent holds
   placeholders; Warden injects real values from the instance's environment /
   secret store.
4. **Host firewall backstops it.** Instance egress rules (security groups /
   nftables) should deny outbound from the agent's namespace except to the proxy
   — defense in depth behind the container runtime.

## Option A — Warden as a systemd service

Sketch (full unit ships in M1):

```ini
# /etc/systemd/system/warden.service
[Unit]
Description=Warden egress guardrail proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/warden -config /etc/warden/config.yaml -listen 127.0.0.1:8080
EnvironmentFile=/etc/warden/secrets.env   # real secrets, root-only (chmod 600)
Restart=on-failure
# Hardening (tighten in M1):
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

The agent container then routes egress to `127.0.0.1:8080` (or the instance-
internal address the proxy binds), and host firewall rules deny it any other
outbound path.

## Option B — Warden as a container on the instance

Run the proxy container with host or instance-internal networking and real
internet access; run the agent container on an `--internal` network attached to
the proxy. This mirrors `deploy/compose/docker-compose.yml` without Compose —
use it when the instance already runs a container engine.

## Cert trust (TLS termination)

Warden terminates TLS, so the agent must trust Warden's CA. Generate it once
with `scripts/gen-certs.sh`, mount/install the CA cert into the agent container's
trust store, and keep the CA **key** with the proxy only. See that script's
header for the full flow.
