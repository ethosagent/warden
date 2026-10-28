# Shipping Warden audit logs to a SIEM

Warden can write two JSON streams that a SIEM shipper (Vector, Fluent Bit, a Splunk forwarder, a Kubernetes node collector) reads without parsing operational logs:

- **`warden.decision.v1`**: written by each worker, one line per stored analytics event (every allow and deny decision), with verified end-user identity fields when identity is on.
- **`warden.admin.v1`**: written by the control plane, one line per admin audit entry (who changed what in the console or CLI) plus a periodic chain-head checkpoint.

Both are newline-delimited JSON objects, closed (no field outside the schema), versioned, and free of request and response bodies, headers, query values and secret values. The schemas are [`docs/schemas/warden.decision.v1.json`](schemas/warden.decision.v1.json) and [`docs/schemas/warden.admin.v1.json`](schemas/warden.admin.v1.json). The feature design is in [the audit-log-export feature page](roadmap/features/audit-log-export.md).

The streams are a **best-effort copy**. The SQLite analytics store, the signed receipts (`audit.signedReceipts`) and, on the control plane, the signed `admin_audit` chain stay the record of truth. A full queue or a write error drops lines (and says so, see [Gap detection](#gap-detection)); it never fails or slows a request or an admin change.

## The streams versus operational logs

| | Operational log | JSON audit stream |
|---|---|---|
| Purpose | What the process is doing: startup, config reloads, warnings | One line per decision (or admin change), for audit and detection |
| Controlled by | `logging.level`, `logging.format` | `audit.jsonLog` |
| Shape | Free-form `slog` records, may change between releases | Closed schema, versioned, documented here |
| Default | stdout | Off |
| Ship to a SIEM? | Not for audit; use it for troubleshooting | Yes |

Do not point a shipper at the operational log and route on its `schema` attribute. The control plane's operational `admin_audit` lines also carry `schema=warden.admin.v1`, but with different field names (`actor_id`, `head_seq`, ...), no `boot_id`, and a `seq` that is the chain sequence number, not the stream counter. Only the lines `audit.jsonLog` writes follow the schema in this document.

When `audit.jsonLog.output` is `stdout` (the default value once the stream is enabled), stdout carries only schema lines and the operational log moves to stderr (logged once at startup). With `stderr` or `file` the operational log stays on stdout.

## Turning it on

The block is `audit.jsonLog` in the YAML config. It is **node-local and restart-only**: it is read from the node's own config file, never travels in the policy the control plane serves to workers, and a change needs a restart. Absent or `enabled: false` writes nothing and creates no file or directory.

```yaml
audit:
  jsonLog:
    enabled: true
    output: file                       # stdout | stderr | file
    path: /var/log/warden/decisions.jsonl
    maxSizeMB: 100
    maxBackups: 10
    maxAgeDays: 30
    compress: false
    fileMode: 0600                     # octal: 0600 or 0640
    query: drop                        # drop | keys
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Switches the stream on. Values are validated even while it is off, so a typo surfaces before you enable it. |
| `output` | `stdout` | `stdout`, `stderr` or `file`. |
| `path` | none | The log file. Required when `output` is `file`. The directory is created (mode 0750) if missing; an unwritable path fails startup. |
| `maxSizeMB` | `100` | Rotate when the file reaches this size. Must be positive. |
| `maxBackups` | `10` | Rotated files kept. `0` keeps all of them (age still applies). |
| `maxAgeDays` | `30` | Delete rotated files older than this. `0` disables age-based deletion. |
| `compress` | `false` | gzip rotated files. They get a `.gz` suffix, so a `*.jsonl` glob does not pick them up again. |
| `fileMode` | `0600` | Permission bits of the file: exactly `0600` or `0640`. |
| `query` | `drop` | `drop` records no query data. `keys` adds `query_keys` with the sorted parameter names, never values. |

`maxSizeMB`, `maxBackups`, `maxAgeDays`, `compress`, `fileMode` and `path` only apply to `output: file`.

**Workers** read the block from their own config file. **The control plane** reads it from the policy file it serves (with `--state-dir`, the copy seeded once from `--config` at `<state-dir>/config.yaml`). The control plane writes admin lines only when `console.adminAudit.enabled` is also true (which needs `--state-dir`); with `audit.jsonLog` on and `console.adminAudit` off it logs a warning and writes none. A node that runs both roles needs a different `path` for each: two processes must not write one file.

### Admin stream

```yaml
# control plane --config
console:
  adminAudit:
    enabled: true
audit:
  jsonLog:
    enabled: true
    output: file
    path: /var/log/warden-cp/admin.jsonl
```

Every stored admin audit entry becomes one `warden.admin.v1` line after its transaction commits. The control plane also writes a checkpoint line (`action` `admin_audit.checkpoint`) once at startup, every 5 minutes and once at shutdown. A checkpoint carries the chain head in `chain_seq`, `entry_hash` and `key_id`, with an empty `prev_hash`, `actor` role empty, and `auth_method` `system`. The newest checkpoint or entry you hold is an off-host anchor: verify the chain with `admin-audit verify --anchor <chain_seq>:<entry_hash>` (see [control-plane.md](control-plane.md#anchoring-the-audit-chain)). No genesis line is emitted; the startup checkpoint carries the head. The control plane has no metrics endpoint in this release: dropped lines raise a rate-limited warning (at most one per 30 seconds) in its operational log.

## Field reference

### warden.decision.v1 fields

One object per line. `ts` is the worker's wall clock at event time. "Required" means the key is always present; the optional keys are absent when empty. Nested keys are written `parent.child`.

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | yes | Always `warden.decision.v1`. Route on this. |
| `schema_rev` | integer | yes | Revision within v1; bumped when an additive optional field is added. |
| `ts` | string | yes | UTC RFC 3339 with nanoseconds, the worker's wall clock at event time. Sort by this. |
| `proxy_id` | string | yes | The worker that wrote the line (`central.proxyID`, else the hostname). |
| `proxy_id_source` | string | yes | Where `proxy_id` came from: `config` or `hostname`. |
| `agent_id` | string | yes | The wrapped agent this worker serves. |
| `boot_id` | string | yes | Random per-process id; `seq` restarts at 1 for each `boot_id`. |
| `seq` | integer | yes | Per-boot line counter; a gap means dropped lines. |
| `decision` | string | yes | `allow` or `deny`. |
| `reason` | string | no | Bounded reason: always set on deny; on allow only when a monitor-mode finding rode one. See [Deny reasons](#deny-reasons). |
| `protocol` | string | yes | Transport or protocol, for example `https`, `http`, `mcp`, `grpc`, `ws`. |
| `domain` | string | yes | Destination host. |
| `port` | integer | yes | Destination port. |
| `method` | string | yes | HTTP method, empty for non-HTTP paths. |
| `url_path` | string | yes | Escaped request path only, at most 2048 bytes: no scheme, host, userinfo, fragment or query values. |
| `query_keys` | array | no | Sorted, de-duplicated query parameter names (at most 64); only with `query: keys`. Never values. |
| `status` | integer | yes | Response status code, 0 when none. |
| `latency_ms` | integer | yes | Request latency in milliseconds. |
| `tool` | string | yes | MCP tool name, empty for non-MCP events. |
| `provider` | string | yes | LLM provider the call was attributed to, empty when none. |
| `cost_usd` | number | yes | Estimated cost in US dollars; never billing-grade. |
| `dlp_action` | string | yes | `allow`, `block`, `redact` or `monitor`; empty when DLP is off. |
| `dlp_rule` | string | yes | DLP rule that fired, empty when none. |
| `dlp_partial` | boolean | yes | True when only part of the body was scanned. |
| `data_classes` | array | no | Detected DLP data class names (at most 64); never matched content. |
| `swapped_refs` | array | no | Placeholder names that were swapped (at most 64); never real secret values. |
| `compliance` | array | no | Framework control ids the event maps to, for example `mitre:T1048`. |
| `judge_reason` | string | no | The LLM judge's rationale with control characters removed, cut to 512 bytes. |
| `user` | object | no | Verified end-user attribution; absent when the event carries no identity status (every event of a worker with identity off). |
| `user.status` | string | yes | `valid`, `invalid`, `expired`, `unverified`, `conflict` or `none`. An open string: a later status does not break readers. |
| `user.sub` | string | no | Subject claim; only when `status` is `valid`. |
| `user.email` | string | no | Email claim; only when `status` is `valid`. Personal data, see [Security](#security-and-privacy). |
| `user.groups` | array | no | Group claims, capped at 64 entries; only when `status` is `valid`. |
| `user.groups_truncated` | boolean | no | True when `groups` was capped here or by the verifier. |
| `user.sid` | string | no | Session id claim; only when `status` is `valid`. |
| `truncated` | boolean | no | True when optional fields were dropped to keep the line under 16 KiB. |

Example (an allow with a verified user, and a deny; `query: keys` is on):

```json
{"schema":"warden.decision.v1","schema_rev":1,"ts":"2026-10-28T09:14:03.482113000Z","proxy_id":"worker-1","proxy_id_source":"config","agent_id":"support-bot","boot_id":"9f2c41d07b6e4a1c8e53a0d2b7c91f64","seq":41,"decision":"allow","protocol":"https","domain":"api.openai.com","port":443,"method":"POST","url_path":"/v1/chat/completions","query_keys":["api-version"],"status":200,"latency_ms":812,"tool":"","provider":"openai","cost_usd":0.0042,"dlp_action":"","dlp_rule":"","dlp_partial":false,"swapped_refs":["openai_secret_001"],"compliance":["mitre:T1071"],"user":{"status":"valid","sub":"00u8abc123","email":"dana@corp.example","groups":["eng","support"],"sid":"sid-7d1e"}}
{"schema":"warden.decision.v1","schema_rev":1,"ts":"2026-10-28T09:14:07.020551000Z","proxy_id":"worker-1","proxy_id_source":"config","agent_id":"support-bot","boot_id":"9f2c41d07b6e4a1c8e53a0d2b7c91f64","seq":42,"decision":"deny","reason":"policy_no_match","protocol":"https","domain":"paste.example.net","port":443,"method":"POST","url_path":"/api/new","status":0,"latency_ms":2,"tool":"","provider":"","cost_usd":0,"dlp_action":"","dlp_rule":"","dlp_partial":false,"user":{"status":"valid","sub":"00u8abc123","email":"dana@corp.example","groups":["eng","support"],"sid":"sid-7d1e"}}
```

### warden.admin.v1 fields

One object per line. `ts` is the control plane's wall clock when the entry was stored (the checkpoint's own instant for a checkpoint). The `chain_seq`, `entry_hash`, `prev_hash` and `key_id` fields are copied from the stored chain row, so a shipped copy anchors the chain off host.

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | yes | Always `warden.admin.v1`. Route on this. |
| `schema_rev` | integer | yes | Revision within v1; bumped when an additive optional field is added. |
| `ts` | string | yes | UTC RFC 3339 with nanoseconds, the control plane's wall clock when the entry was stored. Sort by this. |
| `cp_id` | string | yes | The control plane that wrote the line (its hostname). |
| `boot_id` | string | yes | Random per-process id; `seq` restarts at 1 for each `boot_id`. |
| `seq` | integer | yes | Per-boot line counter; a gap means dropped lines. |
| `actor` | object | yes | Who made the change. |
| `actor.sub` | string | no | Plaintext identity subject from the side table; absent for system rows and checkpoints. |
| `actor.email` | string | no | Plaintext email from the side table; absent when unknown. Personal data, see [Security](#security-and-privacy). |
| `actor.role` | string | yes | The actor's console role at the time; empty for system rows and checkpoints. |
| `auth_method` | string | yes | `oidc`, `breakglass`, `cli`, `bearer`, `none` or `system`. |
| `action` | string | yes | The audited action, for example `policy.write`, or `admin_audit.checkpoint` for a chain-head checkpoint. |
| `target` | string | yes | The kind of thing changed, for example `policy` or `secretstore`. |
| `target_ref` | string | yes | A bounded reference to the thing changed (a route path or name), never a value. |
| `outcome` | string | yes | `ok` (applied), `denied` (refused by authorization or CSRF), `rejected` (invalid request) or `error` (failed server-side). |
| `before_hash` | string | yes | Keyed hash of the state before the change; empty when not applicable. |
| `after_hash` | string | yes | Keyed hash of the state after the change; equal to `before_hash` when nothing changed. |
| `request_id` | string | yes | The request id, for correlation with the control plane's logs. |
| `chain_seq` | integer | yes | The row's seq in the admin audit chain; the head's seq for a checkpoint. |
| `entry_hash` | string | yes | Lowercase hex `entry_hash` of the stored row; the head's hash for a checkpoint. |
| `prev_hash` | string | yes | Lowercase hex `prev_hash` of the stored row; empty for a checkpoint. |
| `key_id` | string | yes | The signing key id the row (or the head) is under. |

Example (an entry and a checkpoint; the hashes are placeholders):

```json
{"schema":"warden.admin.v1","schema_rev":1,"ts":"2026-10-28T09:20:11.304872000Z","cp_id":"cp-1","boot_id":"4be0c7a9d1f2483a96c05e7d8b3a1f20","seq":7,"actor":{"sub":"00u8abc123","email":"dana@corp.example","role":"admin"},"auth_method":"oidc","action":"policy.write","target":"policy","target_ref":"/dashboard/api/policy","outcome":"ok","before_hash":"1111111111111111111111111111111111111111111111111111111111111111","after_hash":"2222222222222222222222222222222222222222222222222222222222222222","request_id":"req-0042","chain_seq":18,"entry_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prev_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","key_id":"cp-audit-1"}
{"schema":"warden.admin.v1","schema_rev":1,"ts":"2026-10-28T09:25:00.000000000Z","cp_id":"cp-1","boot_id":"4be0c7a9d1f2483a96c05e7d8b3a1f20","seq":8,"actor":{"role":""},"auth_method":"system","action":"admin_audit.checkpoint","target":"","target_ref":"","outcome":"ok","before_hash":"","after_hash":"","request_id":"","chain_seq":18,"entry_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prev_hash":"","key_id":"cp-audit-1"}
```

## Deny reasons

`reason` is a bounded enum identifier: metadata, never content, never a raw domain or a secret. It is the same value that labels `warden_blocked_total`, so the dashboard, the alert bridge and the SIEM agree on why a request was denied. The decision schema's `reason` enum is exactly the table below (the `denyreason` and `gateway` rows), plus the `mcp_chain_<pattern>` family (`^mcp_chain_[a-z0-9_]+$`). `denyreason` rows are declared in `internal/denyreason`; `gateway` rows are produced by the MCP gateway (`internal/mcp/gateway`). Tests keep this table, the schema and the code in step, so a new reason cannot ship without a row here.

Alert on `unspecified`: it should never occur, and seeing it means a deny path skipped the deny helper.

| Reason | Source | Meaning |
|---|---|---|
| `policy_no_match` | denyreason | The destination matched no allowlist entry and no judge could decide it: the default-deny floor. |
| `policy_denylist` | denyreason | The destination matched an explicit denylist entry. |
| `rate_limited` | denyreason | The matched allowlist entry's rate limit was exhausted. |
| `time_window` | denyreason | The request fell outside the matched entry's time window. |
| `path_not_canonical` | denyreason | The raw path has a dot segment, an encoded separator or a matrix parameter, so the matched bytes and the served resource could differ. |
| `method_not_allowed` | denyreason | The method is not in the matched entry's `methods`. |
| `path_not_allowed` | denyreason | The path matches no pattern in the matched entry's `paths`. |
| `identity_required` | denyreason | The destination is reachable only with a verified identity and the request carried none. |
| `identity_expired` | denyreason | In identity challenge mode, the token that admitted a terminated tunnel expired while it was open; the client reconnects and is challenged again. |
| `identity_conflict` | denyreason | In identity challenge mode, an `X-Warden-Identity` header named a different subject than the tunnel's CONNECT token. |
| `group_not_allowed` | denyreason | A verified subject matched the destination only through identity-scoped allow entries that do not name it. |
| `identity_groups_truncated` | denyreason | Like `group_not_allowed`, but the subject's group list was cut at the cap, so the miss may come from the cut; it fails closed under its own name. |
| `user_blocked` | denyreason | The request's identity claims (verified or not) match an entry on the user block list. |
| `h2_request_trailers_unsupported` | denyreason | An HTTP/2 stream declared request trailers, which the h2 forward path does not relay. |
| `h2_extended_connect_unsupported` | denyreason | An RFC 8441 extended CONNECT (WebSocket over h2) the stream path cannot relay faithfully. |
| `transform_needs_buffered_body` | denyreason | An auth transform needed the body but it could not be buffered (streaming or unknown length). |
| `host_mismatch` | denyreason | The Host or :authority disagrees with the CONNECT-time host. |
| `request_trailers_unsupported` | denyreason | An HTTP/1.1 request declared trailers. |
| `grpc_body_placeholder` | denyreason | A gRPC message frame carried a secret placeholder; placeholders are swapped in metadata only, so the frame is refused. |
| `grpc_frame_too_large` | denyreason | A gRPC frame declared a length over the inspection bound, so it fails closed. |
| `grpc_frame_malformed` | denyreason | The gRPC body was not valid length-prefixed framing. |
| `grpc_frame_compressed` | denyreason | A gRPC frame set the compressed flag, so its payload cannot be inspected and it fails closed. |
| `secret_echo` | denyreason | The response echoed a swapped secret value back toward the agent. |
| `secret_echo_unscannable` | denyreason | The response body could not be scanned for swapped values, so it fails closed. |
| `ssrf_blocked` | denyreason | The SSRF dial guard refused the dial target. |
| `ssrf_denied_hostname` | denyreason | The SSRF dial guard does not allow the dial target's hostname. |
| `unsupported_protocol` | denyreason | The CONNECT floor saw bytes that are not an HTTP CONNECT request line. |
| `malformed_connect` | denyreason | The CONNECT request line could not be parsed into a host:port target. |
| `no_tls` | denyreason | Egress that required inspection could not be TLS-terminated, so it fails closed. |
| `transparent_no_sni` | denyreason | A TLS ClientHello on a transparent listener carried no readable server name (an ECH-encrypted hello included), so the destination is unknown. |
| `transparent_bad_client_hello` | denyreason | The bytes on a transparent :443 listener were not a parseable TLS ClientHello. |
| `transparent_h2_prior_knowledge` | denyreason | Plaintext HTTP/2 prior-knowledge bytes arrived on a transparent :443 listener, where no SNI can exist. |
| `transparent_loop_guard` | denyreason | An upstream dial resolved to one of Warden's own transparent listener addresses, an interception loop. |
| `malformed_request` | denyreason | The plain-HTTP transparent floor refused a request with no Host header or a header block over the byte budget. |
| `judge` | denyreason | The inline LLM judge denied the request. Its rationale is in `judge_reason`, never here. |
| `dlp_block` | denyreason | The outbound body hit a DLP rule in enforce mode with action block. |
| `dlp_redact` | denyreason | A DLP redact could not be located inline, so the request was escalated to a block. |
| `mcp_ws` | denyreason | The WebSocket frame pump reported a blocked MCP message. |
| `mcp_ws_unscannable` | denyreason | MCP enforce mode could not scan a WebSocket upgrade, so it is refused. |
| `mcp_sse_event_too_large` | denyreason | An MCP SSE event exceeded the scan cap in enforce mode and was held back. |
| `mcp_gateway_deny` | denyreason | An MCP gateway verdict denied without naming a reason (the fallback, so a gateway deny is never anonymous). |
| `http_response_leak` | denyreason | The non-MCP response scan found a high-severity credential leak in enforce mode. |
| `http_response_injection` | denyreason | The non-MCP response scan found a high-severity injection in enforce mode. |
| `unspecified` | denyreason | Fallback for a deny that reached the event writer without a reason. Seeing it means a code path bypassed the deny helper; report it. |
| `mcp_tool_denied` | gateway | The tool is denied by the MCP gateway's tool policy. |
| `mcp_tool_condition` | gateway | A tool-call condition rule denied the call. |
| `mcp_poisoning` | gateway | A tool description in a tools/list response looks like prompt injection. |
| `mcp_schema_drift` | gateway | A tool's input schema changed since the gateway first saw it. |
| `mcp_args_injection` | gateway | The tool arguments carry an injection finding. |
| `mcp_args_leak` | gateway | The tool arguments carry a credential leak finding. |
| `mcp_args_pii` | gateway | The tool arguments carry a PII finding. |
| `mcp_args_constraint` | gateway | The tool arguments violate a constraint of the agent's active scope. |
| `mcp_args_too_large` | gateway | The tool arguments are over the size cap. |
| `mcp_result_injection` | gateway | The tool result carries an injection finding. |
| `mcp_result_leak` | gateway | The tool result carries a credential leak finding. |
| `mcp_result_pii` | gateway | The tool result carries a PII finding. |
| `mcp_fail_closed` | gateway | The gateway could not parse or process the message and `mcp.failClosedOnError` is set. |
| `mcp_out_of_scope` | gateway | The tool is not in the agent's active scope. |
| `mcp_chain_<pattern>` | gateway | A call-chain finding, one of `mcp_chain_read_then_send`, `mcp_chain_permission_probing` or `mcp_chain_rapid_repeat`. Chain analysis only records, so it appears on allow events. |

## Versioning

Each schema is versioned by its `schema` value and revised inside a version by `schema_rev`.

- **Within v1** only additive optional fields appear, and each bumps `schema_rev`. Nothing is renamed, retyped or removed. The Go record (`internal/auditlog`), the JSON Schema and this page change in the same pull request, and tests fail if they drift.
- **A breaking change** ships as `warden.decision.v2` (or `warden.admin.v2`) next to v1 for one minor release, so a pipeline can move at its own pace.
- **Consumers must ignore unknown fields** and must route on `schema`. Send a `schema` value your pipeline does not know to a dead-letter output (both example files do) instead of dropping it, so a new version cannot disappear silently.
- `user.status` and `outcome` are open strings or small enums: handle a value you have not seen.

## Time, ordering and gap detection

### Time

`ts` is the **producer's wall clock**, UTC, RFC 3339 with exactly nine fractional digits (for example `2026-10-28T09:14:03.482113000Z`). Workers and control planes on different hosts can disagree by the skew between their clocks, and a shipper delivers lines in whatever order its batches complete. So:

- Use `ts` as the event time in the SIEM, not the time the line arrived.
- **Sort by `ts`, never by line order or arrival order.** Because the format is fixed-width UTC, sorting the string sorts the time.
- Run NTP (or chrony) on every Warden host. A skewed host shows up as one `proxy_id` whose events interleave oddly with the rest.
- Within one `boot_id`, use `seq` to order lines when two share a `ts`.

### Gap detection

Every line carries `boot_id` and `seq`. `boot_id` is a random id chosen when the process starts, and `seq` counts the lines of that process from 1, one step per line (a batch of N events takes N values). The counter is assigned before the line is queued, so any line the stream loses leaves a hole:

- the queue (64 batches) was full and a batch was dropped (`warden_auditlog_dropped_total` rises on a worker);
- a marshal, write or flush error (`warden_auditlog_write_errors_total{reason}`);
- the shipper was down while rotation deleted the file, or the lines never reached the SIEM.

To check a window, group by (`proxy_id` or `cp_id`, `boot_id`) and compare the `seq` values you hold with the range from 1 to the largest. A restart changes `boot_id` and restarts `seq` at 1, so a new `boot_id` is not a gap. Lines lost at the very end of a boot (the process crashed) leave no hole; compare the highest `seq` with `warden_auditlog_lines_total` if you need that.

A hole means the stream is incomplete, not that the event did not happen: the SQLite store and signed receipts (and the signed `admin_audit` chain) still hold it.

### Worked example: onboarding a SIEM

Two workers write one decision stream each. Their clocks differ and the shipper delivered `worker-2`'s batch first, so the file below is out of order, and `worker-1` lost the line with `seq` 3.

```jsonl
{"schema":"warden.decision.v1","schema_rev":1,"ts":"2026-10-28T09:00:02.100000000Z","proxy_id":"worker-2","proxy_id_source":"config","agent_id":"a2","boot_id":"bbbb","seq":1,"decision":"allow","protocol":"https","domain":"api.openai.com","port":443,"method":"POST","url_path":"/v1/responses","status":200,"latency_ms":300,"tool":"","provider":"openai","cost_usd":0,"dlp_action":"","dlp_rule":"","dlp_partial":false}
{"schema":"warden.decision.v1","schema_rev":1,"ts":"2026-10-28T09:00:01.000000000Z","proxy_id":"worker-1","proxy_id_source":"config","agent_id":"a1","boot_id":"aaaa","seq":1,"decision":"allow","protocol":"https","domain":"api.openai.com","port":443,"method":"POST","url_path":"/v1/responses","status":200,"latency_ms":410,"tool":"","provider":"openai","cost_usd":0,"dlp_action":"","dlp_rule":"","dlp_partial":false}
{"schema":"warden.decision.v1","schema_rev":1,"ts":"2026-10-28T09:00:03.500000000Z","proxy_id":"worker-1","proxy_id_source":"config","agent_id":"a1","boot_id":"aaaa","seq":2,"decision":"deny","reason":"policy_no_match","protocol":"https","domain":"paste.example.net","port":443,"method":"POST","url_path":"/api/new","status":0,"latency_ms":2,"tool":"","provider":"","cost_usd":0,"dlp_action":"","dlp_rule":"","dlp_partial":false}
{"schema":"warden.decision.v1","schema_rev":1,"ts":"2026-10-28T09:00:05.900000000Z","proxy_id":"worker-1","proxy_id_source":"config","agent_id":"a1","boot_id":"aaaa","seq":4,"decision":"allow","protocol":"https","domain":"api.openai.com","port":443,"method":"POST","url_path":"/v1/responses","status":200,"latency_ms":380,"tool":"","provider":"openai","cost_usd":0,"dlp_action":"","dlp_rule":"","dlp_partial":false}
```

Sort by `ts` to get the timeline (`jq` shown; any SIEM does the same with its event-time field):

```sh
jq -s -r 'sort_by(.ts)[] | [.ts, .proxy_id, .seq, .decision, (.reason // "-"), .domain] | @tsv' skew.jsonl
```

```text
2026-10-28T09:00:01.000000000Z	worker-1	1	allow	-	api.openai.com
2026-10-28T09:00:02.100000000Z	worker-2	1	allow	-	api.openai.com
2026-10-28T09:00:03.500000000Z	worker-1	2	deny	policy_no_match	paste.example.net
2026-10-28T09:00:05.900000000Z	worker-1	4	allow	-	api.openai.com
```

Then check for holes per process:

```sh
jq -s -c 'group_by([.proxy_id, .boot_id])[] | (map(.seq) | sort) as $s
  | {proxy_id: .[0].proxy_id, boot_id: .[0].boot_id, missing: ([range(1; $s[-1] + 1)] - $s)}
  | select(.missing | length > 0)' skew.jsonl
```

```text
{"proxy_id":"worker-1","boot_id":"aaaa","missing":[3]}
```

In a SIEM the same two checks are: set the event time from `ts` at ingest (the Vector example sets `timestamp` from it; the Splunk HEC sink sends it as the event time) and sort descending or ascending on that field, then a scheduled search that groups by `proxy_id` and `boot_id` and alerts when the number of distinct `seq` values is below the maximum `seq`. In Splunk that is `index=warden_decisions | stats dc(seq) as seen max(seq) as last by proxy_id boot_id | where seen < last`.

## Rotation and retention

With `output: file` the file is rotated by size (`maxSizeMB`), and rotated files are pruned by count (`maxBackups`) and age (`maxAgeDays`). Rotated files are named `<name>-<timestamp>.<ext>` next to the live file (gzipped to `.gz` with `compress: true`). Every line is written with one `write` call, so a line is never split across two files.

**Typical bytes per line.** A bare deny with no identity is about 450 bytes (measured: 443). An allow with a verified user (subject, email, two groups, session id), a provider and a swapped reference is about 700 bytes. Long URL paths, many groups or many `data_classes` add to that. A line never exceeds 16 KiB: past that, optional fields are dropped in a fixed order (`user.groups`, `data_classes`, `swapped_refs`, `compliance`, `judge_reason`, `query_keys`) and `truncated` is set. An admin line is bounded the same way but is not trimmed: one that is still over the limit is counted as a marshal error and not written.

**Sizing.** Plan with 600 to 700 bytes per line.

- Disk used is at most `maxSizeMB x (maxBackups + 1)` uncompressed. The defaults (100 MB, 10 backups) hold about 1.1 GB, roughly 1.7 million lines.
- A worker doing 20 mediated requests per second writes about 12 KB per second, about 1 GB per day. At that rate the defaults keep about a day of lines, so `maxAgeDays: 30` never fires: size, not age, is the bound. For a week of local history at that rate use `maxBackups` of about 70 with the same `maxSizeMB`, or enable `compress`.
- The local files are a **buffer for a shipper outage**, not the archive. Size them for the longest outage you want to survive without a gap, then keep long-term retention in the SIEM.
- With `maxBackups: 0` nothing is pruned by count, and with `maxAgeDays: 0` nothing is pruned by age; with both at 0 the disk fills. Do not.

**Record of truth.** The stream is best effort. The SQLite analytics store, the signed receipts (`audit.signedReceipts`) and the signed `admin_audit` chain are what you rely on for investigations and evidence; a dropped line shows as a `seq` gap and is not recoverable from the stream. Keep the signed artifacts under the retention your compliance regime needs, independently of the stream.

## Security and privacy

- **File mode.** `fileMode` defaults to `0600`: only the user running Warden reads the file. The mode is applied exactly (the umask does not widen or narrow it) and kept across rotation.
- **A shipper running as another user.** Use `fileMode: 0640` and give the shipper's user the file's group (run the shipper in the same group, or run Warden with the shipper's group as its primary or supplementary group). Warden accepts only `0600` or `0640`; world-readable modes are rejected at startup. The directory is created `0750`.
- **Read-only sidecars.** Mount the log directory (or volume) into the shipper container read-only, as the compose override does. The shipper needs to read and track offsets, never to write the stream. Keep the shipper's own state (offsets, buffers) on a separate writable volume.
- **TLS to the SIEM.** Ship over `https://` (or TLS to the HEC or syslog endpoint) and keep certificate verification on: the stream names users, destinations and tools. Take tokens from the environment or a secret store, never from the config file in the repository; the examples read them from environment variables and contain no token.
- **Personal data.** `user.email` and `actor.email` are plaintext email addresses, and `user.sub`, `user.groups` and `actor.sub` identify people. Treat the index like any store of personal data: restrict who can search it, set its retention, and apply your erasure process. If you cannot hold emails, drop the field in the shipper (in Vector, `del(.user.email)` in the `parse` transform) before it leaves the node. Warden does not hash or mask them.
- **Paths are not scrubbed.** `url_path` is the escaped path only (no query values, no userinfo, no fragment), but it is otherwise verbatim. Some APIs put identifiers in path segments (`/users/12345/export`), and a secret-looking token in a path stays there. `query: drop` (the default) removes query data entirely; `query: keys` adds parameter names, never values. Warden never exports bodies, headers, secret values or scan evidence.
- **Who can write the stream.** The agent has no route to the worker's filesystem, but anything that can write the file can forge lines. For the admin stream, the off-host copy plus `chain_seq` and `entry_hash` is what makes tampering detectable (see [control-plane.md](control-plane.md#anchoring-the-audit-chain)).

## Shipping

### Vector

[`docs/siem/vector.yaml`](siem/vector.yaml) is a complete pipeline: a `file` source over `WARDEN_AUDIT_GLOB`, a `remap` that parses the JSON line and sets `timestamp` from `ts`, a `route` on the top-level `schema` field, and console sinks (so it runs with no SIEM attached) plus a dead-letter sink for lines that are not JSON or carry an unknown schema. Paths come from environment variables: `WARDEN_AUDIT_GLOB` (default `/var/log/warden/*.jsonl`) and `WARDEN_VECTOR_DATA_DIR` (Vector's checkpoint directory, default `/var/lib/vector`). It is written for Vector 0.43.

```sh
export WARDEN_AUDIT_GLOB='/var/log/warden/*.jsonl'
vector validate --no-environment docs/siem/vector.yaml
vector --config docs/siem/vector.yaml
```

Replace the console sinks with your SIEM. Both blocks below were validated with `vector validate --no-environment` merged with `vector.yaml`; they read the endpoint and token from the environment.

```yaml
sinks:
  out_decision:                     # generic HTTP collector
    type: http
    inputs: [tag_decision]
    uri: ${WARDEN_SIEM_URL}
    method: post
    encoding:
      codec: json
    framing:
      method: newline_delimited
    auth:
      strategy: bearer
      token: ${WARDEN_SIEM_TOKEN}
    request:
      retry_attempts: 10
    buffer:
      type: disk
      max_size: 536870912
      when_full: block

  out_admin:                        # Splunk HTTP Event Collector
    type: splunk_hec_logs
    inputs: [tag_admin]
    endpoint: ${SPLUNK_HEC_URL}
    default_token: ${SPLUNK_HEC_TOKEN}
    index: warden_admin
    sourcetype: warden:admin
    timestamp_key: timestamp
    encoding:
      codec: json
    buffer:
      type: disk
      max_size: 536870912
      when_full: block
```

(Delete or rename the console sinks of the same name in `vector.yaml` when you merge a file like this, or use different sink names and keep both.) Vector tracks a file by its content fingerprint, so rotation neither loses nor repeats lines; compressed rotations (`.gz`) are not matched by a `*.jsonl` glob. The decision and admin streams from one host can share a glob; the `route` separates them.

CI does not run Vector by default. To run the real binary against the example, with Vector on `PATH`: `go test -tags vector ./internal/auditlog -run TestSIEMVectorRoutes`. It writes a decision line and an admin line with the real sink, runs `vector validate --no-environment` and then Vector over the files, and checks each record reaches its own route.

### Fluent Bit

[`docs/siem/fluent-bit.conf`](siem/fluent-bit.conf) tails `WARDEN_AUDIT_GLOB` with the `warden_json` parser from [`docs/siem/warden-parsers.conf`](siem/warden-parsers.conf) (which takes the record time from `ts`), then a `rewrite_tag` filter retags each record from its `schema` field to `warden.decision` or `warden.admin`. Offsets are kept in the SQLite file named by `WARDEN_FLB_DB`, which must be writable. Lines with an unknown schema keep the `warden.raw` tag and land in the last output. It was tested with Fluent Bit 3.2.

```sh
export WARDEN_AUDIT_GLOB='/var/log/warden/*.jsonl' WARDEN_FLB_DB=/var/lib/fluent-bit/warden.db
fluent-bit --dry-run -c docs/siem/fluent-bit.conf
fluent-bit -c docs/siem/fluent-bit.conf
```

Replace the `stdout` outputs with your destination. These two pass `fluent-bit --dry-run`:

```ini
[OUTPUT]
    Name         http
    Match        warden.admin
    Host         siem.example.com
    Port         443
    URI          /ingest
    Format       json_lines
    tls          On
    tls.verify   On
    Header       Authorization Bearer ${WARDEN_SIEM_TOKEN}

[OUTPUT]
    Name              splunk
    Match             warden.decision
    Host              splunk.example.com
    Port              8088
    Splunk_Token      ${SPLUNK_HEC_TOKEN}
    tls               On
    tls.verify        On
    event_index       warden_decisions
    event_sourcetype  warden:decision
```

### Kubernetes

Run Warden with `audit.jsonLog.output: stdout` (the default) and let the node-level log collector pick the container's stdout up. Stdout then carries only schema lines and the operational log is on **stderr**, so the collector can tell them apart by stream, and also by content: filter on the presence of a top-level `schema` key.

- Fluent Bit (the usual DaemonSet collector): with `Merge_Log On` in the `kubernetes` filter the JSON line's keys become top-level record keys, so a `grep` filter such as `Regex schema ^warden\.(decision|admin)\.v1$` selects the schema lines.
- Vector's `kubernetes_logs` source: add a `filter` transform that keeps events whose message contains the schema key, then parse and route as in `vector.yaml`:

  ```yaml
  transforms:
    only_warden:
      type: filter
      inputs: [k8s]
      condition: 'contains(string(.message) ?? "", "\"schema\":\"warden.")'
  ```

- Select by stream where the collector supports it (`stdout` for the schema lines, `stderr` for the operational log), and still route on `schema`.

Because nothing is written to disk, there is no rotation to size, and a collector that is down loses what the container runtime's own log rotation drops. If you need a longer buffer, write `output: file` to an `emptyDir` volume and run the shipper as a sidecar that mounts it read-only. The worker pod's other containers must not mount that volume writable.

### Compose

[`deploy/compose/docker-compose.siem.yml`](../deploy/compose/docker-compose.siem.yml) is an override for [`docker-compose.yml`](../deploy/compose/docker-compose.yml). It mounts `deploy/compose/siem/worker.yaml` (the example worker config plus `audit.jsonLog` with `output: file`) on the proxy, shares the worker's `/data` volume read-only with a `vector` service, and runs `docs/siem/vector.yaml` plus a file sink (`deploy/compose/siem/vector-file.yaml`) that writes each routed stream to the `siem-out` volume.

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
WARDEN_VERSION=<a release that includes audit.jsonLog> \
docker compose -f deploy/compose/docker-compose.yml \
               -f deploy/compose/docker-compose.siem.yml up
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.siem.yml \
  exec vector tail -f /var/lib/siem-out/decisions.jsonl
```

`WARDEN_VERSION` must name an image that knows `audit.jsonLog`; older images reject the unknown key at startup. The override enables the worker's decision stream only; to add the control plane's admin stream, add `console.adminAudit` and an `audit.jsonLog` block (with its own `path`) to the control plane's config as shown under [Admin stream](#admin-stream).

## Operating the stream

| Signal | Where | Meaning |
|---|---|---|
| `warden_auditlog_lines_total{schema}` | worker metrics | Lines written, by schema. |
| `warden_auditlog_write_errors_total{reason}` | worker metrics | Failures; `reason` is `marshal`, `write` or `flush`. |
| `warden_auditlog_dropped_total` | worker metrics | Events dropped because the sink queue was full or closed. |
| `audit JSON stream write failed` | operational log, WARN, at most once per 30 s | A write error; carries the reason only, never record content. |
| `audit JSON stream queue full or closed` | control plane log, WARN, at most once per 30 s | Admin lines were dropped. |

Alert on any increase of `warden_auditlog_dropped_total` or `warden_auditlog_write_errors_total`, and on a `seq` gap in the SIEM. A full disk, a path the Warden user cannot write, or a shipper that holds the file open on a read-only mount with the wrong ownership are the usual causes.
