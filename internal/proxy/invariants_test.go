package proxy

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/ws"
)

// This file is the invariant suite: one canary secret pushed through every
// protocol path in ProtocolPaths(), on allow, deny, upstream-error and timeout
// scenarios, with the same few assertions after each. A row names the PATH and
// SCENARIO it drives, so a failure reads "path=http1 scenario=allow: canary in
// logs: ...". Adding a protocol path means adding rows here;
// TestInvariants_EveryPathHasRows fails until you do.
//
// Known open issues: a row may carry knownIssue (an issue ref) and knownWhere
// (the exact places of the violations it expects). Such a row asserts the violation
// STILL happens and passes noting the issue; once the bug is fixed the row
// fails with "<ref> appears fixed: remove knownIssue", which forces cleanup.
// Never weaken an assertion to get a row green — add the issue instead.

type invScenario string

const (
	scAllow       invScenario = "allow"
	scDeny        invScenario = "deny"
	scUpstreamErr invScenario = "upstream-error"
	scTimeout     invScenario = "timeout"
	scEcho        invScenario = "echo"
	scHeaderStrip invScenario = "header-strip"
	scBodySwap    invScenario = "body-swap"
	scQuerySwap   invScenario = "query-swap"
	scDLPBlock    invScenario = "dlp-block"
)

// invCanaryScenarios are the scenarios every registered path must cover, either
// with a row or with an entry in invNotApplicable stating why not.
var invCanaryScenarios = []invScenario{scAllow, scDeny, scUpstreamErr, scTimeout}

// invNotApplicable records, with a reason, the (path, scenario) pairs that
// cannot exist. An empty cell is a bug; a documented gap is a decision.
var invNotApplicable = map[Path]map[invScenario]string{}

type invRow struct {
	name     string
	path     Path
	scenario invScenario
	opts     invOpts
	setup    func(e *invEnv)
	// run drives the agent side and returns everything the agent received plus
	// any row-specific violations.
	run func(e *invEnv) (view string, violations []string)
	// mustReach requires dispatch to have taken row.path (allow-style rows).
	mustReach bool
	// wantSwap requires the upstream to have received the real secret, which
	// proves the swap stage ran (so removing swapSecrets fails here, by name).
	wantSwap bool
	// wantNoUpstream requires that the upstream never saw the request.
	wantNoUpstream bool
	// wantDenyEvent requires a deny event to have been recorded; agentMustNot and
	// upstreamMustNot name payloads that must never reach the agent / the
	// upstream's WebSocket (so a deny that is recorded but not enforced fails).
	wantDenyEvent   bool
	agentMustNot    string
	upstreamMustNot string

	// knownIssue is the tracker ref of an open bug this row reproduces; knownWhere
	// lists the places (violationPlace) it is expected to show (each must appear,
	// and no other place may). Rows with a knownIssue assert the bug is STILL present.
	knownIssue string
	knownWhere []string
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

var denyJudge = &fakeJudge{verdict: Verdict{Decision: "deny", Reason: "invariants: judge says no"}}

func judgeOpts() invOpts {
	return invOpts{judge: denyJudge}
}

func mcpOpts() invOpts { return invOpts{mcp: true} }

// invBearer is the header every swap row sends: the agent's placeholder.
func invBearer() http.Header {
	return hdr("Authorization", "Bearer "+invPlaceholder, "X-Api-Key", invPlaceholder)
}

func mcpHeaders() http.Header {
	h := invBearer()
	h.Set("Content-Type", "application/json")
	return h
}

func grpcHeaders() http.Header {
	h := invBearer()
	h.Set("Content-Type", "application/grpc")
	return h
}

const grpcEmptyFrame = "\x00\x00\x00\x00\x00"

// h1 returns a driver that sends r over HTTP/1.1.
func h1(r invReq) func(*invEnv) (string, []string) {
	return func(e *invEnv) (string, []string) {
		view, _, _ := e.doHTTP1(r)
		return view, nil
	}
}

func h2(r invReq) func(*invEnv) (string, []string) {
	return func(e *invEnv) (string, []string) {
		view, _, _ := e.doH2(r)
		return view, nil
	}
}

func shortTimeout(r invReq) invReq {
	r.timeout = 400 * time.Millisecond
	return r
}

// wsUpgradeView performs the WebSocket upgrade through the proxy, sends frames
// and returns what the agent received.
func wsDrive(e *invEnv, host, path string, h http.Header, frames ...ws.Frame) string {
	tc, err := e.connectTLS(host)
	if err != nil {
		return err.Error()
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n", path, host)
	for k, vs := range h {
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	sb.WriteString("\r\n")
	_, _ = io.WriteString(tc, sb.String())
	for _, f := range frames {
		_, _ = tc.Write(frameWire(f))
	}
	_ = tc.SetReadDeadline(time.Now().Add(time.Second))
	got, _ := io.ReadAll(tc)
	return string(got)
}

func wsText(body string) ws.Frame {
	return ws.Frame{Fin: true, Opcode: ws.OpcodeText, Masked: true, MaskKey: [4]byte{}, Payload: []byte(body)}
}

// rawBytes is non-HTTP, non-TLS payload long enough for protocol sniffing (8+).
var rawBytes = "\x00\x01SSH-2.0-agent token=" + invPlaceholder + "\r\n"

// Each known violation is the exact place (kind, and the row's own sink) it shows
// up in; see violationKind.
var swapMissing = "swap stage did not run: the upstream never received the real secret"

func invRows() []invRow {
	var rows []invRow
	add := func(r ...invRow) { rows = append(rows, r...) }

	// ---- http1 --------------------------------------------------------------
	add(
		invRow{name: "http1/allow/header", path: PathHTTP1, scenario: scAllow, mustReach: true, wantSwap: true,
			run: h1(invReq{path: "/ok", header: invBearer()})},
		invRow{name: "http1/allow/query", path: PathHTTP1, scenario: scAllow, mustReach: true, wantSwap: true,
			run: h1(invReq{path: "/ok?key=" + invPlaceholder})},
		invRow{name: "http1/allow/body", path: PathHTTP1, scenario: scAllow, mustReach: true, wantSwap: true,
			run: h1(invReq{method: "POST", path: "/ok", header: hdr("Content-Type", "application/json"),
				body: `{"api_key":"` + invPlaceholder + `"}`})},
		invRow{name: "http1/allow/basic-auth", path: PathHTTP1, scenario: scAllow, mustReach: true, wantSwap: true,
			run: h1(invReq{path: "/ok", header: hdr("Authorization",
				"Basic "+base64.StdEncoding.EncodeToString([]byte("user:"+invPlaceholder)))})},
		invRow{name: "http1/deny", path: PathHTTP1, scenario: scDeny, opts: judgeOpts(), wantNoUpstream: true,
			run: h1(invReq{host: invJudgedHost, path: "/ok", header: invBearer()})},
		invRow{name: "http1/upstream-error", path: PathHTTP1, scenario: scUpstreamErr, wantSwap: true,
			run: h1(invReq{path: "/abort", header: invBearer()})},
		invRow{name: "http1/timeout", path: PathHTTP1, scenario: scTimeout, wantSwap: true,
			run: h1(shortTimeout(invReq{path: "/hang", header: invBearer()}))},
	)

	// ---- h2 -----------------------------------------------------------------
	add(
		invRow{name: "h2/allow/header", path: PathH2, scenario: scAllow, mustReach: true, wantSwap: true,
			run: h2(invReq{path: "/ok", header: invBearer()})},
		invRow{name: "h2/deny", path: PathH2, scenario: scDeny, opts: judgeOpts(), wantNoUpstream: true,
			run: h2(invReq{host: invJudgedHost, path: "/ok", header: invBearer()})},
		invRow{name: "h2/upstream-error", path: PathH2, scenario: scUpstreamErr, wantSwap: true,
			run: h2(invReq{path: "/abort", header: invBearer()})},
		invRow{name: "h2/timeout", path: PathH2, scenario: scTimeout, wantSwap: true,
			run: h2(shortTimeout(invReq{path: "/hang", header: invBearer()}))},
	)

	// ---- grpc ---------------------------------------------------------------
	add(
		invRow{name: "grpc/allow", path: PathGRPC, scenario: scAllow, mustReach: true, wantSwap: true,
			run: h2(invReq{method: "POST", path: "/pkg.Svc/Call", header: grpcHeaders(), body: grpcEmptyFrame})},
		invRow{name: "grpc/deny", path: PathGRPC, scenario: scDeny, opts: judgeOpts(), wantNoUpstream: true,
			run: h2(invReq{host: invJudgedHost, method: "POST", path: "/pkg.Svc/Call", header: grpcHeaders(), body: grpcEmptyFrame})},
		invRow{name: "grpc/upstream-error", path: PathGRPC, scenario: scUpstreamErr, wantSwap: true,
			run: h2(invReq{method: "POST", path: "/abort", header: grpcHeaders(), body: grpcEmptyFrame})},
		invRow{name: "grpc/timeout", path: PathGRPC, scenario: scTimeout, wantSwap: true,
			run: h2(shortTimeout(invReq{method: "POST", path: "/hang", header: grpcHeaders(), body: grpcEmptyFrame}))},
	)

	// ---- mcp ----------------------------------------------------------------
	mcpReq := func(path, body string) invReq {
		return invReq{method: "POST", path: path, header: mcpHeaders(), body: body}
	}
	add(
		invRow{name: "mcp/allow", path: PathMCP, scenario: scAllow, opts: mcpOpts(), mustReach: true, wantSwap: true,
			run: h1(mcpReq("/mcp", mcpReadFileBody))},
		invRow{name: "mcp/deny", path: PathMCP, scenario: scDeny, opts: mcpOpts(), mustReach: true, wantNoUpstream: true,
			run: h1(mcpReq("/mcp", mcpExecCmdBody))},
		invRow{name: "mcp/upstream-error", path: PathMCP, scenario: scUpstreamErr, opts: mcpOpts(), mustReach: true, wantSwap: true,
			run: h1(mcpReq("/abort", mcpReadFileBody))},
		invRow{name: "mcp/timeout", path: PathMCP, scenario: scTimeout, opts: mcpOpts(), mustReach: true, wantSwap: true,
			run: h1(shortTimeout(mcpReq("/hang", mcpReadFileBody)))},
	)

	// ---- sse ----------------------------------------------------------------
	add(
		invRow{name: "sse/allow", path: PathSSE, scenario: scAllow, opts: mcpOpts(), mustReach: true, wantSwap: true,
			run: h1(mcpReq("/sse", mcpToolsList))},
		invRow{name: "sse/deny", path: PathSSE, scenario: scDeny, opts: mcpOpts(), mustReach: true,
			wantDenyEvent: true, agentMustNot: invAfterBlock,
			run: h1(mcpReq("/sse-poisoned", mcpToolsList))},
		invRow{name: "sse/upstream-error", path: PathSSE, scenario: scUpstreamErr, opts: mcpOpts(), mustReach: true, wantSwap: true,
			run: h1(mcpReq("/sse-abort", mcpToolsList))},
		invRow{name: "sse/timeout", path: PathSSE, scenario: scTimeout, opts: mcpOpts(), mustReach: true, wantSwap: true,
			run: h1(shortTimeout(mcpReq("/sse-stall", mcpToolsList)))},
	)

	// ---- websocket ----------------------------------------------------------
	add(
		invRow{name: "websocket/allow", path: PathWebSocket, scenario: scAllow, opts: mcpOpts(), mustReach: true, wantSwap: true,
			run: func(e *invEnv) (string, []string) {
				return wsDrive(e, invHost, "/ws", invBearer(), wsText(mcpReadFileBody)), nil
			}},
		invRow{name: "websocket/deny", path: PathWebSocket, scenario: scDeny, opts: mcpOpts(), mustReach: true, wantSwap: true,
			wantDenyEvent: true, upstreamMustNot: invAfterBlock,
			run: func(e *invEnv) (string, []string) {
				return wsDrive(e, invHost, "/ws", invBearer(), wsText(mcpExecCmdBody), wsText(`{"after":"`+invAfterBlock+`"}`)), nil
			}},
		invRow{name: "websocket/upstream-error", path: PathWebSocket, scenario: scUpstreamErr, opts: mcpOpts(), wantSwap: true,
			run: func(e *invEnv) (string, []string) {
				return wsDrive(e, invHost, "/abort", invBearer()), nil
			}},
		invRow{name: "websocket/timeout", path: PathWebSocket, scenario: scTimeout, opts: mcpOpts(), wantSwap: true,
			run: func(e *invEnv) (string, []string) {
				return wsDrive(e, invHost, "/hang", invBearer()), nil
			}},
	)

	// ---- tunnel -------------------------------------------------------------
	tunnelAllow := func(e *invEnv) (string, []string) {
		conn, br, status, err := e.connectRaw(invHost + ":443")
		if err != nil || !strings.Contains(status, "200") {
			return fmt.Sprintf("%v %q", err, status), nil
		}
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nX-Token: "+invPlaceholder+"\r\n\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		got, _ := io.ReadAll(br)
		return status + string(got), nil
	}
	add(
		invRow{name: "tunnel/allow", path: PathTunnel, scenario: scAllow, mustReach: true,
			setup: func(e *invEnv) { e.startRawTCP(false) }, run: tunnelAllow},
		invRow{name: "tunnel/deny", path: PathTunnel, scenario: scDeny, wantNoUpstream: true,
			run: func(e *invEnv) (string, []string) {
				_, _, status, err := e.connectRaw("unlisted.test:443")
				return fmt.Sprintf("%v %q", err, status), nil
			}},
		invRow{name: "tunnel/upstream-error", path: PathTunnel, scenario: scUpstreamErr, mustReach: true, run: tunnelAllow},
		invRow{name: "tunnel/timeout", path: PathTunnel, scenario: scTimeout, mustReach: true,
			setup: func(e *invEnv) { e.startRawTCP(true) }, run: tunnelAllow},
	)

	// ---- raw-tls ------------------------------------------------------------
	rawTLS := func(host string) func(*invEnv) (string, []string) {
		return func(e *invEnv) (string, []string) {
			tc, err := e.connectTLS(host)
			if err != nil {
				return err.Error(), nil
			}
			_, _ = io.WriteString(tc, rawBytes)
			_ = tc.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			got, _ := io.ReadAll(tc)
			return string(got), nil
		}
	}
	add(
		invRow{name: "raw-tls/allow", path: PathRawTLS, scenario: scAllow, mustReach: true,
			setup: func(e *invEnv) { e.startRawTLS(false) }, run: rawTLS(invHost)},
		invRow{name: "raw-tls/deny", path: PathRawTLS, scenario: scDeny, opts: judgeOpts(), wantNoUpstream: true,
			run: rawTLS(invJudgedHost)},
		invRow{name: "raw-tls/upstream-error", path: PathRawTLS, scenario: scUpstreamErr, mustReach: true,
			setup: func(e *invEnv) { e.rawTLSAddr, e.useRawTLS = "127.0.0.1:1", true }, run: rawTLS(invHost)},
		invRow{name: "raw-tls/timeout", path: PathRawTLS, scenario: scTimeout, mustReach: true,
			setup: func(e *invEnv) { e.startRawTLS(true) }, run: rawTLS(invHost)},
	)

	// ---- upstream echo (#389, fixed) ---------------------------------------
	// An upstream that reflects the request it received must never hand the
	// swapped secret back to the agent: the echo guard blocks the response on
	// every path that relays an upstream body.
	add(
		invRow{name: "http1/echo", path: PathHTTP1, scenario: scEcho, mustReach: true, wantSwap: true,
			run: h1(invReq{path: "/echo", header: invBearer()})},
		invRow{name: "h2/echo", path: PathH2, scenario: scEcho, mustReach: true, wantSwap: true,
			run: h2(invReq{path: "/echo", header: invBearer()})},
		invRow{name: "grpc/echo", path: PathGRPC, scenario: scEcho, mustReach: true, wantSwap: true,
			run: h2(invReq{method: "POST", path: "/echo", header: grpcHeaders(), body: grpcEmptyFrame})},
		invRow{name: "mcp/echo", path: PathMCP, scenario: scEcho, opts: mcpOpts(), mustReach: true, wantSwap: true,
			run: h1(mcpReq("/mcp-echo", mcpReadFileBody))},
		// The echo guard blocks this response before the SSE relay starts, so the
		// row does not reach PathSSE; sse/allow and the other sse rows cover it.
		invRow{name: "sse/echo", path: PathSSE, scenario: scEcho, opts: mcpOpts(), wantSwap: true,
			run: h1(mcpReq("/sse-echo", mcpToolsList))},
	)

	// ---- proxy-only headers never reach the upstream -----------------------
	stripHeaders := func() http.Header {
		h := invBearer()
		h.Set("Proxy-Authorization", "Basic c2Vzc2lvbjp0b2tlbg==")
		h.Set("Proxy-Connection", "keep-alive")
		h.Set("X-Warden-Identity", "Bearer warden-identity-token")
		return h
	}
	stripCheck := func(do func(*invEnv) string) func(*invEnv) (string, []string) {
		return func(e *invEnv) (string, []string) {
			view := do(e)
			h, ok := e.backend.upstreamHeaders()
			if !ok {
				return view, []string{"header-strip: request never reached the upstream"}
			}
			var v []string
			for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Warden-Identity"} {
				if h.Get(name) != "" {
					v = append(v, "proxy-only header forwarded upstream: "+name)
				}
			}
			return view, v
		}
	}
	add(
		invRow{name: "http1/header-strip", path: PathHTTP1, scenario: scHeaderStrip, mustReach: true,
			run: stripCheck(func(e *invEnv) string {
				v, _, _ := e.doHTTP1(invReq{path: "/ok", header: stripHeaders()})
				return v
			})},
		invRow{name: "h2/header-strip", path: PathH2, scenario: scHeaderStrip, mustReach: true,
			run: stripCheck(func(e *invEnv) string {
				v, _, _ := e.doH2(invReq{path: "/ok", header: stripHeaders()})
				return v
			})},
		invRow{name: "grpc/header-strip", path: PathGRPC, scenario: scHeaderStrip, mustReach: true,
			run: stripCheck(func(e *invEnv) string {
				h := stripHeaders()
				h.Set("Content-Type", "application/grpc")
				v, _, _ := e.doH2(invReq{method: "POST", path: "/ok", header: h, body: grpcEmptyFrame})
				return v
			})},
	)

	// ---- h2 runs the same stages as HTTP/1.1 (#388, fixed) -------------------
	add(
		invRow{name: "http1/body-swap", path: PathHTTP1, scenario: scBodySwap, mustReach: true, wantSwap: true,
			run: h1(invReq{method: "POST", path: "/ok", body: "token=" + invPlaceholder})},
		invRow{name: "h2/body-swap", path: PathH2, scenario: scBodySwap, mustReach: true, wantSwap: true,
			run: h2(invReq{method: "POST", path: "/ok", body: "token=" + invPlaceholder})},
		invRow{name: "http1/query-swap", path: PathHTTP1, scenario: scQuerySwap, mustReach: true, wantSwap: true,
			run: h1(invReq{path: "/ok?token=" + invPlaceholder})},
		invRow{name: "h2/query-swap", path: PathH2, scenario: scQuerySwap, mustReach: true, wantSwap: true,
			run: h2(invReq{path: "/ok?token=" + invPlaceholder})},
		invRow{name: "http1/dlp-block", path: PathHTTP1, scenario: scDLPBlock, mustReach: true, wantNoUpstream: true,
			opts: dlpBlockOpts(),
			run:  h1(invReq{method: "POST", path: "/ok", header: hdr("Content-Type", "text/plain"), body: piiBody})},
		invRow{name: "h2/dlp-block", path: PathH2, scenario: scDLPBlock, mustReach: true, wantNoUpstream: true,
			opts: dlpBlockOpts(),
			run:  h2(invReq{method: "POST", path: "/ok", header: hdr("Content-Type", "text/plain"), body: piiBody})},
	)
	return rows
}

// dlpBlockOpts is an enforce-mode DLP policy that blocks PII to every
// destination.
func dlpBlockOpts() invOpts {
	cfg := config.DLPConfig{
		Mode:  config.DLPModeEnforce,
		Rules: []config.DLPRule{{Class: "pii.*", Action: config.DLPActionBlock}},
	}
	return invOpts{dlp: NewDLPScanner(cfg, false, false)}
}

// violationPlace reduces a violation to the exact place it was found, so a row's
// knownWhere pins it: "canary in logs: ...line..." -> "canary in logs",
// "canary in analytics event #3: ..." -> "canary in analytics event". Violations
// that are not canary sightings are kept whole (they name their own subject).
func violationPlace(v string) string {
	if !strings.HasPrefix(v, "canary in ") {
		return v
	}
	place, _, _ := strings.Cut(v, ": ")
	if i := strings.Index(place, " #"); i >= 0 {
		place = place[:i]
	}
	return place
}

// invViolations drives one row and collects everything wrong with it.
func invViolations(e *invEnv, row invRow) []string {
	view, violations := row.run(e)
	e.settle()
	violations = append(violations, e.leaks(view)...)
	if row.mustReach && !e.reached(row.path) {
		violations = append(violations, fmt.Sprintf("dispatch never reached path %q (row is not exercising it)", row.path))
	}
	if row.wantSwap && !e.backend.upstreamSawCanary() {
		violations = append(violations, swapMissing)
	}
	if row.wantDenyEvent && !e.hasDenyEvent() {
		violations = append(violations, "no deny event was recorded")
	}
	if row.agentMustNot != "" && strings.Contains(view, row.agentMustNot) {
		violations = append(violations, "blocked payload reached the agent")
	}
	if row.upstreamMustNot != "" && strings.Contains(e.backend.wsBytes(), row.upstreamMustNot) {
		violations = append(violations, "blocked payload reached the upstream")
	}
	if row.wantNoUpstream && len(e.backend.requests()) > 0 {
		violations = append(violations, "denied request reached the upstream")
	}
	return violations
}

func TestInvariants(t *testing.T) {
	for _, row := range invRows() {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			e := newInvEnv(t, row.opts)
			if row.setup != nil {
				row.setup(e)
			}
			violations := invViolations(e, row)
			label := fmt.Sprintf("path=%s scenario=%s", row.path, row.scenario)
			if row.knownIssue == "" {
				for _, v := range violations {
					t.Errorf("%s: %s", label, v)
				}
				return
			}
			// Every expected violation must still appear (else the bug looks fixed),
			// and nothing beyond them may appear (else this row would hide a new bug).
			// Matching is on the exact place (violationPlace), not a substring.
			want := map[string]bool{}
			for _, w := range row.knownWhere {
				want[w] = true
			}
			got := map[string]bool{}
			failed := false
			for _, v := range violations {
				place := violationPlace(v)
				got[place] = true
				if !want[place] {
					failed = true
					t.Errorf("%s: violation beyond known issue %s: %s", label, row.knownIssue, v)
				}
			}
			for _, w := range row.knownWhere {
				if !got[w] {
					failed = true
					t.Errorf("%s: %s appears fixed: remove knownIssue (no %q violation; got %v)",
						label, row.knownIssue, w, violations)
				}
			}
			if !failed {
				t.Logf("%s: known issue %s still reproduces (%d violation(s)); expected until it is fixed", label, row.knownIssue, len(violations))
			}
		})
	}
}

// uncoveredPaths returns, for each registered path, the canary scenarios that
// have neither a row nor a documented not-applicable entry.
func uncoveredPaths(paths []Path, rows []invRow, na map[Path]map[invScenario]string) []string {
	have := map[Path]map[invScenario]bool{}
	for _, r := range rows {
		if have[r.path] == nil {
			have[r.path] = map[invScenario]bool{}
		}
		have[r.path][r.scenario] = true
	}
	var missing []string
	for _, p := range paths {
		for _, sc := range invCanaryScenarios {
			if have[p][sc] {
				continue
			}
			if _, ok := na[p][sc]; ok {
				continue
			}
			missing = append(missing, fmt.Sprintf("path %q has no %q row", p, sc))
		}
	}
	return missing
}

func TestInvariants_EveryPathHasRows(t *testing.T) {
	for _, m := range uncoveredPaths(ProtocolPaths(), invRows(), invNotApplicable) {
		t.Errorf("%s: add a row to invRows (or a reasoned invNotApplicable entry)", m)
	}
	// Rows must name a registered path, so a typo cannot hide a gap.
	reg := map[Path]bool{}
	for _, p := range ProtocolPaths() {
		reg[p] = true
	}
	for _, r := range invRows() {
		if !reg[r.path] {
			t.Errorf("row %q names unregistered path %q", r.name, r.path)
		}
	}
}

// The checker itself: a path added to the registry without rows must be flagged.
func TestInvariants_UncoveredPathIsReported(t *testing.T) {
	paths := append(ProtocolPaths(), Path("quic"))
	missing := uncoveredPaths(paths, invRows(), invNotApplicable)
	if len(missing) != len(invCanaryScenarios) {
		t.Fatalf("a new path with no rows should miss every canary scenario, got %v", missing)
	}
	for _, m := range missing {
		if !strings.Contains(m, `"quic"`) {
			t.Errorf("unexpected gap reported: %s", m)
		}
	}
	// And a documented N/A silences exactly that cell.
	na := map[Path]map[invScenario]string{"quic": {scTimeout: "datagram, no stream to stall"}}
	if got := uncoveredPaths(paths, invRows(), na); len(got) != len(invCanaryScenarios)-1 {
		t.Fatalf("N/A entry should remove one gap, got %v", got)
	}
}
