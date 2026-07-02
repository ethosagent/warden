package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// --- Pure rewrite algorithm: sort / merge / non-destructive rewrite ---

func TestRedactRanges(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		ranges []redactRange
		want   string
	}{
		{
			name:   "single span mid-body",
			body:   "hello world",
			ranges: []redactRange{{0, 5, "x"}},
			want:   "[REDACTED:x] world",
		},
		{
			name:   "span at offset 0",
			body:   "SECRETrest",
			ranges: []redactRange{{0, 6, "c"}},
			want:   "[REDACTED:c]rest",
		},
		{
			name:   "span ending at len(body)",
			body:   "keep SECRET",
			ranges: []redactRange{{5, 11, "c"}},
			want:   "keep [REDACTED:c]",
		},
		{
			name:   "multiple non-adjacent spans",
			body:   "aa BB cc DD ee",
			ranges: []redactRange{{3, 5, "b"}, {9, 11, "d"}},
			want:   "aa [REDACTED:b] cc [REDACTED:d] ee",
		},
		{
			name:   "adjacent spans stay separate markers",
			body:   "ABCDEF",
			ranges: []redactRange{{0, 3, "x"}, {3, 6, "y"}},
			want:   "[REDACTED:x][REDACTED:y]",
		},
		{
			name:   "overlapping spans merge to one marker (first label)",
			body:   "helloworld",
			ranges: []redactRange{{0, 5, "x"}, {2, 8, "y"}},
			want:   "[REDACTED:x]ld",
		},
		{
			name:   "same-start spans: longer wins the label",
			body:   "helloworld",
			ranges: []redactRange{{0, 5, "short"}, {0, 8, "long"}},
			want:   "[REDACTED:long]ld",
		},
		{
			name:   "unsorted input is sorted first",
			body:   "aa BB cc DD",
			ranges: []redactRange{{9, 11, "d"}, {3, 5, "b"}},
			want:   "aa [REDACTED:b] cc [REDACTED:d]",
		},
		{
			name:   "whole body",
			body:   "everything",
			ranges: []redactRange{{0, 10, "all"}},
			want:   "[REDACTED:all]",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := string(redactRanges([]byte(c.body), c.ranges))
			if got != c.want {
				t.Fatalf("redactRanges = %q, want %q", got, c.want)
			}
		})
	}
}

// --- End-to-end: enforce redaction correctness through the proxy ---

// redactCredsConfig redacts the credentials class everywhere in enforce mode.
func redactCredsConfig() config.DLPConfig {
	return config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Classes: map[string]config.DLPClassDefault{
			"credentials": {Action: config.DLPActionRedact},
		},
	}
}

// runRedactCase POSTs body through an enforce-redact proxy and returns the exact
// bytes the upstream received.
func runRedactCase(t *testing.T, cfg config.DLPConfig, body string) (status int, upstream string) {
	t.Helper()
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)
	dlp := NewDLPScanner(cfg, false, false)
	p, _ := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)
	status = doPostThroughProxy(t, p, caCertPEM, "text/plain", body)
	return status, backendBody(rb)
}

func TestDLP_Redact_SingleSpan(t *testing.T) {
	status, got := runRedactCase(t, redactCredsConfig(), "key is "+dlpAKIA+" ok")
	if status != 200 {
		t.Fatalf("redact must forward, got %d", status)
	}
	want := "key is [REDACTED:credentials] ok"
	if got != want {
		t.Fatalf("upstream = %q, want %q", got, want)
	}
	if strings.Contains(got, dlpAKIA) {
		t.Fatalf("upstream must not receive the raw key: %q", got)
	}
}

func TestDLP_Redact_MultipleSpans(t *testing.T) {
	body := dlpAKIA + " then " + "AKIAJKLMNOPQRST01234" + " end"
	status, got := runRedactCase(t, redactCredsConfig(), body)
	if status != 200 {
		t.Fatalf("redact must forward, got %d", status)
	}
	want := "[REDACTED:credentials] then [REDACTED:credentials] end"
	if got != want {
		t.Fatalf("upstream = %q, want %q", got, want)
	}
	if strings.Contains(got, "AKIA") {
		t.Fatalf("upstream must not receive any raw key: %q", got)
	}
}

func TestDLP_Redact_SpanAtStart(t *testing.T) {
	status, got := runRedactCase(t, redactCredsConfig(), dlpAKIA+" trailing")
	if status != 200 {
		t.Fatalf("redact must forward, got %d", status)
	}
	if want := "[REDACTED:credentials] trailing"; got != want {
		t.Fatalf("upstream = %q, want %q", got, want)
	}
}

func TestDLP_Redact_SpanAtEnd(t *testing.T) {
	status, got := runRedactCase(t, redactCredsConfig(), "leading "+dlpAKIA)
	if status != 200 {
		t.Fatalf("redact must forward, got %d", status)
	}
	if want := "leading [REDACTED:credentials]"; got != want {
		t.Fatalf("upstream = %q, want %q", got, want)
	}
}

// Overlapping-class span: a PEM private-key line carries BOTH credentials and
// source_code; with both classes redacting it produces ONE marker labelled by the
// first/most-specific class (credentials).
func TestDLP_Redact_OverlappingClassOneMarker(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Classes: map[string]config.DLPClassDefault{
			"credentials": {Action: config.DLPActionRedact},
			"source_code": {Action: config.DLPActionRedact},
		},
	}
	body := "x -----BEGIN RSA PRIVATE KEY----- y"
	status, got := runRedactCase(t, cfg, body)
	if status != 200 {
		t.Fatalf("redact must forward, got %d", status)
	}
	if strings.Count(got, "[REDACTED:") != 1 {
		t.Fatalf("multi-class span must yield exactly one marker, got %q", got)
	}
	if !strings.Contains(got, "[REDACTED:credentials]") {
		t.Fatalf("merged marker must be labelled credentials (first class), got %q", got)
	}
	if strings.Contains(got, "PRIVATE KEY") {
		t.Fatalf("upstream must not receive the raw PEM header: %q", got)
	}
}

// A class that resolves to allow in the same body is NOT redacted, while the
// credentials span IS — proving per-class action selection.
func TestDLP_Redact_OnlyRedactingClassScrubbed(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Classes: map[string]config.DLPClassDefault{
			"credentials": {Action: config.DLPActionRedact},
			"pii.contact": {Action: config.DLPActionAllow},
		},
	}
	body := "mail alice@example.com key " + dlpAKIA
	status, got := runRedactCase(t, cfg, body)
	if status != 200 {
		t.Fatalf("redact must forward, got %d", status)
	}
	if !strings.Contains(got, "alice@example.com") {
		t.Fatalf("an allow-class value must survive unredacted: %q", got)
	}
	if strings.Contains(got, dlpAKIA) {
		t.Fatalf("the redact-class key must be scrubbed: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:credentials]") {
		t.Fatalf("expected a credentials marker, got %q", got)
	}
}

// --- Redact + secret swap interaction ---

// A body with BOTH a foreign AKIA (redact) and a configured placeholder NAME: the
// AKIA is scrubbed by dlpScan (pre-swap), the placeholder is then swapped to the
// real secret by swapSecrets (post-redact), and the real secret VALUE appears in no
// event. Content-Length is implicitly correct because the upstream parsed the exact
// expected body (a wrong length truncates or hangs).
func TestDLP_RedactThenSwap(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	const placeholder = "PLACEHOLDER_TOKEN"
	const realSecret = "AKIAREALSECRET000000" // itself AKIA-shaped: must NOT be scanned/redacted
	dlp := NewDLPScanner(redactCredsConfig(), false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp,
		map[string]string{placeholder: realSecret}, []string{placeholder}, nil)
	p.dialTLS = dialBackend(backendLn)

	body := fmt.Sprintf("auth=%s foreign=%s", placeholder, dlpAKIA)
	if status := doPostThroughProxy(t, p, caCertPEM, "text/plain", body); status != 200 {
		t.Fatalf("redact+swap must forward, got %d", status)
	}
	got := backendBody(rb)
	want := "auth=" + realSecret + " foreign=[REDACTED:credentials]"
	if got != want {
		t.Fatalf("upstream = %q, want %q", got, want)
	}
	if strings.Contains(got, dlpAKIA) {
		t.Fatalf("foreign key must be redacted at upstream: %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected allow event, got %+v", ss.snapshot())
	}
	if ev.DLPAction != "redact" {
		t.Fatalf("event DLPAction = %q, want redact", ev.DLPAction)
	}
	if eventContains(t, *ev, realSecret) {
		t.Fatalf("real swapped secret leaked into event: %+v", ev)
	}
}

// --- Decoded-layer escalation (fail-closed) ---

// base64Body returns "field <base64(plain)>" with a >=64-char base64 block.
func base64Body(t *testing.T, plain string) string {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	if len(b64) < 64 {
		t.Fatalf("test setup: base64 block must be >=64 chars, got %d", len(b64))
	}
	return "payload " + b64
}

// ENFORCE: a redact rule cannot locate a key hidden in a decoded base64 layer, so
// the whole request escalates to a 403 block with DLPEncoded=true.
func TestDLP_DecodedLayerEscalatesInEnforce(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)
	dlp := NewDLPScanner(redactCredsConfig(), false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	body := base64Body(t, dlpAKIA+" is the leaked value, padded out nicely")
	if status := doPostThroughProxy(t, p, caCertPEM, "text/plain", body); status != 403 {
		t.Fatalf("decoded-layer redact must fail closed to 403 in enforce, got %d", status)
	}
	if got := backendBody(rb); got != "" {
		t.Fatalf("escalated request must not reach upstream, got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "deny")
	if ev == nil {
		t.Fatalf("expected deny event, got %+v", ss.snapshot())
	}
	if !ev.DLPEncoded {
		t.Fatalf("deny event must flag DLPEncoded=true, got %+v", ev)
	}
	if ev.DLPAction != "redact" {
		t.Fatalf("event must preserve the redact intent, got %q", ev.DLPAction)
	}
}

// MONITOR: the same decoded-layer redact forwards the ORIGINAL body byte-identical
// and records the would-be redact + DLPEncoded flag (never a deny, never a mutation).
func TestDLP_DecodedLayerMonitorForwards(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)
	cfg := redactCredsConfig()
	cfg.Mode = config.DLPModeMonitor
	dlp := NewDLPScanner(cfg, false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	body := base64Body(t, dlpAKIA+" is the leaked value, padded out nicely")
	if status := doPostThroughProxy(t, p, caCertPEM, "text/plain", body); status != 200 {
		t.Fatalf("monitor must forward, got %d", status)
	}
	if got := backendBody(rb); got != body {
		t.Fatalf("monitor must not mutate the body, got %q want %q", got, body)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected allow event, got %+v", ss.snapshot())
	}
	if ev.DLPAction != "redact" {
		t.Fatalf("monitor must record would-be redact, got %q", ev.DLPAction)
	}
	if !ev.DLPEncoded {
		t.Fatalf("monitor must flag DLPEncoded on a decoded-layer redact, got %+v", ev)
	}
	if findEvent(ss.snapshot(), "https", "deny") != nil {
		t.Fatalf("monitor must never emit a deny event")
	}
}

// Monitor never mutates a redactable body: a raw-span redact verdict in monitor
// forwards the ORIGINAL bytes unchanged.
func TestDLP_Redact_MonitorNoMutate(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)
	cfg := redactCredsConfig()
	cfg.Mode = config.DLPModeMonitor
	dlp := NewDLPScanner(cfg, false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	body := "key is " + dlpAKIA + " ok"
	if status := doPostThroughProxy(t, p, caCertPEM, "text/plain", body); status != 200 {
		t.Fatalf("monitor must forward, got %d", status)
	}
	if got := backendBody(rb); got != body {
		t.Fatalf("monitor must forward byte-identical, got %q want %q", got, body)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil || ev.DLPAction != "redact" {
		t.Fatalf("monitor must record would-be redact, got %+v", ev)
	}
}

// Wire hygiene at the event layer: a redact allow event's JSON carries the bounded
// classes/action/rule/flags only — no offsets, no matched content.
func TestDLP_RedactEventWireHygiene(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)
	dlp := NewDLPScanner(redactCredsConfig(), false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	if status := doPostThroughProxy(t, p, caCertPEM, "text/plain", "key "+dlpAKIA); status != 200 {
		t.Fatalf("redact must forward, got %d", status)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected allow event, got %+v", ss.snapshot())
	}
	b, err := json.Marshal(*ev)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if strings.Contains(js, dlpAKIA) {
		t.Fatalf("event JSON must not contain the matched secret: %s", js)
	}
	for _, forbidden := range []string{"Start", "\"End\"", "SpanDetection"} {
		if strings.Contains(js, forbidden) {
			t.Fatalf("event JSON must not carry offsets/spans (%q): %s", forbidden, js)
		}
	}
	if !strings.Contains(js, "redact") {
		t.Fatalf("event JSON must record the DLP action: %s", js)
	}
}
