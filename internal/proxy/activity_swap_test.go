package proxy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// TestActivity_SwapAndDLP_PopulatesMetadataOnly drives one request that BOTH
// secret-swaps a placeholder AND trips a DLP finding, then asserts the allow event
// carries the three dashboard fields — LatencyMs>0, SwappedRefs listing the
// placeholder NAME, and a MASKED Evidence sample — while proving neither the real
// secret value nor the raw matched content lands in the event OR any log line.
func TestActivity_SwapAndDLP_PopulatesMetadataOnly(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	const placeholder = "{{OPENAI_API_KEY}}"
	const realSecret = "sk-ThisIsARealSecretValue0123456789ABCDEF"
	const rawEmail = "alice-secret@example.com" // the raw DLP-matched (pii) content

	// Debug level so EVERY logging path fires (the dlp-finding debug log, which
	// carries the masked evidence, plus the decision log) — the strongest surface
	// on which to prove no raw value ever appears.
	logs := &syncBuf{}
	logger, _ := observability.NewLogger(logs, "debug", "json")

	certFile := filepath.Join(t.TempDir(), "ca.crt")
	keyFile := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, caKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// DLP monitor with MASKED evidence capture ON (the "••••<last4> (len N)" form),
	// matching the worker wiring. No policy => pure observability: forwards unchanged.
	dlp := NewDLPScanner(config.DLPConfig{Mode: config.DLPModeMonitor}, false, true)

	store := &syncStore{}
	p, err := New(Config{
		ListenAddr:       "127.0.0.1:0",
		Policy:           policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "backend.test", Port: 443}}}),
		Secrets:          &fakes.FakeSecretProvider{Values: map[string]string{placeholder: realSecret}},
		Analytics:        store,
		AgentID:          "agent",
		DLP:              dlp,
		PlaceholderNames: []string{placeholder},
		Logger:           logger,
		CACertPath:       certFile,
		CAKeyPath:        keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	waitForAddr(t, p)
	p.dialTLS = dialBackend(backendLn)

	// The body carries BOTH the placeholder (swapped to the real secret AFTER the
	// DLP scan, so the scanner never sees the value) and a raw email (a pii finding
	// scanned pre-swap).
	body := fmt.Sprintf(`{"prompt":"reach me at %s","auth":"%s"}`, rawEmail, placeholder)
	if status := doPostThroughProxy(t, p, caCertPEM, "application/json", body); status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	// The backend received the SWAPPED body: the real secret replaced the placeholder.
	if got := backendBody(rb); !strings.Contains(got, realSecret) || strings.Contains(got, placeholder) {
		t.Fatalf("backend body should contain the real secret and no placeholder; got %q", got)
	}

	time.Sleep(50 * time.Millisecond)
	ev := findEvent(store.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", store.snapshot())
	}

	// (1) LatencyMs populated (> 0: the request made a real backend TLS round trip).
	if ev.LatencyMs <= 0 {
		t.Fatalf("LatencyMs = %d, want > 0", ev.LatencyMs)
	}
	// (2) SwappedRefs lists the placeholder NAME (never the value).
	if !containsStr(ev.SwappedRefs, placeholder) {
		t.Fatalf("SwappedRefs = %v, want to include %q", ev.SwappedRefs, placeholder)
	}
	// (3) Evidence carries a MASKED sample; the raw email never appears in it.
	if len(ev.Evidence) == 0 {
		t.Fatalf("expected a masked evidence sample, got none")
	}
	for _, e := range ev.Evidence {
		if !strings.Contains(e, "•") || !strings.Contains(e, "(len ") {
			t.Fatalf("evidence sample is not masked: %q", e)
		}
		if strings.Contains(e, rawEmail) {
			t.Fatalf("raw matched content leaked into evidence: %q", e)
		}
	}

	// (4) METADATA-ONLY PROOF: neither the real secret value nor the raw matched
	// content appears anywhere in the event's serialized form...
	if eventContains(t, *ev, realSecret) {
		t.Fatalf("real secret value leaked into event: %+v", ev)
	}
	if eventContains(t, *ev, rawEmail) {
		t.Fatalf("raw matched content leaked into event: %+v", ev)
	}
	// ...nor in any log line.
	out := logs.String()
	if strings.Contains(out, realSecret) {
		t.Fatalf("real secret value leaked into logs:\n%s", out)
	}
	if strings.Contains(out, rawEmail) {
		t.Fatalf("raw matched content leaked into logs:\n%s", out)
	}
}

// TestActivity_DenyEventCarriesLatency confirms LatencyMs rides a DENY event too:
// a response-scan enforce block (which denies only after a real upstream round
// trip) records a deny event whose LatencyMs is populated (> 0).
func TestActivity_DenyEventCarriesLatency(t *testing.T) {
	rb := &mcpBackend{respStatus: 200, respCT: "text/plain", respBody: leakBody}
	caCertPEM, caKeyPEM, backendLn := mustBackend(t, rb)

	rs := NewResponseScanner("enforce", 1<<20, false, false)
	p, ss := startTestProxyWithResponseScan(t, []string{"backend.test"}, caCertPEM, caKeyPEM, rs, nil)
	p.dialTLS = dialBackend(backendLn)

	status, _ := doGet(t, p, caCertPEM)
	if status != 502 {
		t.Fatalf("enforce block should 502, got %d", status)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "deny")
	if ev == nil {
		t.Fatalf("expected https deny event, got %+v", ss.snapshot())
	}
	if ev.LatencyMs <= 0 {
		t.Fatalf("deny event LatencyMs = %d, want > 0", ev.LatencyMs)
	}
}
