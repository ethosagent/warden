package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// d2EnforceConfig is the plan's D2 example as a typed enforce config, driving the
// end-to-end enforce tests.
func d2EnforceConfig() config.DLPConfig {
	return config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Classes: map[string]config.DLPClassDefault{
			// pii.contact default is redact; in enforce Phase 3 redact fails closed
			// (blocks) until Phase 4 span redaction lands.
			"pii.contact": {Action: config.DLPActionMonitor},
		},
		Rules: []config.DLPRule{
			{Class: "pii.*", To: []string{"*.zendesk.com"}, Action: config.DLPActionAllow},
			{Class: "pii.*", To: []string{"api.openai.com", "api.anthropic.com", "openrouter.ai"}, Action: config.DLPActionBlock},
			{Class: "source_code", To: []string{"github.com", "*.githubusercontent.com"}, Action: config.DLPActionAllow},
			{Class: "source_code", Action: config.DLPActionBlock},
		},
	}
}

// doPostTo POSTs one request to the given CONNECT domain through the proxy and
// returns the response status. Unlike doPostThroughProxy it targets an arbitrary
// domain so per-destination DLP rules can be exercised (all domains route to the
// single test backend via dialBackend).
func doPostTo(t *testing.T, p *Proxy, caCertPEM []byte, domain, contentType, body string) int {
	t.Helper()
	tlsClient := dialProxyAndConnect(t, p.Addr().String(), domain, caCertPEM)
	url := "https://" + domain + "/ingest"
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = int64(len(body))
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	_ = readAllResp(resp)
	return resp.StatusCode
}

// piiBody carries an email (pii.contact); goSourceBody trips the code_go classifier.
const (
	piiBody      = `contact: alice@example.com please`
	goSourceBody = "package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n"
)

// Enforce: pii POSTed to api.openai.com → 403 + deny event (block + rule).
func TestDLP_EnforceBlocksPIIToLLM(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	dlp := NewDLPScanner(d2EnforceConfig(), false, false)
	allowed := []string{"api.openai.com", "foo.zendesk.com", "github.com", "evil.example.com"}
	p, ss := startTestProxyWithDLP(t, allowed, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	if status := doPostTo(t, p, caCertPEM, "api.openai.com", "text/plain", piiBody); status != 403 {
		t.Fatalf("pii to openai must 403 in enforce, got %d", status)
	}
	if got := backendBody(rb); got != "" {
		t.Fatalf("blocked request must not reach upstream, got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "deny")
	if ev == nil {
		t.Fatalf("expected https deny event, got %+v", ss.snapshot())
	}
	if ev.DLPAction != "block" {
		t.Fatalf("deny event DLPAction = %q, want block", ev.DLPAction)
	}
	if ev.DLPRule == "" {
		t.Fatalf("deny event must carry the winning rule id, got %+v", ev)
	}
	if !containsStr(ev.DataClasses, "pii.contact") {
		t.Fatalf("deny event must carry pii.contact, got %v", ev.DataClasses)
	}
	if ev.Reason != "dlp_block" {
		t.Fatalf("deny reason = %q, want dlp_block", ev.Reason)
	}
}

// Enforce: same pii body to foo.zendesk.com → forwarded, allow event.
func TestDLP_EnforceAllowsPIIToZendesk(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	dlp := NewDLPScanner(d2EnforceConfig(), false, false)
	allowed := []string{"api.openai.com", "foo.zendesk.com", "github.com"}
	p, ss := startTestProxyWithDLP(t, allowed, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	if status := doPostTo(t, p, caCertPEM, "foo.zendesk.com", "text/plain", piiBody); status != 200 {
		t.Fatalf("pii to zendesk must forward, got %d", status)
	}
	if got := backendBody(rb); got != piiBody {
		t.Fatalf("allowed body must reach upstream intact, got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", ss.snapshot())
	}
	if ev.DLPAction != "allow" {
		t.Fatalf("allow event DLPAction = %q, want allow", ev.DLPAction)
	}
	if !containsStr(ev.DataClasses, "pii.contact") {
		t.Fatalf("allow event must still record classes, got %v", ev.DataClasses)
	}
}

// Enforce: source_code to github → allow; source_code elsewhere → 403.
func TestDLP_EnforceSourceCodeByDestination(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)

	// Allowed to github.
	backendLn, rb := startBackend(t, caCert, caKey)
	dlp := NewDLPScanner(d2EnforceConfig(), false, false)
	allowed := []string{"github.com", "evil.example.com"}
	p, ss := startTestProxyWithDLP(t, allowed, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	if status := doPostTo(t, p, caCertPEM, "github.com", "text/plain", goSourceBody); status != 200 {
		t.Fatalf("source_code to github must forward, got %d", status)
	}
	if got := backendBody(rb); got != goSourceBody {
		t.Fatalf("github body must reach upstream intact, got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	if ev := findEvent(ss.snapshot(), "https", "allow"); ev == nil || ev.DLPAction != "allow" {
		t.Fatalf("expected allow event for source_code→github, got %+v", ss.snapshot())
	}

	// Blocked elsewhere (class-default rule, no `to`).
	backendLn2, rb2 := startBackend(t, caCert, caKey)
	dlp2 := NewDLPScanner(d2EnforceConfig(), false, false)
	p2, ss2 := startTestProxyWithDLP(t, allowed, caCertPEM, caKeyPEM, dlp2, map[string]string{}, nil, nil)
	p2.dialTLS = dialBackend(backendLn2)

	if status := doPostTo(t, p2, caCertPEM, "evil.example.com", "text/plain", goSourceBody); status != 403 {
		t.Fatalf("source_code elsewhere must 403, got %d", status)
	}
	if got := backendBody(rb2); got != "" {
		t.Fatalf("blocked source_code must not reach upstream, got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	if ev := findEvent(ss2.snapshot(), "https", "deny"); ev == nil || ev.DLPAction != "block" {
		t.Fatalf("expected deny/block event for source_code→elsewhere, got %+v", ss2.snapshot())
	}
}

// Monitor downgrade: the same enforce-blocking scenario in mode=monitor is
// FORWARDED, and the allow event records the WOULD-BE action ("block") — never 403.
func TestDLP_MonitorDowngradeRecordsWouldBe(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	cfg := d2EnforceConfig()
	cfg.Mode = config.DLPModeMonitor // downgrade everything to event-only
	dlp := NewDLPScanner(cfg, false, false)
	allowed := []string{"api.openai.com", "foo.zendesk.com", "github.com"}
	p, ss := startTestProxyWithDLP(t, allowed, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	if status := doPostTo(t, p, caCertPEM, "api.openai.com", "text/plain", piiBody); status != 200 {
		t.Fatalf("monitor mode must FORWARD even a block-verdict body, got %d", status)
	}
	if got := backendBody(rb); got != piiBody {
		t.Fatalf("monitor mode must not mutate the body, got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event (monitor never denies), got %+v", ss.snapshot())
	}
	if ev.DLPAction != "block" {
		t.Fatalf("monitor downgrade must record would-be action block, got %q", ev.DLPAction)
	}
	if findEvent(ss.snapshot(), "https", "deny") != nil {
		t.Fatalf("monitor mode must NEVER emit a deny event")
	}
}

// Custom class: a body matching a custom regex to a blocked dest is blocked in
// enforce, and the event carries custom.<name> as the class.
func TestDLP_EnforceCustomClassBlocks(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	cfg := config.DLPConfig{
		Mode:   config.DLPModeEnforce,
		Custom: []config.DLPCustomClass{{Name: "project_codename", Regex: `ACME-\d{4}`, Severity: "medium"}},
		Rules: []config.DLPRule{
			{Class: "custom.project_codename", To: []string{"api.openai.com"}, Action: config.DLPActionBlock},
		},
	}
	dlp := NewDLPScanner(cfg, false, false)
	p, ss := startTestProxyWithDLP(t, []string{"api.openai.com"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	if status := doPostTo(t, p, caCertPEM, "api.openai.com", "text/plain", "codename ACME-1234 leaked"); status != 403 {
		t.Fatalf("custom-class body to blocked dest must 403, got %d", status)
	}
	if got := backendBody(rb); got != "" {
		t.Fatalf("blocked custom-class body must not reach upstream, got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "deny")
	if ev == nil {
		t.Fatalf("expected deny event, got %+v", ss.snapshot())
	}
	if !containsStr(ev.DataClasses, "custom.project_codename") {
		t.Fatalf("deny event must carry custom.project_codename, got %v", ev.DataClasses)
	}
}

// Redact → block interim: until Phase 4 implements span redaction, a redact
// verdict fails closed (blocks) in enforce, and the event records the redact intent.
func TestDLP_EnforceRedactBlocksInterim(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Classes: map[string]config.DLPClassDefault{
			"pii.contact": {Action: config.DLPActionRedact}, // class default: redact everywhere
		},
	}
	dlp := NewDLPScanner(cfg, false, false)
	p, ss := startTestProxyWithDLP(t, []string{"api.openai.com"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	if status := doPostTo(t, p, caCertPEM, "api.openai.com", "text/plain", piiBody); status != 403 {
		t.Fatalf("redact must fail closed (block) in enforce Phase 3, got %d", status)
	}
	if got := backendBody(rb); got != "" {
		t.Fatalf("redact-blocked request must not reach upstream, got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "deny")
	if ev == nil {
		t.Fatalf("expected deny event, got %+v", ss.snapshot())
	}
	if ev.DLPAction != "redact" {
		t.Fatalf("event must record the redact intent, got %q", ev.DLPAction)
	}
	if ev.Reason != "dlp_redact" {
		t.Fatalf("deny reason = %q, want dlp_redact", ev.Reason)
	}
}

// DLP cannot widen a static deny: a destination NOT on the static allowlist is
// refused at CONNECT (403) even though a DLP `allow` rule names it — DLP runs only
// AFTER CONNECT, so it never resurrects a statically-denied destination.
func TestDLP_CannotWidenStaticDeny(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)

	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Rules: []config.DLPRule{
			// A DLP allow for a domain that is NOT statically allowed.
			{Class: "pii.*", To: []string{"denied.example.com"}, Action: config.DLPActionAllow},
		},
	}
	dlp := NewDLPScanner(cfg, false, false)
	// Static allowlist deliberately EXCLUDES denied.example.com.
	p, _ := startTestProxyWithDLP(t, []string{"api.openai.com"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)

	// Raw CONNECT to the statically-denied host → 403, before any DLP evaluation.
	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com:443\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "403") {
		t.Fatalf("static deny must refuse CONNECT with 403 (DLP allow cannot widen it), got %q", line)
	}
}
