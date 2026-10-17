package compose

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
)

// The pure halves of the compose target, unit-tested WITHOUT Docker (this file
// has no build tag, so the default gate runs it): the argv the agent shim
// builds, the `curl -i` output parser, the CONNECT footer parser, the
// deadline+stability events poll, the recorder decoder and the leak needles.
// The Docker-driving halves live in the e2e-tagged files and are exercised by
// target_e2e_test.go against the running stack.

// TestHost pins the compose answers so the L2 spellings never move: the names
// the stack's fake DNS serves, and the L1-only aliases that must refuse rather
// than resolve to nothing.
func TestHost(t *testing.T) {
	for alias, want := range map[string]string{
		"api": "api.example.test", "llm": "llm.example.test", "mcp": "mcp.example.test",
		"evil": "evil.example.test", "unlisted": "unlisted.example.test",
	} {
		got, err := Host(alias)
		if err != nil || got != want {
			t.Errorf("Host(%s) = %q, %v; want %q", alias, got, err, want)
		}
	}
	for _, alias := range []string{"grpc", "ws", "nope"} {
		if _, err := Host(alias); err == nil {
			t.Errorf("Host(%s) = nil error, want a refusal (the stack serves no such fake)", alias)
		}
	}
	if _, err := Host("grpc"); err != nil && !strings.Contains(err.Error(), "in-process") {
		t.Errorf("Host(grpc) error does not say the fake is in-process-only: %v", err)
	}
}

// TestComposeArgs pins the docker compose argv: both -f files, in the
// Makefile's order, before the subcommand.
func TestComposeArgs(t *testing.T) {
	got := ComposeArgs("logs", "--no-color", SvcWorker1)
	want := []string{
		"compose",
		"-f", "deploy/compose/docker-compose.control-plane.yml",
		"-f", "deploy/compose/docker-compose.e2e.yml",
		"logs", "--no-color", SvcWorker1,
	}
	if !slicesEqual(got, want) {
		t.Errorf("ComposeArgs = %v, want %v", got, want)
	}
}

// TestSecretSpecs pins the deployment's secret wiring — exactly what
// configs/config.e2e-worker.yaml holds — so the sweep guards the value the
// workers actually swap.
func TestSecretSpecs(t *testing.T) {
	specs := SecretSpecs()
	if len(specs) != 1 {
		t.Fatalf("SecretSpecs = %d spec(s), want the stack's one secret", len(specs))
	}
	s := specs[0]
	if s.Placeholder != "example_secret_001" || s.Value != Canary {
		t.Errorf("spec = %q/%q, want the stack's placeholder and canary", s.Placeholder, s.Value)
	}
	if len(s.MatchHosts) != 2 || s.MatchHosts[0] != "api.example.test" || s.MatchHosts[1] != "llm.example.test" {
		t.Errorf("MatchHosts = %v, want the config.e2e-worker.yaml scope", s.MatchHosts)
	}
}

// TestAgentCurlArgs: the argv must drive curl exactly the way the ticket's
// shim spells it — `curl -s -i` inside agent-1, CA pinned, headers carried,
// body on stdin, --http2 when the scenario asked for h2.
func TestAgentCurlArgs(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://api.example.test/v1/canary", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Api-Key", "example_secret_001")
	req.Header.Set("Content-Type", "text/plain")
	args, err := AgentCurlArgs(req, []byte("key=example_secret_001"), false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"curl", "-s", "-i", "--max-time", "25",
		"--cacert", "/etc/warden/certs/proxy-ca.crt",
		"-X", http.MethodPost,
		"-H", "Content-Type: text/plain",
		"-H", "X-Api-Key: example_secret_001",
		"--data-binary", "@-",
		"https://api.example.test/v1/canary",
	}
	if !slicesEqual(args, want) {
		t.Errorf("argv = %v, want %v", args, want)
	}

	req2, _ := http.NewRequest(http.MethodGet, "https://api.example.test/", nil)
	args2, err := AgentCurlArgs(req2, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slicesEqual(args2, []string{
		"curl", "-s", "-i", "--max-time", "25",
		"--cacert", "/etc/warden/certs/proxy-ca.crt",
		"--http2",
		"-X", http.MethodGet,
		"https://api.example.test/",
	}) {
		t.Errorf("h2 GET argv = %v", args2)
	}

	req3, _ := http.NewRequest(http.MethodGet, "https://x.example.test/", nil)
	req3.URL = nil
	if _, err := AgentCurlArgs(req3, nil, false); err == nil {
		t.Error("a request without a URL must be an argv error, not a curl run")
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestParseCurlResponse: the parser reads `curl -s -i` output — HTTP/1.1 and
// the bare "HTTP/2" status line, skipping a 1xx interim response, and handing
// back a body decoupled from the framing headers (curl already de-chunked it).
func TestParseCurlResponse(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.test/", nil)

	resp, err := ParseCurlResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Status != "200 OK" {
		t.Errorf("status = %d/%q, want 200", resp.StatusCode, resp.Status)
	}
	if resp.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}

	resp, err = ParseCurlResponse([]byte("HTTP/2 200\r\ncontent-type: application/json\r\n\r\n{}"), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Proto != "HTTP/2.0" {
		t.Errorf("h2 status = %d proto %q, want 200 HTTP/2.0", resp.StatusCode, resp.Proto)
	}

	resp, err = ParseCurlResponse([]byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 403 Forbidden\r\nX-A: b\r\n\r\nno"), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-A") != "b" {
		t.Errorf("status after 1xx = %d, want the 403 final response", resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	if string(body) != "no" {
		t.Errorf("body after 1xx = %q", body)
	}

	resp, err = ParseCurlResponse([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\ndecoded"), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.TransferEncoding != nil || resp.ContentLength != -1 {
		t.Errorf("framing headers survived: TE=%v len=%d; curl already decoded the body", resp.TransferEncoding, resp.ContentLength)
	}
	body, _ = io.ReadAll(resp.Body)
	if string(body) != "decoded" {
		t.Errorf("body = %q, want the decoded stream", body)
	}

	for _, broken := range []string{"", "garbage without a status line"} {
		if _, err := ParseCurlResponse([]byte(broken), req); err == nil {
			t.Errorf("ParseCurlResponse(%q) = nil error, want one", broken)
		}
	}
}

// TestParseConnectStatus: curl's %{http_connect} footer is the whole stdout.
func TestParseConnectStatus(t *testing.T) {
	for out, want := range map[string]int{"200\n": 200, "403\n": 403, " 200 ": 200} {
		got, err := ParseConnectStatus(out)
		if err != nil || got != want {
			t.Errorf("ParseConnectStatus(%q) = %d, %v; want %d", out, got, err, want)
		}
	}
	for _, out := range []string{"", "000\n", "ok"} {
		if _, err := ParseConnectStatus(out); err == nil {
			t.Errorf("ParseConnectStatus(%q) = nil error, want one (no tunnel was attempted)", out)
		}
	}
}

// TestPollEvents: the events oracle waits for the fleet view to SETTLE — a
// non-empty count must hold stable for the stability window before it returns,
// a zero count never settles early (an absent event may just be unflushed; the
// workers forward analytics on their own tick), transient read errors are
// tolerated, and the deadline produces an error that says what was seen unless
// the fleet is genuinely empty. The sleep func is injected, so the test is
// instant.
func TestPollEvents(t *testing.T) {
	since := time.Unix(100, 0)
	ev := func(domain string, at time.Time) analytics.Event {
		return analytics.Event{Domain: domain, Timestamp: at}
	}
	before := ev("old.example.test", since.Add(-time.Minute))
	after := ev("new.example.test", since.Add(time.Minute))

	t.Run("settles_on_a_stable_count", func(t *testing.T) {
		fetches := 0
		fetch := func() ([]analytics.Event, error) {
			fetches++
			return []analytics.Event{before, after}, nil
		}
		var slept time.Duration
		evs, err := PollEvents(fetch, since, time.Minute, 500*time.Millisecond, 2, func(d time.Duration) { slept += d })
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != 1 || evs[0].Domain != "new.example.test" {
			t.Errorf("events = %+v, want only the since-filtered one", evs)
		}
		if fetches != 3 {
			t.Errorf("fetches = %d, want 3 (one read + the 2-poll stability window)", fetches)
		}
		if slept != time.Second {
			t.Errorf("slept %s between polls, want 2×500ms", slept)
		}
	})

	t.Run("waits_while_the_count_grows", func(t *testing.T) {
		calls := 0
		fetch := func() ([]analytics.Event, error) {
			calls++
			return repeat(after, min(calls, 3)), nil
		}
		evs, err := PollEvents(fetch, since, time.Minute, time.Millisecond, 2, func(time.Duration) {})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != 3 {
			t.Errorf("events = %d, want the settled 3", len(evs))
		}
		if calls != 5 {
			t.Errorf("fetches = %d, want 5 (0,1,2,3,3: two stable reads after the last growth)", calls)
		}
	})

	t.Run("catches_a_late_arrival", func(t *testing.T) {
		// THE bug this oracle exists for: an empty first read must not read as
		// "settled at zero" — the workers forward on their own tick, so the
		// event this harness's traffic produced lands whole seconds later.
		calls := 0
		fetch := func() ([]analytics.Event, error) {
			calls++
			if calls < 3 {
				return nil, nil
			}
			return []analytics.Event{after}, nil
		}
		evs, err := PollEvents(fetch, since, time.Minute, time.Millisecond, 1, func(time.Duration) {})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != 1 || evs[0].Domain != "new.example.test" {
			t.Errorf("events = %+v, want the event that arrived on the third read", evs)
		}
		if calls != 4 {
			t.Errorf("fetches = %d, want 4 (two empty reads, the arrival, one stable read)", calls)
		}
	})

	t.Run("an_empty_fleet_polls_out_the_deadline_without_error", func(t *testing.T) {
		// Zero is a legitimate answer the caller asserts on — but only after
		// the whole forward pipeline had its chance, never off the first reads.
		calls := 0
		fetch := func() ([]analytics.Event, error) {
			calls++
			return []analytics.Event{before}, nil // everything predates since
		}
		evs, err := PollEvents(fetch, since, 5*time.Millisecond, time.Millisecond, 2, func(time.Duration) {})
		if err != nil {
			t.Fatalf("an empty result at the deadline is not an error: %v", err)
		}
		if len(evs) != 0 {
			t.Errorf("events = %+v, want none (all predate since)", evs)
		}
		if calls < 6 {
			t.Errorf("fetches = %d, want one per tick across the deadline — zero must not settle early", calls)
		}
	})

	t.Run("tolerates_transient_read_errors", func(t *testing.T) {
		calls := 0
		fetch := func() ([]analytics.Event, error) {
			calls++
			if calls == 1 {
				return nil, errFleetDown
			}
			return []analytics.Event{after}, nil
		}
		evs, err := PollEvents(fetch, since, time.Minute, time.Millisecond, 1, func(time.Duration) {})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != 1 {
			t.Errorf("events = %d, want the one good read", len(evs))
		}
	})

	t.Run("deadline_names_what_it_saw", func(t *testing.T) {
		calls := 0
		fetch := func() ([]analytics.Event, error) {
			calls++
			return repeat(after, calls), nil
		}
		_, err := PollEvents(fetch, since, 2*time.Millisecond, time.Millisecond, 2, func(time.Duration) {})
		if err == nil || !strings.Contains(err.Error(), "never settled") {
			t.Fatalf("err = %v, want the settle deadline error", err)
		}
	})

	t.Run("deadline_reports_a_broken_read", func(t *testing.T) {
		_, err := PollEvents(func() ([]analytics.Event, error) { return nil, errFleetDown },
			since, time.Millisecond, time.Millisecond, 2, func(time.Duration) {})
		if err == nil || !strings.Contains(err.Error(), "fleet down") {
			t.Fatalf("err = %v, want the underlying read error", err)
		}
	})
}

var errFleetDown = errString("fleet down")

type errString string

func (e errString) Error() string { return string(e) }

func repeat(ev analytics.Event, n int) []analytics.Event {
	out := make([]analytics.Event, n)
	for i := range out {
		out[i] = ev
	}
	return out
}

// TestDecodeRecorded: the recorder envelope decodes, a dropped record is an
// error (the recorder must be reset between scenarios, never silently lossy),
// and FilterRecorded keeps one host's records in the harness's shape.
func TestDecodeRecorded(t *testing.T) {
	body := []byte(`{"records":[` +
		`{"id":1,"method":"POST","host":"api.example.test","path":"/v1/canary","proto":"HTTP/1.1","header":{"X-Api-Key":["example_secret_001"]},"body":"key=example_secret_001"},` +
		`{"id":2,"method":"GET","host":"llm.example.test","path":"/","proto":"HTTP/2.0","header":{"Authorization":["Bearer CANARY-e2e-0123456789abcdef0123456789abcdef"]},"body":""}],` +
		`"dropped":0}`)
	recs, err := DecodeRecorded(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	api := FilterRecorded(recs, "api.example.test")
	if len(api) != 1 || api[0].Path != "/v1/canary" || api[0].Header.Get("X-Api-Key") != "example_secret_001" {
		t.Errorf("api records = %+v", api)
	}
	if got := FilterRecorded(recs, "evil.example.test"); len(got) != 0 {
		t.Errorf("evil records = %v, want none", got)
	}

	if _, err := DecodeRecorded([]byte(`{"records":[],"dropped":1}`)); err == nil {
		t.Error("a dropped record must be an error: the recorder was not reset between scenarios")
	}
	if _, err := DecodeRecorded([]byte("not json")); err == nil {
		t.Error("garbage must be a decode error")
	}
}

// TestNeedlesDetectsEveryEncoding is the scanner's own proof, moved with the
// needles from test/e2e (they now live here so both suites share them): every
// encoding the hunt claims, at every base64 alignment, with and without
// padding. "\xfb\xff?>>" forces '+' '/' (std) and '-' '_' (url) into the output.
func TestNeedlesDetectsEveryEncoding(t *testing.T) {
	for _, secret := range []string{Canary, "\xfb\xff?>>tail-secret\xfe\xfd"} {
		needles := Needles(secret)
		enc := map[string]func([]byte) string{
			"std-padded":   base64.StdEncoding.EncodeToString,
			"std-raw":      base64.RawStdEncoding.EncodeToString,
			"url-padded":   base64.URLEncoding.EncodeToString,
			"url-raw":      base64.RawURLEncoding.EncodeToString,
			"hex":          hex.EncodeToString,
			"hex-upper":    func(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) },
			"query-escape": func(b []byte) string { return url.QueryEscape(string(b)) },
		}
		for name, f := range enc {
			for pre := 0; pre < 3; pre++ {
				for _, post := range []string{"", "x", "yz", "Zm9v"} {
					text := "header: " + f(append([]byte(strings.Repeat("A", pre)), append([]byte(secret), post...)...)) + " trailer"
					if strings.HasPrefix(name, "hex") || name == "query-escape" {
						text = "k=" + strings.Repeat("A", pre) + f([]byte(secret)) + post
					}
					if len(LeaksIn(text, needles)) == 0 {
						t.Errorf("%s secret %q pre=%d post=%q: not detected in %q", name, secret, pre, post, text)
					}
				}
			}
		}
		if hits := LeaksIn("nothing to see: Zm9vYmFy 0123abcd", needles); len(hits) > 0 {
			t.Errorf("false positive on clean text: %v", hits)
		}
	}
	// The raw canary and its percent-everything form are among the needles.
	ns := Needles(Canary)
	if !bytes.Contains([]byte(ns["raw"]), []byte("CANARY-e2e-")) {
		t.Errorf("raw needle = %q", ns["raw"])
	}
	if ns["url-all-bytes"] == "" {
		t.Error("the percent-everything needle is missing")
	}
}
