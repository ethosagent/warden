package harness

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingTB embeds *testing.T because testing.TB carries an unexported
// method no external type can implement; the embedding supplies Cleanup,
// TempDir and friends, and the overrides below turn Fatalf/Errorf/FailNow
// into RECORDING so a test can assert that an oracle WOULD fail (and with
// what message) without failing itself.
type recordingTB struct {
	*testing.T

	// isParallel mirrors testing.T's unexported flag so the parallel-guard
	// test can drive assertNotParallel through the same reflect path a real
	// *testing.T takes.
	isParallel bool

	// goexitFatal upgrades Fatal/Fatalf from RECORDING to a real testing.T's
	// semantics: record the failure, run THIS TB's own registered cleanups
	// (LIFO, as tRunner does at the Goexit), then runtime.Goexit. A test drives
	// New (or anything that Fatals) with it on a goroutine of its own and reads
	// the outcome from a channel the goroutine's defer feeds — the only way to
	// observe "what a real Fatal actually does to the caller" and keep going.
	goexitFatal bool

	// cleanups backs Cleanup while goexitFatal is set; without the flag,
	// Cleanup delegates to the embedded T as before.
	cleanups []func()

	mu      sync.Mutex
	failed  bool
	message string
}

// Cleanup registers on this TB when goexitFatal is set — fatalNow runs those
// registrations at the Fatal, mirroring a real testing.T. Otherwise it
// delegates to the embedded T, whose cleanups the test framework runs as ever.
func (r *recordingTB) Cleanup(f func()) {
	if r.goexitFatal {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.cleanups = append(r.cleanups, f)
		return
	}
	r.T.Cleanup(f)
}

// fatalNow is a real testing.T Fatal replayed: record, run this TB's own
// cleanups LIFO, then Goexit the calling goroutine. The caller (a test driving
// New on its own goroutine) resumes from the receive its deferred send feeds.
func (r *recordingTB) fatalNow(msg string) {
	r.mu.Lock()
	r.failed = true
	r.message = msg
	cleanups := r.cleanups
	r.cleanups = nil
	r.mu.Unlock()
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
	runtime.Goexit()
}

func (r *recordingTB) Fatalf(format string, args ...any) {
	if r.goexitFatal {
		r.fatalNow(fmt.Sprintf(format, args...))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	r.message = fmt.Sprintf(format, args...)
}

func (r *recordingTB) Fatal(args ...any) {
	r.Fatalf("%v", fmt.Sprint(args...))
}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	r.message = fmt.Sprintf(format, args...)
}

func (r *recordingTB) FailNow() {}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Failed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

func (r *recordingTB) failureMessage() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.message
}

// TestCanary_Format pins the marker format: CANARY- + 24 random hex chars,
// unique per call.
func TestCanary_Format(t *testing.T) {
	re := regexp.MustCompile(`^CANARY-[0-9a-f]{24}$`)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		c := Canary()
		if !re.MatchString(c) {
			t.Fatalf("Canary() = %q, want CANARY- + 24 hex chars", c)
		}
		if seen[c] {
			t.Fatalf("Canary() repeated %q across calls", c)
		}
		seen[c] = true
	}
}

// TestCanary_EchoLeakCaught is the Task D acceptance proof: an upstream that
// reflects request headers (a malicious reflector) hands the REAL swapped
// secret back to the agent under default worker config — the upstream-echo
// leak (#389, being fixed separately). AssertCanaryNeverLeaked must FAIL the
// recording TB and name WHERE the canary appeared. The pre-conditions below
// pin the leak itself: if a fix for #389 lands, the first Fatalf here flips
// and this test must be consciously reworked (the oracle would then be
// catching nothing, because there is nothing to catch).
func TestCanary_EchoLeakCaught(t *testing.T) {
	value := Canary()
	h := New(t, WithSecret("openai", value), Allow("echo.example.com"))
	echo := h.Upstream("echo.example.com")
	echo.EchoHeaders(true)

	req, err := http.NewRequest(http.MethodGet, "https://echo.example.com/reflect", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Placeholder("openai"))
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("GET the reflector through the worker: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET the reflector = %d, want 200", resp.StatusCode)
	}

	// Pre-condition (the #389 behavior): the REAL value came back to the agent.
	if !strings.Contains(string(body), value) {
		t.Fatalf("the reflector's body does not carry the real value — the upstream-echo leak (#389) appears fixed; rework this test so the oracle still has a real leak to catch")
	}

	rec := &recordingTB{T: t}
	h.assertCanaryNeverLeaked(rec)
	if !rec.Failed() {
		t.Fatal("AssertCanaryNeverLeaked passed while the canary reached the agent; the oracle missed a real leak")
	}
	msg := rec.failureMessage()
	for _, want := range []string{"agent response", "openai", "raw"} {
		if !strings.Contains(msg, want) {
			t.Errorf("oracle failure message missing %q:\n%s", want, msg)
		}
	}
}

// TestCanary_CleanRunPasses proves the oracle does not cry wolf: an unscoped
// secret swapped to its destination and a scoped secret swapped ONLY within
// its matchHosts both flow, and the sweep stays silent.
func TestCanary_CleanRunPasses(t *testing.T) {
	unscoped := Canary()
	scoped := Canary()
	h := New(t,
		WithSecret("openai", unscoped),
		WithSecret("db", scoped, "api.example.com"),
	)
	h.FakeLLM() // registers llm.example.com — the POST below must have somewhere to go
	api := h.Upstream("api.example.com")

	// Unscoped secret rides to the LLM fake.
	req, err := http.NewRequest(http.MethodPost, "https://llm.example.com/v1/chat/completions",
		strings.NewReader(`{"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Placeholder("openai"))
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("POST to the LLM fake: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST to the LLM fake = %d, want 200", resp.StatusCode)
	}

	// Scoped secret rides ONLY to its matchHost.
	resp2, err := h.Agent().Post("https://api.example.com/upload", "text/plain",
		strings.NewReader("token="+h.Placeholder("db")))
	if err != nil {
		t.Fatalf("POST to the scoped host: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("POST to the scoped host = %d, want 200", resp2.StatusCode)
	}
	// The scoped value really did reach the scoped upstream (the swap worked).
	sawScoped := false
	for _, r := range api.Requests() {
		if strings.Contains(string(r.Body), scoped) {
			sawScoped = true
		}
	}
	if !sawScoped {
		t.Fatal("scoped upstream never recorded the scoped value; the swap did not happen")
	}

	rec := &recordingTB{T: t}
	h.assertCanaryNeverLeaked(rec)
	if rec.Failed() {
		t.Fatalf("AssertCanaryNeverLeaked failed on a clean run:\n%s", rec.failureMessage())
	}
}

// TestCanary_UpstreamOutOfScopeCaught proves the sweep's upstream clause —
// a scoped secret's value recorded on an upstream OUTSIDE its matchHosts is
// a leak with WHERE. The proxy currently prevents that swap (the #373 scope
// check), so this plants the recorded request directly: the clause exists to
// catch a future proxy regression, and this test pins that it fires.
func TestCanary_UpstreamOutOfScopeCaught(t *testing.T) {
	scoped := Canary()
	h := New(t, WithSecret("db", scoped, "api.example.com"))
	u := h.Upstream("llm.example.com") // OUTSIDE the secret's scope

	// Plant what a regression would produce: the real value on the wrong host.
	u.mu.Lock()
	u.reqs = append(u.reqs, RecordedRequest{
		Method: http.MethodPost,
		Host:   "llm.example.com",
		Path:   "/v1/chat/completions",
		Header: http.Header{"Authorization": {"Bearer " + scoped}},
	})
	u.mu.Unlock()

	rec := &recordingTB{T: t}
	h.assertCanaryNeverLeaked(rec)
	if !rec.Failed() {
		t.Fatal("AssertCanaryNeverLeaked passed while a scoped secret sat on an out-of-scope upstream")
	}
	if msg := rec.failureMessage(); !strings.Contains(msg, "upstream llm.example.com request #0") {
		t.Errorf("oracle failure does not name the leaking upstream:\n%s", msg)
	}
}

// TestCanary_EncodedFormsCaught proves the sweep sees past encodings: the
// base64 and hex forms of a value are leaks too. Same white-box planting as
// TestCanary_UpstreamOutOfScopeCaught (the proxy would have to regress to
// produce these on the wire).
func TestCanary_EncodedFormsCaught(t *testing.T) {
	value := Canary()
	h := New(t, WithSecret("openai", value))
	u := h.Upstream("api.example.com")

	u.mu.Lock()
	u.reqs = append(u.reqs, RecordedRequest{
		Method: http.MethodPost,
		Host:   "api.example.com",
		Path:   "/echo-b64",
		Body:   []byte("payload=" + base64.StdEncoding.EncodeToString([]byte(value))),
	})
	u.mu.Unlock()

	rec := &recordingTB{T: t}
	h.assertCanaryNeverLeaked(rec)
	if !rec.Failed() {
		t.Fatal("oracle passed while a base64-encoded canary sat on an upstream")
	}
	if msg := rec.failureMessage(); !strings.Contains(msg, "base64") {
		t.Errorf("oracle failure does not name the encoding:\n%s", msg)
	}
}

// TestLeakForms_Base64AlignmentShifts pins the shifted-base64 forms: a value
// embedded in a base64 blob after a prefix of ANY length must be found by at
// least one leak form, whatever the alphabet. The prefix's length mod 3 sets
// the value's bit alignment; the plain forms only cover the ≡0 (mod 3) case —
// the shifted forms exist for the other two (`Basic ` + base64("user:"+v) is
// the canonical ≡2 case). One negative: no form of a value may appear in a
// blob carrying a DIFFERENT value.
func TestLeakForms_Base64AlignmentShifts(t *testing.T) {
	value := Canary()
	other := Canary()
	forms := leakForms(value)

	encodings := []struct {
		name string
		enc  *base64.Encoding
	}{
		{"std", base64.StdEncoding},
		{"url", base64.URLEncoding},
		{"std-unpadded", base64.RawStdEncoding},
		{"url-unpadded", base64.RawURLEncoding},
	}
	for _, e := range encodings {
		// Blob framings: the value alone, a 1-byte prefix, "user:" (the Basic
		// case), a 7-byte prefix — every prefix remainder mod 3.
		for _, prefix := range []string{"", "\x80", "user:", "7 bytes"} {
			blob := e.enc.EncodeToString([]byte(prefix + value))
			matched := false
			for _, f := range forms {
				if strings.Contains(blob, f.form) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("%s encoding of %q+%q: no leak form is a substring of %q", e.name, prefix, value, blob)
			}
			// The negative: the same blob built from a different value must not
			// match any of value's forms.
			otherBlob := e.enc.EncodeToString([]byte(prefix + other))
			for _, f := range forms {
				if strings.Contains(otherBlob, f.form) {
					t.Errorf("%s encoding of a DIFFERENT value matched form %q (%s)", e.name, f.form, f.name)
				}
			}
		}
	}

	// The canonical case by name: Authorization: Basic base64("user:"+v) must
	// be caught BY the shift-2 form (prefix "user:" is 5 bytes ≡ 2 mod 3).
	blob := base64.StdEncoding.EncodeToString([]byte("user:" + value))
	for _, f := range forms {
		if f.name == "base64@shift2" && strings.Contains(blob, f.form) {
			return
		}
	}
	t.Errorf("base64@shift2 form did not match Basic base64(%q+value); forms: %+v", "user:", forms)
}

// TestFault_ControlPlaneRestart exercises the outage fault: with the control
// plane down the worker keeps enforcing last-known policy (fail-STATIC, not
// fail-open); after the CP returns on the same address and the worker's
// backoff elapses on the fake clock, the edited policy (host removed) is
// enforced without restarting the worker.
func TestFault_ControlPlaneRestart(t *testing.T) {
	h := New(t)
	h.Upstream("api.example.com")

	// Baseline: allowed by the served policy.
	if status, err := getThrough(h, "https://api.example.com/before"); err != nil {
		t.Fatalf("baseline GET: %v", err)
	} else if status != http.StatusOK {
		t.Fatalf("baseline GET = %d, want 200", status)
	}

	// Edit the served policy: api.example.com is no longer allowed. (This test
	// reaches the in-process target's config path directly — the one place a
	// scenario needs the concrete target; H itself stays on the interface.)
	ip, ok := h.target.(*inprocess)
	if !ok {
		t.Fatalf("target = %T, want the in-process target", h.target)
	}
	if err := os.WriteFile(ip.cp.params.ConfigPath, []byte(
		"logging:\n  level: info\n  format: json\n\npolicy:\n  allowlist:\n    - domain: llm.example.com\n",
	), 0o600); err != nil {
		t.Fatalf("rewrite control-plane policy: %v", err)
	}

	// Outage: the worker rides it on last-known policy.
	h.CP().Stop()
	if status, err := getThrough(h, "https://api.example.com/during"); err != nil {
		t.Fatalf("GET while the control plane is down: %v", err)
	} else if status != http.StatusOK {
		t.Fatalf("GET while the control plane is down = %d, want 200 (last-known policy, not fail-open)", status)
	}

	// Recovery: same address, worker re-polls once its (fake-clock) backoff
	// elapses, and the edited policy is enforced live — probed as a fresh
	// CONNECT, the decision itself.
	h.CP().Start()
	h.Eventually("the worker to deny the removed host after re-polling", func() bool {
		h.Clock().Advance(2 * time.Second)
		return connectStatus(t, h, "api.example.com:443") == http.StatusForbidden
	})
}

// TestFault_UpstreamFail exercises the error fault: the worker relays the
// upstream's 500 to the agent, and the failed request is still recorded
// upstream-side.
func TestFault_UpstreamFail(t *testing.T) {
	h := New(t)
	u := h.Upstream("api.example.com")
	u.Fail(http.StatusInternalServerError)

	resp, err := h.Agent().Get("https://api.example.com/flaky")
	if err != nil {
		t.Fatalf("GET the faulted upstream: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET the faulted upstream = %d, want 500 relayed", resp.StatusCode)
	}
	if n := len(u.Requests()); n != 1 {
		t.Errorf("faulted upstream recorded %d requests, want 1 (faults do not hide traffic)", n)
	}
}

// TestFault_UpstreamDelay exercises the latency fault on harness time: the
// request holds until the fake clock advances — no wall-clock wait anywhere.
// WaitParked makes the hold OBSERVABLE (the request is provably stuck on the
// fault's timer before any Advance), so the test never races a real sleep
// against the request's arrival.
func TestFault_UpstreamDelay(t *testing.T) {
	h := New(t)
	u := h.Upstream("api.example.com")
	u.Delay(5 * time.Second)

	// The probe goroutine only reports; t is touched from the test goroutine.
	type probe struct {
		status int
		err    error
	}
	done := make(chan probe, 1)
	go func() {
		status, err := getThrough(h, "https://api.example.com/slow")
		done <- probe{status, err}
	}()

	// The request has REACHED the fault and is parked on the fake timer. No
	// wall-clock window to race: an Advance issued now cannot be absorbed by a
	// timer that arms after it.
	u.WaitParked(1)
	h.Clock().Advance(5 * time.Second)
	select {
	case p := <-done:
		if p.err != nil {
			t.Fatalf("delayed request: %v", p.err)
		}
		if p.status != http.StatusOK {
			t.Fatalf("delayed request = %d after Advance, want 200", p.status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the delayed request never finished after Advance(5s)")
	}
}

// connectStatus returns the status the worker answers a fresh CONNECT with —
// the policy decision itself, read straight off the proxy's reply line.
func connectStatus(t *testing.T, h *H, hostPort string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the worker proxy: %v", err)
	}
	defer conn.Close()
	req := "CONNECT " + hostPort + " HTTP/1.1\r\nHost: " + hostPort + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("send CONNECT: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	var proto string
	var code int
	if _, err := fmt.Sscanf(line, "%s %d", &proto, &code); err != nil {
		t.Fatalf("parse CONNECT reply %q: %v", line, err)
	}
	return code
}

// getThrough probes policy the way a NEW agent connection would see it: a
// fresh transport per call, so every probe is a fresh CONNECT decision. (An
// established tunnel keeps the decision it was admitted under — that is how a
// CONNECT proxy behaves, and the probe must not ride a pre-change verdict.)
// It reports the status and transport error instead of failing t, so callers
// (including goroutines) decide what a failure means.
func getThrough(h *H, target string) (int, error) {
	tr := &http.Transport{
		Proxy:           func(*http.Request) (*url.URL, error) { return url.Parse("http://" + h.ProxyAddr()) },
		TLSClientConfig: &tls.Config{RootCAs: h.proxyCA.pool(), MinVersion: tls.VersionTLS12},
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get(target)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
