package scenarios

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/harness"
)

// Warden credentials in agent egress (W-P2-APIK-06). An agent request body that
// carries a wak_ API key or a wwt_ worker token is a credential leak: with
// dlp.wardenTokens on, the worker flags it as class credentials, and the DLP mode
// and rules decide the rest. Nothing is detected with the setting off.

const wardenTokenHost = "api.example.com"

func wardenTokenOpts(cfg config.DLPConfig) []harness.Option {
	return []harness.Option{harness.WithDLP(cfg)}
}

// mintWardenCredentials returns a freshly generated wak_ key and a wwt_ token.
// The key comes from apikeys.Generate. The worker token is SHAPE ONLY: random
// bytes built the way generateWorkerToken does it (the real generator is
// unexported); controlplane's TestWorkerTokenPatternMatchesGenerator ties the
// pattern to the real generator. Neither is registered anywhere or printed.
func mintWardenCredentials(t *testing.T) (apiKey, workerToken string) {
	t.Helper()
	g, err := apikeys.Generate(rand.Reader, func(string) bool { return false })
	if err != nil {
		t.Fatalf("apikeys.Generate: %v", err)
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	return g.Plaintext, "wwt_" + strings.ToLower(enc)
}

// postWardenCredentials sends both credentials in one request body and returns
// the response status.
func postWardenCredentials(t *testing.T, h *harness.H) (status int, apiKey, workerToken string) {
	t.Helper()
	apiKey, workerToken = mintWardenCredentials(t)
	body := `{"note":"ci env","k":"` + apiKey + `","w":"` + workerToken + `"}`
	req, err := http.NewRequest(http.MethodPost, "https://"+wardenTokenHost+"/v1/ingest", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("POST through the worker: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, apiKey, workerToken
}

// assertNoTokenInObservables fails if either credential value shows up in the
// worker's logs or anywhere in a recorded event (each event is marshalled whole,
// so no field is skipped).
func assertNoTokenInObservables(t *testing.T, h *harness.H, vals ...string) {
	t.Helper()
	logs := h.Logs()
	for _, v := range vals {
		if strings.Contains(logs, v) {
			t.Error("a Warden credential value appears in the worker's logs")
		}
	}
	for _, e := range h.Events() {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		for _, v := range vals {
			if strings.Contains(string(b), v) {
				t.Error("a Warden credential value appears in a recorded event")
			}
		}
	}
}

// wardenTokenOff: dlp is on (monitor) but wardenTokens is unset, so the request
// is forwarded as today and carries no credential finding.
func wardenTokenOff(t *testing.T, h *harness.H) {
	u := h.Upstream(wardenTokenHost)
	status, k, w := postWardenCredentials(t, h)
	if status != http.StatusOK {
		t.Fatalf("POST = %d, want 200", status)
	}
	got := lastRequest(t, u)
	if !strings.Contains(string(got.Body), k) || !strings.Contains(string(got.Body), w) {
		t.Error("the body was altered with wardenTokens off")
	}
	for _, e := range eventsFor(h.Events(), wardenTokenHost, "allow") {
		if slices.Contains(e.DataClasses, "credentials") {
			t.Errorf("a credentials finding was recorded with wardenTokens off: %v", e.DataClasses)
		}
	}
	assertNoTokenInObservables(t, h, k, w)
}

// wardenTokenMonitor: wardenTokens on in monitor mode flags the request as
// credentials and still forwards it unchanged; nothing is blocked.
func wardenTokenMonitor(t *testing.T, h *harness.H) {
	u := h.Upstream(wardenTokenHost)
	status, k, w := postWardenCredentials(t, h)
	if status != http.StatusOK {
		t.Fatalf("monitor POST = %d, want 200", status)
	}
	got := lastRequest(t, u)
	if !strings.Contains(string(got.Body), k) || !strings.Contains(string(got.Body), w) {
		t.Error("monitor mode altered the body")
	}
	h.Eventually("the allow event to carry the credentials finding", func() bool {
		for _, e := range eventsFor(h.Events(), wardenTokenHost, "allow") {
			if slices.Contains(e.DataClasses, "credentials") && e.DLPAction == config.DLPActionMonitor {
				return true
			}
		}
		return false
	})
	assertNoTokenInObservables(t, h, k, w)
}

// wardenTokenEnforce: wardenTokens on, enforce mode and a credentials block rule
// stop the request: 403, a dlp_block deny event, and the upstream sees nothing.
func wardenTokenEnforce(t *testing.T, h *harness.H) {
	u := h.Upstream(wardenTokenHost)
	status, k, w := postWardenCredentials(t, h)
	if status != http.StatusForbidden {
		t.Fatalf("enforce POST = %d, want 403", status)
	}
	if n := len(u.Requests()); n != 0 {
		t.Errorf("the upstream saw %d request(s), want 0", n)
	}
	h.Eventually("a dlp_block deny event", func() bool {
		for _, e := range eventsFor(h.Events(), wardenTokenHost, "deny") {
			if e.Reason == "dlp_block" && slices.Contains(e.DataClasses, "credentials") {
				return true
			}
		}
		return false
	})
	assertNoTokenInObservables(t, h, k, w)
}
