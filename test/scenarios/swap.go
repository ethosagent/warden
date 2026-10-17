package scenarios

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// swapValue is the "real" secret the swap scenarios plant. A fresh canary, so
// AssertCanaryNeverLeaked recognises it anywhere it surfaces. (A target that
// wires its own secrets — compose — supersedes it at boot.)
var swapValue = harness.Canary()

// swapOpts plants swapValue as the "openai" secret, swappable only for the
// fake provider hosts the swap scenarios talk to.
func swapOpts() []harness.Option {
	return []harness.Option{harness.WithSecret("openai", swapValue, "api.example.com", "llm.example.com")}
}

// secretSwapped ports TestE2E_SecretSwapped: the agent holds the placeholder,
// the upstream receives the real value, the analytics record references the
// secret by hash only, and the value never reaches anything the agent or an
// operator can read.
func secretSwapped(t *testing.T, h *harness.H) {
	u := h.Upstream("api.example.com")
	ph := h.Placeholder("openai")
	if ph == swapValue {
		t.Fatal("placeholder must differ from the real value")
	}

	status, body := get(t, h, "https://api.example.com/v1/models", map[string]string{"Authorization": "Bearer " + ph})
	if status != http.StatusOK {
		t.Fatalf("GET = %d, want 200", status)
	}
	if got := lastRequest(t, u).Header.Get("Authorization"); got != "Bearer "+swapValue {
		t.Errorf("upstream Authorization = %q, want the real value swapped in for the placeholder", got)
	}
	if strings.Contains(string(body), swapValue) {
		t.Error("the real value reached the agent's response")
	}

	evs := eventsFor(h.Events(), "api.example.com", "allow")
	if len(evs) != 1 {
		t.Fatalf("allow events = %d, want 1", len(evs))
	}
	if !strings.HasPrefix(evs[0].SecretRef, "sha256:") {
		t.Errorf("SecretRef = %q, want a sha256: reference", evs[0].SecretRef)
	}
	h.AssertCanaryNeverLeaked()
}

// allowWithSwap is manual step 1: an allowed request through the fake LLM. The
// agent sent the placeholder; the provider saw the secret. The host and the
// asserted value come from the harness, so the same body runs against the
// in-process fakes and the compose stack (whose secret wiring is its own).
func allowWithSwap(t *testing.T, h *harness.H) {
	llm := h.FakeLLM()
	ph := h.Placeholder("openai")
	secret := h.Secret("openai")

	req, err := http.NewRequest(http.MethodPost, "https://"+h.Host("llm")+"/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+ph) // what the agent holds and sends
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("POST through the worker: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST = %d, want 200", resp.StatusCode)
	}

	if got := llm.AuthHeaders(); len(got) != 1 || got[0] != "Bearer "+secret {
		t.Errorf("provider Authorization headers = %v, want [Bearer <the real secret>]", got)
	}
	h.AssertCanaryNeverLeaked()
}

// swapInBody is manual step 3: the placeholder rides both a header and the JSON
// body of a POST, and both arrive swapped.
func swapInBody(t *testing.T, h *harness.H) {
	u := h.Upstream("api.example.com")
	ph := h.Placeholder("openai")

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions",
		strings.NewReader(`{"api_key":"`+ph+`","messages":[{"role":"user","content":"Say hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+ph)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("POST through the worker: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST = %d, want 200", resp.StatusCode)
	}

	got := lastRequest(t, u)
	if v := got.Header.Get("Authorization"); v != "Bearer "+swapValue {
		t.Errorf("header Authorization = %q, want the real value", v)
	}
	if !strings.Contains(string(got.Body), `"api_key":"`+swapValue+`"`) {
		t.Errorf("body = %q, want the placeholder swapped for the real value", got.Body)
	}
	if strings.Contains(string(got.Body), ph) || strings.Contains(got.Header.Get("Authorization"), ph) {
		t.Error("a placeholder survived to the upstream")
	}
	h.AssertCanaryNeverLeaked()
}
