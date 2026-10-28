package harness

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// FakeJudge is the LLM endpoint the worker's inline judge is pointed at
// (WithFakeJudge). It answers every call with a deny verdict and counts the
// calls, so a scenario can prove a request was never sent to the judge: a
// group-scoped decision must be made by the policy, not escalated to the LLM.
type FakeJudge struct {
	srv   *httptest.Server
	calls atomic.Int64
}

// Calls is the number of requests the judge endpoint has received.
func (j *FakeJudge) Calls() int { return int(j.calls.Load()) }

// URL is the endpoint's base URL (plain http on loopback).
func (j *FakeJudge) URL() string { return j.srv.URL }

// WithFakeJudge enables the inline judge against a counting loopback endpoint
// that always answers deny (h.Judge()). Like WithUnreachableJudge, a
// destination matching no allowlist rule is then judged inside the tunnel.
func WithFakeJudge() Option {
	return func(h *H) {
		h.tb.Setenv(judgeKeyEnv, "harness-judge-key-not-a-secret")
		j := &FakeJudge{}
		j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			j.calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"j","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"{\"decision\":\"deny\",\"reason\":\"harness fake judge\"}"},"finish_reason":"stop"}]}`))
		}))
		h.closers = append(h.closers, j.srv.Close)
		h.fakeJudge = j
	}
}

// Judge returns the fake judge endpoint started by WithFakeJudge.
func (h *H) Judge() *FakeJudge {
	h.tb.Helper()
	if h.fakeJudge == nil {
		h.tb.Fatal("harness: Judge needs the WithFakeJudge option")
	}
	return h.fakeJudge
}

// The judge needs a policy for its agent: with one agent configured the
// worker's id is that agent's id.
const (
	fakeJudgeAgent  = "harness-agent"
	fakeJudgePolicy = "Deny everything."
)

// fakeJudgeYAML is the judge and agents blocks the control plane distributes
// (settings carry the key's env NAME only). The harness worker is always
// control-plane managed, and its first settings apply replaces the boot-local
// judge with what the control plane serves, so the judge must be served too.
func (h *H) fakeJudgeYAML() string {
	if h.fakeJudge == nil {
		return ""
	}
	return fmt.Sprintf(`
judge:
  enabled: true
  model: harness-judge
  baseURL: %s
  apiKeyEnv: %s
  timeout: 1s
agents:
  - id: %s
    policy: %q
`, h.fakeJudge.URL(), judgeKeyEnv, fakeJudgeAgent, fakeJudgePolicy)
}

// applyFakeJudge points worker policy p's judge at the fake endpoint.
func (h *H) applyFakeJudge(p *config.Policy) {
	if h.fakeJudge == nil {
		return
	}
	p.Agents = []config.AgentPolicy{{ID: fakeJudgeAgent, Policy: fakeJudgePolicy}}
	p.Judge = config.JudgeConfig{
		Enabled:   true,
		Model:     "harness-judge",
		BaseURL:   h.fakeJudge.URL(),
		APIKeyEnv: judgeKeyEnv,
		Timeout:   time.Second,
	}
}

// WithoutProxyCA boots the workers with no TLS-termination CA (the
// production default when tls.caCert is unset): CONNECT tunnels are opaque, so
// a destination that needs a per-request decision fails closed at CONNECT.
// The agent clients (h.Agent) cannot reach HTTPS through such a worker; probe
// with ConnectStatusWithAuth.
func WithoutProxyCA() Option {
	return func(h *H) { h.noProxyCA = true }
}

// WithScopedAllow adds an identity-scoped allow entry ({domain, groups}) to the
// control plane's served policy at boot, beside the harness's own hosts. Boot
// YAML, not a dashboard save, so a scenario that also edits the served file for
// MCP settings never rewrites it through the dashboard's YAML mirror.
func WithScopedAllow(domain string, groups ...string) Option {
	return func(h *H) {
		h.scopedAllow = append(h.scopedAllow, scopedAllowSpec{domain: domain, groups: groups})
	}
}

type scopedAllowSpec struct {
	domain string
	groups []string
}
