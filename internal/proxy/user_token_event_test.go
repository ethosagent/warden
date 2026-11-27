package proxy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/ethosagent/warden/internal/denyreason"
)

// The per-user token fields on the scope reach every scope-based event: the
// allow event, an emitDeny event and the MCP allow event (W-P3-PUS-10).
func TestUserTokenFieldsOnScopeEvents(t *testing.T) {
	st := &syncStore{}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  st,
	})
	if err != nil {
		t.Fatal(err)
	}
	newScope := func(provider string, retried bool) *requestScope {
		return &requestScope{
			domain: "gmail.googleapis.com", port: 443, proto: "https",
			req:               &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "gmail.googleapis.com", Path: "/x"}},
			resp:              &http.Response{StatusCode: 200},
			userTokenProvider: provider, userTokenRetried: retried,
		}
	}
	s := newScope("google", true)
	p.recordAllowEvent(s)
	p.emitDeny(s, denyreason.PolicyNoMatch)
	p.recordMCPAllowEvent(s, "https://gmail.googleapis.com/mcp")
	plain := newScope("", false)
	p.recordAllowEvent(plain)
	p.emitDeny(plain, denyreason.PolicyNoMatch)
	p.recordMCPAllowEvent(plain, "https://gmail.googleapis.com/mcp")

	got := st.snapshot()
	if len(got) != 6 {
		t.Fatalf("got %d events, want 6", len(got))
	}
	for i, e := range got {
		want := i < 3
		if (e.UserTokenProvider == "google") != want || e.UserTokenRetried != want {
			t.Errorf("event %d (%s/%s): provider %q retried %v, want set=%v", i, e.Decision, e.Protocol, e.UserTokenProvider, e.UserTokenRetried, want)
		}
		if e.Provider != "" {
			t.Errorf("event %d: LLM Provider polluted: %q", i, e.Provider)
		}
	}
}
