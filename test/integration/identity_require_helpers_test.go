//go:build integration

package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/security"
)

// The helpers of the require-mode end-to-end test (W-P2-WBND-10). They sit on
// top of test/security's stack, which boots the real control plane
// (controlplane.Run: token service, worker CA, agent registry, signed bundles,
// fleet store) and real workers (worker.Run) in this process, so nothing here
// re-implements a check: the test only mints tokens, drives traffic and reads
// what the components recorded.

// skew is identity.clockSkewSeconds of the stack (the default, 60s).
const skew = 60 * time.Second

// requireStack boots a require-mode stack (the stack default) with agent-a and
// agent-b registered, each bound to its own worker.
func requireStack(t *testing.T, opts security.StackOptions) (s *security.Stack, a, b *security.Agent) {
	t.Helper()
	s = security.StartStack(t, opts)
	a = s.RegisterAgent(t, "agent-a", fakes.NewAgentKey(t, "agent-a-key-1"), "eng")
	b = s.RegisterAgent(t, "agent-b", fakes.NewAgentKey(t, "agent-b-key-1"), "eng")
	return s, a, b
}

// claims are the Warden token claims the test reads back.
type claims struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	SID    string   `json:"sid"`
	Groups []string `json:"groups"`
	Act    struct {
		Sub string `json:"sub"`
	} `json:"act"`
	Exp int64 `json:"exp"`
	Iat int64 `json:"iat"`
}

func decode(t testing.TB, token string) claims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("a Warden token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode a Warden token payload: %v", err)
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse a Warden token payload: %v", err)
	}
	return c
}

// expiry is the instant after which the worker no longer serves token: its exp
// plus the verifier's skew.
func expiry(t testing.TB, token string) time.Time {
	t.Helper()
	return time.Unix(decode(t, token).Exp, 0).Add(skew)
}

// advanceTo moves the shared fake clock to at, if it is not already past it.
func advanceTo(s *security.Stack, at time.Time) {
	if d := at.Sub(s.Clock.Now()); d > 0 {
		s.Clock.Advance(d)
	}
}

// connect sends one request through w over CONNECT with token and returns the
// response.
func connect(t testing.TB, s *security.Stack, w *security.Worker, token string) security.Response {
	t.Helper()
	return s.Do(t, w, security.Via(security.TransportConnect, token))
}

// verifyCount is warden_identity_verify_total on w for the labels.
func verifyCount(t testing.TB, s *security.Stack, w *security.Worker, labels map[string]string) float64 {
	t.Helper()
	return s.Metric(t, w, "warden_identity_verify_total", labels)
}

// eventsFor returns the stored events of w that carry sub, oldest first.
func eventsFor(t testing.TB, s *security.Stack, w *security.Worker, sub string) []analytics.Event {
	t.Helper()
	var out []analytics.Event
	for _, e := range s.AllEvents(t, w) {
		if e.UserSub == sub {
			out = append(out, e)
		}
	}
	return out
}

// httpOK is a 2xx status.
func httpOK(status int) bool { return status >= http.StatusOK && status < http.StatusMultipleChoices }
