package identityclient_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/identityclient"
)

// cpReply is one scripted answer of the fake control plane.
type cpReply struct {
	status     int
	body       string
	retryAfter string
}

// fakeCP is an httptest TLS server standing in for POST /oauth2/token: it
// records every form and answers from a script, then with a token of
// expiresIn seconds.
type fakeCP struct {
	srv       *httptest.Server
	expiresIn int

	mu     sync.Mutex
	script []cpReply
	forms  []url.Values
	hdrs   []http.Header
	gate   chan struct{} // when set, a request waits for it to close
	hit    chan struct{} // receives one value per request
	seq    int
}

func newFakeCP(t *testing.T) *fakeCP {
	t.Helper()
	cp := &fakeCP{expiresIn: 900, hit: make(chan struct{}, 64)}
	cp.srv = httptest.NewTLSServer(http.HandlerFunc(cp.serve))
	t.Cleanup(cp.srv.Close)
	return cp
}

func (cp *fakeCP) endpoint() string { return cp.srv.URL + "/oauth2/token" }

func (cp *fakeCP) serve(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	cp.mu.Lock()
	cp.forms = append(cp.forms, r.PostForm)
	cp.hdrs = append(cp.hdrs, r.Header.Clone())
	gate := cp.gate
	var rep *cpReply
	if len(cp.script) > 0 {
		rep = &cp.script[0]
		cp.script = cp.script[1:]
	}
	cp.seq++
	n := cp.seq
	cp.mu.Unlock()
	cp.hit <- struct{}{}
	if gate != nil {
		<-gate
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if rep != nil {
		if rep.retryAfter != "" {
			w.Header().Set("Retry-After", rep.retryAfter)
		}
		w.WriteHeader(rep.status)
		_, _ = w.Write([]byte(rep.body))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "warden-token-secret-" + strconv.Itoa(n), "token_type": "Bearer",
		"issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"expires_in":        cp.expiresIn, "scope": "read",
	})
}

func (cp *fakeCP) reply(rs ...cpReply) {
	cp.mu.Lock()
	cp.script = append(cp.script, rs...)
	cp.mu.Unlock()
}

func (cp *fakeCP) calls() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.forms)
}

func (cp *fakeCP) lastForm() url.Values {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.forms[len(cp.forms)-1]
}

func oauthErr(status int, code string) cpReply {
	b, _ := json.Marshal(map[string]string{"error": code, "error_description": "CP-BODY-MARKER"})
	return cpReply{status: status, body: string(b)}
}

// agentRig is a generated agent key, a fake control plane and an exchanger on
// the shared fake clock.
type agentRig struct {
	cp    *fakeCP
	key   identityclient.AgentKey
	clock *fakeClock
	ex    *identityclient.Exchanger
}

func newAgentRig(t *testing.T) *agentRig {
	t.Helper()
	key, err := identityclient.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	cp := newFakeCP(t)
	clk := newClock()
	return &agentRig{cp: cp, key: key, clock: clk, ex: &identityclient.Exchanger{
		Endpoint: cp.endpoint(), AgentID: "agent-1", Key: key, HTTP: cp.srv.Client(), Now: clk.Now,
	}}
}

// staticSubject is a SubjectSource with a fixed answer.
type staticSubject struct {
	tok string
	err error
}

func (s staticSubject) Subject(context.Context) (string, error) { return s.tok, s.err }

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
