package proxy

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/auditlog"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// TestIdentityBindingRecordedThroughStreams: a bound request goes through
// recordEvent to the store and through a real decision-line sink; the stored
// event carries sid, act and token type, the line carries user.act and
// user.token_type, and no token appears in either.
func TestIdentityBindingRecordedThroughStreams(t *testing.T) {
	const token = "tok.secret.value"
	v := &bindVerifier{claims: wardenClaims("agent-7", "T1")}
	v.set(t, 1, map[string]identity.WardenAgent{"agent-7": {Active: true, JKT: jktSet("T1")}})
	p := bindProxy(t, v)
	ci := p.resolveConnIdentity(1, connectBasic(token))
	s := stageScope(ci)
	runIdentity(t, p, s)

	p.recordEvent(s.resolved(), analytics.Event{Domain: "d.test", Decision: "allow"})
	st := p.cfg.Analytics.(*syncStore)
	if len(st.events) != 1 {
		t.Fatalf("%d events stored, want 1", len(st.events))
	}
	ev := st.events[0]
	if ev.UserSID != "wts_1" || ev.UserAct != "agent-7" || ev.IdentityTokenType != "warden" || ev.IdentityStatus != "valid" {
		t.Fatalf("stored event = %+v", ev)
	}

	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	sink, err := auditlog.New(config.JSONLogConfig{Enabled: true, Output: config.JSONLogOutputFile, Path: path, FileMode: 0o600},
		auditlog.Meta{ProxyID: "px", AgentID: "agent-7"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sink.Observe([]analytics.Event{ev})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"act":"agent-7"`, `"token_type":"warden"`, `"sid":"wts_1"`} {
		if !strings.Contains(string(line), want) {
			t.Errorf("decision line lacks %s: %s", want, line)
		}
	}
	for name, all := range map[string]string{"line": string(line), "event": strings.Join([]string{ev.UserSub, ev.UserSID, ev.IdentityReason, ev.URL}, "|")} {
		if strings.Contains(all, token) || strings.Contains(all, "T1") {
			t.Errorf("%s holds token material: %s", name, all)
		}
	}
}

func challengeBindProxy(t *testing.T, v identity.Verifier) *Proxy {
	t.Helper()
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0", Policy: policy.NewEvaluator(config.Policy{}),
		Secrets: &fakes.FakeSecretProvider{Values: map[string]string{}}, Analytics: &syncStore{},
		AgentID: "agent-7", Identity: IdentityConfig{Verifier: v, Mode: IdentityModeChallenge},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A live CONNECT identity that stops binding (key removed, agent disabled, signing
// key removed) ends the request in challenge mode with 403 identity_required.
func TestChallengeTerminatedOnRebindFailure(t *testing.T) {
	active := func(k string) map[string]identity.WardenAgent {
		return map[string]identity.WardenAgent{"agent-7": {Active: true, JKT: jktSet(k)}}
	}
	for _, tc := range []struct {
		name   string
		change func(v *bindVerifier)
		reason identity.Reason
	}{
		{"key_removed", func(v *bindVerifier) { v.set(t, 2, active("T2")) }, identity.ReasonCnfMismatch},
		{"agent_disabled", func(v *bindVerifier) {
			v.set(t, 2, map[string]identity.WardenAgent{"agent-7": {Active: false, JKT: jktSet("T1")}})
		}, identity.ReasonAgentDisabled},
		{"signing_key_removed", func(v *bindVerifier) { v.setKeys(t, 2, nil, active("T1")) }, identity.ReasonUnknownKID},
		{"issuer_changed", func(v *bindVerifier) { v.setKeys(t, 2, []string{"k1"}, active("T1"), "https://other.example") }, identity.ReasonWrongIss},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &bindVerifier{claims: wardenClaims("agent-7", "T1")}
			v.setKeys(t, 1, []string{"k1"}, active("T1"))
			p := challengeBindProxy(t, v)
			ci := p.resolveConnIdentity(1, connectBasic("tok"))
			if ci.Status != identity.StatusValid {
				t.Fatalf("CONNECT = %s/%s", ci.Status, ci.Reason)
			}
			live := stageScope(ci)
			rec := &sinkRecorder{}
			live.out = rec
			p.captureIdentityHeader(live)
			if p.identityStage(live) {
				t.Fatal("request ended before the change")
			}
			tc.change(v)
			s := stageScope(ci)
			rec = &sinkRecorder{}
			s.out = rec
			p.captureIdentityHeader(s)
			if !p.identityStage(s) {
				t.Fatalf("request not ended after %s (status %s/%s)", tc.name, s.idStatus, s.idReason)
			}
			if s.idReason != tc.reason || s.subject != nil {
				t.Errorf("reason %s subject %v, want %s and nil", s.idReason, s.subject, tc.reason)
			}
			if rec.status != http.StatusForbidden || rec.body != identityRequiredBody {
				t.Errorf("answer %d %q, want 403 %s", rec.status, rec.body, identityRequiredBody)
			}
		})
	}
}

// sinkRecorder is a responseSink that records the terminal answer.
type sinkRecorder struct {
	status int
	body   string
}

func (r *sinkRecorder) errorResponse(status int, text string) { r.status, r.body = status, text }
func (r *sinkRecorder) errorJSON(status int, body string)     { r.status, r.body = status, body }
func (r *sinkRecorder) errorJSONRetry(status int, body string, _ int) {
	r.status, r.body = status, body
}
func (r *sinkRecorder) relay(*http.Response) error { return nil }
func (r *sinkRecorder) stream(*http.Response) (io.Writer, error) {
	return io.Discard, nil
}
