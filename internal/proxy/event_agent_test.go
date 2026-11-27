package proxy

import (
	"path/filepath"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/identity"
)

// TestEventAgentID: every event the proxy records names the agent that made
// the request, and the worker sync read (GetOldestEventIDs) returns it
// (W-P3-PUL-02). LimitRule stays empty until the limit stages fill it.
func TestEventAgentID(t *testing.T) {
	st, err := analytics.NewSQLiteStore("file:"+filepath.Join(t.TempDir(), "w.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sync := &syncStore{}
	e := newIDEnvCfg(t, IdentityModeAttribute, func(c *Config) {
		c.AgentID = "claude-code"
		c.Analytics = &teeStore{SQLiteStore: st, sync: sync}
	})
	if code := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n").get(""); code != 200 {
		t.Fatalf("status = %d", code)
	}
	waitEvent(t, sync, "allow", func(ev analytics.Event) bool { return ev.Decision == "allow" })
	_, evs, err := st.GetOldestEventIDs(10)
	if err != nil || len(evs) == 0 {
		t.Fatalf("GetOldestEventIDs: %d events, err %v", len(evs), err)
	}
	for _, ev := range evs {
		if ev.AgentID != "claude-code" || ev.LimitRule != "" {
			t.Errorf("event agent %q rule %q; want claude-code and empty", ev.AgentID, ev.LimitRule)
		}
	}
}

// teeStore writes to the SQLite store first, then signals the syncStore, so a
// waitEvent hit means the row is readable from SQLite.
type teeStore struct {
	*analytics.SQLiteStore
	sync *syncStore
}

func (s *teeStore) StoreEvent(e analytics.Event) error {
	err := s.SQLiteStore.StoreEvent(e)
	_ = s.sync.StoreEvent(e)
	return err
}

func TestAgentIDFor(t *testing.T) {
	p := &Proxy{cfg: Config{AgentID: "worker-agent"}}
	valid := func(act string) connIdentity {
		return connIdentity{Status: identity.StatusValid, Claims: identity.Claims{Sub: "s", Act: act}}
	}
	tests := []struct {
		name string
		ci   connIdentity
		want string
	}{
		{"valid warden token uses act", valid("claude-code"), "claude-code"},
		{"valid idp token falls back", valid(""), "worker-agent"},
		{"no identity falls back", connIdentity{}, "worker-agent"},
		{"unverified claims are ignored", connIdentity{Status: identity.StatusInvalid, Claims: identity.Claims{Act: "mallory"}}, "worker-agent"},
	}
	for _, tt := range tests {
		if got := p.agentIDFor(tt.ci); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}
