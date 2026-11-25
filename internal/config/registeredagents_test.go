package config

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	jktA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	jktB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	jktC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func TestRegisteredAgents_Validate(t *testing.T) {
	ok := func(id string, jkt ...string) RegisteredAgent {
		return RegisteredAgent{ID: id, Status: "active", JKT: jkt}
	}
	many := make([]RegisteredAgent, MaxRegisteredAgents+1)
	cases := []struct {
		name string
		in   []RegisteredAgent
		bad  string // substring of the error; "" = valid
	}{
		{"empty", nil, ""},
		{"two agents", []RegisteredAgent{ok("a", jktA), ok("b", jktB, jktC)}, ""},
		{"disabled", []RegisteredAgent{{ID: "a", Status: "disabled", JKT: []string{jktA}}}, ""},
		{"bad id", []RegisteredAgent{ok("!identity-scoped", jktA)}, "invalid id"},
		{"empty id", []RegisteredAgent{ok("", jktA)}, "invalid id"},
		{"duplicate id", []RegisteredAgent{ok("a", jktA), ok("a", jktB)}, "unique and sorted"},
		{"unsorted", []RegisteredAgent{ok("b", jktA), ok("a", jktB)}, "unique and sorted"},
		{"bad status", []RegisteredAgent{{ID: "a", Status: "paused", JKT: []string{jktA}}}, "status"},
		{"empty status", []RegisteredAgent{{ID: "a", JKT: []string{jktA}}}, "status"},
		{"no jkt", []RegisteredAgent{ok("a")}, "1 to 2"},
		{"three jkt", []RegisteredAgent{ok("a", jktA, jktB, jktC)}, "1 to 2"},
		{"short jkt", []RegisteredAgent{ok("a", "abc")}, "43-character"},
		{"bad jkt char", []RegisteredAgent{ok("a", strings.Repeat("+", 43))}, "43-character"},
		{"jkt shared across agents", []RegisteredAgent{ok("a", jktA), ok("b", jktA)}, "not unique"},
		{"jkt repeated in one agent", []RegisteredAgent{ok("a", jktA, jktA)}, "not unique"},
		{"too many", many, "exceeds the limit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateRegisteredAgents(c.in)
			if c.bad == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.bad) {
				t.Fatalf("err = %v, want %q", err, c.bad)
			}
			if strings.Contains(err.Error(), jktA) {
				t.Errorf("error carries a thumbprint: %v", err)
			}
		})
	}
}

func TestRegisteredAgents_ParseRemotePolicy(t *testing.T) {
	const base = `"allowlist":[{"domain":"a.example.com"}],"denylist":[]`
	t.Run("absent key", func(t *testing.T) {
		p, _, err := parseRemotePolicy([]byte(`{` + base + `}`))
		if err != nil || len(p.RegisteredAgents) != 0 {
			t.Fatalf("p = %+v, err = %v", p, err)
		}
	})
	t.Run("sorted on decode", func(t *testing.T) {
		p, _, err := parseRemotePolicy([]byte(`{` + base + `,"registeredAgents":[` +
			`{"id":"b","status":"disabled","jkt":["` + jktB + `"]},{"id":"a","status":"active","jkt":["` + jktA + `"]}]}`))
		if err != nil || len(p.RegisteredAgents) != 2 || p.RegisteredAgents[0].ID != "a" || p.RegisteredAgents[1].Status != "disabled" {
			t.Fatalf("p = %+v, err = %v", p.RegisteredAgents, err)
		}
	})
	t.Run("invalid list rejects the whole wire", func(t *testing.T) {
		_, _, err := parseRemotePolicy([]byte(`{` + base + `,"registeredAgents":[{"id":"a","status":"paused","jkt":["` + jktA + `"]}]}`))
		if err == nil {
			t.Fatal("an invalid registeredAgents list was accepted")
		}
	})
}

// DeepCopy gives the copy its own agents and thumbprint slices; run under -race.
func TestRegisteredAgents_DeepCopy(t *testing.T) {
	p := Policy{RegisteredAgents: []RegisteredAgent{{ID: "a", Status: "active", JKT: []string{jktA}}}}
	cp := p.DeepCopy()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		cp.RegisteredAgents[0].JKT[0] = jktB
		cp.RegisteredAgents[0].Status = "disabled"
	}()
	go func() { defer wg.Done(); _ = p.RegisteredAgents[0].JKT[0] }()
	wg.Wait()
	if p.RegisteredAgents[0].JKT[0] != jktA || p.RegisteredAgents[0].Status != "active" {
		t.Fatalf("mutating the copy changed the original: %+v", p.RegisteredAgents)
	}
	if (Policy{}).DeepCopy().RegisteredAgents != nil {
		t.Error("a nil list became non-nil")
	}
}

// TestRegisteredAgents_InvalidWireKeepsDisabled: a worker that holds a list
// with a disabled agent and then pulls a wire whose registeredAgents it cannot
// validate rejects the whole wire and keeps the last-known-good policy, so the
// disabled agent is never re-enabled by a bad or newer list.
func TestRegisteredAgents_InvalidWireKeepsDisabled(t *testing.T) {
	bodies := []string{
		`{"allowlist":[{"domain":"a.example.com"}],"registeredAgents":[{"id":"claude-code","status":"disabled","jkt":["` + jktA + `"]}]}`,
		// A status this build does not know, as a newer control plane would serve.
		`{"allowlist":[{"domain":"b.example.com"}],"registeredAgents":[{"id":"claude-code","status":"suspended","jkt":["` + jktA + `"]}]}`,
		// Three keys: more than the two a worker accepts.
		`{"allowlist":[{"domain":"c.example.com"}],"registeredAgents":[{"id":"claude-code","status":"active","jkt":["` + jktA + `","` + jktB + `","` + jktC + `"]}]}`,
	}
	var n int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bodies[n]))
	}))
	defer srv.Close()
	rp, err := NewRemoteProvider(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	rp.client = srv.Client()
	if err := rp.Pull(); err != nil {
		t.Fatalf("first Pull: %v", err)
	}
	for n = 1; n < len(bodies); n++ {
		if err := rp.Pull(); err == nil {
			t.Fatalf("wire %d with an invalid registeredAgents list was accepted", n)
		}
		pol, err := rp.GetPolicy()
		if err != nil {
			t.Fatal(err)
		}
		if len(pol.RegisteredAgents) != 1 || pol.RegisteredAgents[0].Status != RegisteredAgentDisabled || pol.Allowlist[0].Domain != "a.example.com" {
			t.Fatalf("after rejecting wire %d the policy is %+v, want the last-known-good (disabled agent, a.example.com)", n, pol)
		}
	}
}
