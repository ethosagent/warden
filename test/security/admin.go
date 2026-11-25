package security

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/fakes"
)

// The admin actions of the binding and lifetime cases: each is an operator
// request to the control plane's console API, exactly as in production, and
// returns once the control plane accepted it. The cut reaches a worker with the
// next signed bundle: wait for it with AwaitBundle.

// agentRevision reads agent id's current revision from GET
// /dashboard/api/agents/{id}, the value If-Match carries back.
func (s *Stack) agentRevision(tb testing.TB, id string) int64 {
	tb.Helper()
	r := s.AdminSession(tb).Do(tb, http.MethodGet, agentsPath+"/"+id, nil)
	var v struct {
		Revision int64 `json:"revision"`
	}
	if r.Status != http.StatusOK || json.Unmarshal([]byte(r.Body), &v) != nil || v.Revision <= 0 {
		tb.Fatalf("security: GET %s/%s = %d %s", agentsPath, id, r.Status, r.Body)
	}
	return v.Revision
}

func ifMatch(rev int64) http.Header {
	return http.Header{"If-Match": {`"r` + strconv.FormatInt(rev, 10) + `"`}}
}

// RotateAgentKey replaces agent a's registered key with newKey through PUT
// /dashboard/api/agents/{id} and returns the agent holding the new key. The
// token a held before the call keeps its old cnf.jkt.
func (s *Stack) RotateAgentKey(tb testing.TB, a *Agent, newKey *fakes.AgentKey, groups ...string) *Agent {
	tb.Helper()
	return s.putAgent(tb, a.ID, newKey, groups)
}

// UpdateAgent replaces agent a's allowed groups and keeps its registered key.
func (s *Stack) UpdateAgent(tb testing.TB, a *Agent, groups ...string) *Agent {
	tb.Helper()
	return s.putAgent(tb, a.ID, a.Key, groups)
}

func (s *Stack) putAgent(tb testing.TB, id string, newKey *fakes.AgentKey, groups []string) *Agent {
	tb.Helper()
	a := &Agent{ID: id}
	r := s.AdminSession(tb).DoWith(tb, http.MethodPut, agentsPath+"/"+a.ID, map[string]any{
		"id": a.ID, "displayName": a.ID, "keys": []json.RawMessage{newKey.JWK()}, "allowedGroups": groups,
	}, ifMatch(s.agentRevision(tb, a.ID)))
	if r.Status != http.StatusOK {
		tb.Fatalf("security: PUT %s/%s = %d %s", agentsPath, a.ID, r.Status, r.Body)
	}
	return &Agent{ID: a.ID, Key: newKey}
}

// SetAgentEnabled posts /disable or /enable for agent id.
func (s *Stack) SetAgentEnabled(tb testing.TB, id string, enabled bool) {
	tb.Helper()
	action := "disable"
	if enabled {
		action = "enable"
	}
	r := s.AdminSession(tb).DoWith(tb, http.MethodPost, agentsPath+"/"+id+"/"+action, nil, ifMatch(s.agentRevision(tb, id)))
	if r.Status != http.StatusOK {
		tb.Fatalf("security: POST %s/%s/%s = %d %s", agentsPath, id, action, r.Status, r.Body)
	}
}

// BlockUser adds sub to the block list through POST /dashboard/api/blocked-users.
func (s *Stack) BlockUser(tb testing.TB, sub string) {
	tb.Helper()
	r := s.AdminSession(tb).Do(tb, http.MethodPost, "/dashboard/api/blocked-users", map[string]any{"sub": sub, "reason": "security suite"})
	if r.Status != http.StatusOK && r.Status != http.StatusCreated {
		tb.Fatalf("security: POST blocked-users for %s = %d %s", sub, r.Status, r.Body)
	}
}

// RotateTokenKey runs POST /dashboard/api/keys/rotate for the token purpose.
func (s *Stack) RotateTokenKey(tb testing.TB, emergency bool) {
	tb.Helper()
	r := s.AdminSession(tb).Do(tb, http.MethodPost, "/dashboard/api/keys/rotate", map[string]any{"purpose": "token", "emergency": emergency})
	if r.Status != http.StatusOK {
		tb.Fatalf("security: POST keys/rotate = %d %s", r.Status, r.Body)
	}
}

// BundleSeq is w's warden_bundle_seq: the generation of the bundle it applied.
func (s *Stack) BundleSeq(tb testing.TB, w *Worker) float64 {
	tb.Helper()
	return s.Metric(tb, w, "warden_bundle_seq", nil)
}

// cutBound is how long a cut may take to reach a worker, in real time, from the
// moment the admin call returned.
const cutBound = 3 * time.Second

// Cut is an admin cut that has been accepted by the control plane. The worker
// learns it with the next signed bundle; Within asserts what the worker shows
// by a real-time deadline measured from the moment the admin call returned.
type Cut struct {
	s       *Stack
	w       *Worker
	seq     float64
	started time.Time
}

// StartCut reads w's bundle seq, runs apply (the admin call) and starts the
// clock when it returns.
func (s *Stack) StartCut(tb testing.TB, w *Worker, apply func()) *Cut {
	tb.Helper()
	c := &Cut{s: s, w: w, seq: s.BundleSeq(tb, w)}
	apply()
	c.started = time.Now()
	return c
}

// Within polls cond every 100ms of real time, without moving the fake clock,
// and fails unless it holds within bound of the cut. It returns the elapsed
// time.
func (c *Cut) Within(tb testing.TB, bound time.Duration, desc string, cond func() bool) time.Duration {
	tb.Helper()
	for {
		if cond() {
			return time.Since(c.started)
		}
		if time.Since(c.started) > bound {
			tb.Fatalf("security: %s did not %s within %s of the cut\nlast log lines:\n%s", c.w.Name, desc, bound, tail(c.s.logs.String(), 1500))
		}
		<-time.After(100 * time.Millisecond)
	}
}

// Applied waits, within cutBound, for the worker to hold a bundle newer than
// the one it had before the cut.
func (c *Cut) Applied(tb testing.TB) {
	tb.Helper()
	c.Within(tb, cutBound, "apply the bundle that carries the cut", func() bool {
		v, ok := c.s.TryMetric(c.w, "warden_bundle_seq", nil)
		return ok && v > c.seq
	})
}

// AwaitBundle drives the shared clock until w has applied a bundle newer than
// seq. Setup uses it for state the case does not assert a deadline on.
func (s *Stack) AwaitBundle(tb testing.TB, w *Worker, seq float64) {
	tb.Helper()
	s.EventuallyAdvance(w.Name+" to apply a bundle newer than seq "+strconv.FormatFloat(seq, 'f', 0, 64), 100*time.Millisecond, func() bool {
		v, ok := s.TryMetric(w, "warden_bundle_seq", nil)
		return ok && v > seq
	})
}
