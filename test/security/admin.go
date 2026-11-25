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

// AwaitBundle drives the shared clock until w has applied a bundle newer than
// seq: a condition, never a fixed wait. A cut reaches a worker on the control
// plane's real-time policy reload (3s) and the worker's long poll, so no
// fake-time bound holds here; the wait is bounded by the stack's ready
// deadline instead.
func (s *Stack) AwaitBundle(tb testing.TB, w *Worker, seq float64) {
	tb.Helper()
	s.EventuallyAdvance(w.Name+" to apply a bundle newer than seq "+strconv.FormatFloat(seq, 'f', 0, 64), 100*time.Millisecond, func() bool {
		v, ok := s.TryMetric(w, "warden_bundle_seq", nil)
		return ok && v > seq
	})
}
