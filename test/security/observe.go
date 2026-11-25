package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// The observation helpers read what the components recorded, through the same
// surfaces an operator reads: a worker's admin /metrics scrape, its event
// store, the control plane's admin audit table and token_events table, and the
// logs. They never reach into a component's memory.

// Sample is one series of a Prometheus text scrape.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// Scrape reads the worker's admin /metrics and parses it.
func (s *Stack) Scrape(tb testing.TB, w *Worker) []Sample {
	tb.Helper()
	text, err := s.scrapeText(w)
	if err != nil {
		tb.Fatalf("security: scrape %s /metrics: %v", w.Name, err)
	}
	return parseProm(text)
}

func (s *Stack) scrapeText(w *Worker) (string, error) {
	cl := harness.NewLoopbackClient(nil, harness.ClientOptions{Timeout: 5 * time.Second})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+w.AdminAddr+"/metrics", nil)
	if err != nil {
		return "", err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	return string(b), nil
}

// Metric is the sum of every series of name whose labels include all of
// labels: a counter that has not been recorded yet reads 0. The worker's admin
// scrape is the only source.
func (s *Stack) Metric(tb testing.TB, w *Worker, name string, labels map[string]string) float64 {
	tb.Helper()
	v, _ := sumSamples(s.Scrape(tb, w), name, labels)
	return v
}

// TryMetric is Metric for a wait condition: it reports whether any series
// matched and never fails the test (a scrape error reads as "not yet").
func (s *Stack) TryMetric(w *Worker, name string, labels map[string]string) (float64, bool) {
	text, err := s.scrapeText(w)
	if err != nil {
		return 0, false
	}
	return sumSamples(parseProm(text), name, labels)
}

func sumSamples(samples []Sample, name string, labels map[string]string) (float64, bool) {
	var sum float64
	found := false
	for _, sm := range samples {
		if sm.Name != name {
			continue
		}
		ok := true
		for k, v := range labels {
			if sm.Labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			sum += sm.Value
			found = true
		}
	}
	return sum, found
}

// parseProm parses the Prometheus text exposition format: comment lines are
// skipped and every other line is name{labels} value [timestamp].
func parseProm(text string) []Sample {
	var out []Sample
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest := line, ""
		labels := map[string]string{}
		if i := strings.IndexByte(line, '{'); i >= 0 {
			name = line[:i]
			j := closingBrace(line, i)
			if j < 0 {
				continue
			}
			parseLabels(line[i+1:j], labels)
			rest = strings.TrimSpace(line[j+1:])
		} else if i := strings.IndexByte(line, ' '); i >= 0 {
			name, rest = line[:i], strings.TrimSpace(line[i+1:])
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		out = append(out, Sample{Name: name, Labels: labels, Value: v})
	}
	return out
}

// closingBrace finds the } that closes the label set opened at i, skipping
// braces inside quoted label values.
func closingBrace(line string, i int) int {
	inQuote := false
	for k := i + 1; k < len(line); k++ {
		switch c := line[k]; {
		case c == '\\' && inQuote:
			k++
		case c == '"':
			inQuote = !inQuote
		case c == '}' && !inQuote:
			return k
		}
	}
	return -1
}

func parseLabels(s string, out map[string]string) {
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return
		}
		key := strings.TrimSpace(s[:eq])
		s = s[eq+1:]
		if !strings.HasPrefix(s, `"`) {
			return
		}
		var val strings.Builder
		k := 1
		for ; k < len(s); k++ {
			if s[k] == '\\' && k+1 < len(s) {
				k++
				val.WriteByte(s[k])
				continue
			}
			if s[k] == '"' {
				break
			}
			val.WriteByte(s[k])
		}
		out[key] = val.String()
		if k >= len(s) {
			return
		}
		s = strings.TrimPrefix(strings.TrimSpace(s[k+1:]), ",")
		s = strings.TrimSpace(s)
	}
}

// DenyEvents returns the deny events worker w persisted, oldest first. It
// first drains the worker's async analytics writer, so the events of traffic a
// case has already finished making are readable, then reads the store through
// the production analytics package.
func (s *Stack) DenyEvents(tb testing.TB, w *Worker) []analytics.Event {
	tb.Helper()
	return s.events(tb, w, analytics.EventFilter{Decision: "deny"})
}

// AllEvents returns every event worker w persisted (allow and deny), oldest
// first, after draining its writer.
func (s *Stack) AllEvents(tb testing.TB, w *Worker) []analytics.Event {
	tb.Helper()
	return s.events(tb, w, analytics.EventFilter{})
}

func (s *Stack) events(tb testing.TB, w *Worker, f analytics.EventFilter) []analytics.Event {
	tb.Helper()
	s.WaitIdle(tb)
	if err := w.flushAnalytics(); err != nil {
		tb.Fatalf("security: drain %s analytics (a failed flush means the events were NOT persisted): %v", w.Name, err)
	}
	st, err := analytics.NewSQLiteStore("file:"+w.DBPath+"?_pragma=busy_timeout(10000)", 0)
	if err != nil {
		tb.Fatalf("security: open %s analytics store: %v", w.Name, err)
	}
	defer func() { _ = st.Close() }()
	evs, err := st.GetEvents(f)
	if err != nil {
		tb.Fatalf("security: read %s events: %v", w.Name, err)
	}
	return evs
}

// AuditRow is one row of the control plane's admin audit table.
type AuditRow struct {
	Seq        int64
	Action     string
	AuthMethod string
	ActorRole  string
	Target     string
	TargetRef  string
	Outcome    string
	HTTPStatus int
	// Details is the row's details object as stored (JSON).
	Details string
	Sub     string
}

// AuditRows returns the admin audit rows whose action is action ("" = all),
// oldest first, read straight from the CP's state database.
func (s *Stack) AuditRows(tb testing.TB, action string) []AuditRow {
	tb.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(s.CP.StateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		tb.Fatalf("security: open the CP state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT a.seq, a.action, a.auth_method, a.actor_role, a.target, a.target_ref,
		a.outcome, a.http_status, a.details_json, COALESCE(s.sub, '')
		FROM admin_audit a LEFT JOIN admin_audit_actor s ON s.seq = a.seq ORDER BY a.seq`)
	if err != nil {
		tb.Fatalf("security: read admin_audit: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.Seq, &r.Action, &r.AuthMethod, &r.ActorRole, &r.Target, &r.TargetRef,
			&r.Outcome, &r.HTTPStatus, &r.Details, &r.Sub); err != nil {
			tb.Fatalf("security: scan an admin_audit row: %v", err)
		}
		if action == "" || r.Action == action {
			out = append(out, r)
		}
	}
	if err := rows.Err(); err != nil {
		tb.Fatalf("security: read admin_audit: %v", err)
	}
	return out
}

// TokenEvent is one row of the control plane's token_events table: what the
// token endpoint decided, which is not admin-audited.
type TokenEvent struct {
	ID      int64
	Outcome string
	Reason  string
	AgentID string
	JTI     string
	KID     string
	Scope   string
}

// TokenEvents returns every token_events row, oldest first.
func (s *Stack) TokenEvents(tb testing.TB) []TokenEvent {
	tb.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(s.CP.StateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		tb.Fatalf("security: open the CP state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT id, outcome, reason, agent_id, jti, kid, scope FROM token_events ORDER BY id`)
	if err != nil {
		tb.Fatalf("security: read token_events: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []TokenEvent
	for rows.Next() {
		var e TokenEvent
		if err := rows.Scan(&e.ID, &e.Outcome, &e.Reason, &e.AgentID, &e.JTI, &e.KID, &e.Scope); err != nil {
			tb.Fatalf("security: scan a token_events row: %v", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		tb.Fatalf("security: read token_events: %v", err)
	}
	return out
}

// Logs returns everything the CP and the workers logged so far.
func (s *Stack) Logs(tb testing.TB) string {
	tb.Helper()
	return s.logs.String()
}

// surfaces returns every place a secret must never appear, by name: the logs,
// each worker's scrape and deny events, the admin audit rows and the
// token_events rows. The upstream requests are checked separately.
func (s *Stack) surfaces(tb testing.TB) map[string]string {
	tb.Helper()
	out := map[string]string{"logs": s.logs.String()}
	for _, w := range s.Workers {
		text, err := s.scrapeText(w)
		if err != nil {
			tb.Fatalf("security: scrape %s /metrics for the leak check: %v", w.Name, err)
		}
		out[w.Name+" metrics"] = text
		evs, err := json.Marshal(s.AllEvents(tb, w))
		if err != nil {
			tb.Fatalf("security: encode %s events: %v", w.Name, err)
		}
		out[w.Name+" events"] = string(evs)
	}
	audit, err := json.Marshal(s.AuditRows(tb, ""))
	if err != nil {
		tb.Fatalf("security: encode the audit rows: %v", err)
	}
	out["admin audit rows"] = string(audit)
	tev, err := json.Marshal(s.TokenEvents(tb))
	if err != nil {
		tb.Fatalf("security: encode the token events: %v", err)
	}
	out["token_events rows"] = string(tev)
	return out
}
