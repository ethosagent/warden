package security

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Path is the part of the system a case attacks.
type Path string

// The five paths of the case matrix.
const (
	PathWorker  Path = "worker"   // traffic through a worker's proxy
	PathToken   Path = "token"    // POST /oauth2/token
	PathCPRoute Path = "cp-route" // a worker-facing or dashboard CP route
	PathEnroll  Path = "enroll"   // /control/enroll and /control/renew
	PathBundle  Path = "bundle"   // the signed bundle on /policy
)

// Observed is what the attacker saw. Build it with Seen (a worker Response) or
// SeenReply (a CP reply).
type Observed struct {
	Status int
	Header http.Header
	Body   string
	// Responses and Replies feed the leak invariant.
	Responses []Response
	Replies   []Reply
}

// Seen is the Observed of a worker response.
func Seen(r Response) Observed {
	return Observed{Status: r.Status, Header: r.Header, Body: r.Body, Responses: []Response{r}}
}

// SeenReply is the Observed of a CP reply.
func SeenReply(r Reply) Observed {
	return Observed{Status: r.Status, Header: r.Header, Body: r.Body, Replies: []Reply{r}}
}

// Case is one attack and everything it must be rejected with. Later tickets
// add cases and nothing else: the runner owns the assertions and the leak
// invariant, so a case cannot pass because it forgot to look.
type Case struct {
	// Name names the subtest. Path says what is attacked.
	Name string
	Path Path
	// Covers lists the enum values this case is the test of (see Covers*
	// constructors). The enum-completeness test needs every identity.Reason,
	// bundle.Reason, token-service reason and worker-facing route in some
	// case's Covers or in pending.go.
	Covers []string

	// Setup, when set, runs before the case's assertion sources are read: it
	// builds the state the attack needs (a held tunnel, a prepared token) and
	// keeps it with Stack.Put, so a case stays plain package-level data and the
	// hits and events it makes do not count against the attack.
	Setup func(t testing.TB, s *Stack)

	// Attack performs the attack and returns what the attacker saw.
	Attack func(t testing.TB, s *Stack) Observed

	// WantStatus is the HTTP status the attacker must see (0 = not checked).
	WantStatus int
	// WantBody, when set, must be contained in the body.
	WantBody string
	// WantHeader, when set, must be present on the reply: name -> value (a
	// value of "*" means any non-empty value).
	WantHeader map[string]string

	// Worker is the agent id of the worker whose metrics and events the case
	// asserts on (default: the first worker).
	Worker string
	// WantResult and WantReason are the assertion sources of the path. On a
	// worker path, warden_identity_verify_total{result,reason} must rise by
	// exactly one. On a token path, exactly one new token_events row must
	// carry outcome WantResult and reason WantReason. On a bundle path,
	// warden_bundle_rejected_total{reason=WantReason} must rise by one.
	WantResult, WantReason string
	// Unauthenticated marks a token-path refusal of a caller whose client
	// assertion did not authenticate (a disabled agent is one): the service
	// writes no token_events row for it, so the case asserts that none is
	// written and reads WantReason from the rate-limited
	// token_exchange_unauthenticated warning instead. WantResult stays empty.
	Unauthenticated bool
	// WantDeny, when set, is the Reason of a new deny event on the worker.
	WantDeny string
	// WantAudit, when set, is the action of exactly one new admin audit row.
	WantAudit string
	// WantLog, when set, must appear in the logs written during the case.
	WantLog string
	// WantUpstreamHits is how many requests may reach the upstream during the
	// case: 0 for an attack, 1 for an allowed control.
	WantUpstreamHits int
}

// Covers constructors: the strings a Case.Covers and a pending.go entry share.
func CoverIdentity(reason string) string { return "identity.reason:" + reason }

// CoverBundle covers a bundle.Reason (or config.BundleReasonInvalidPolicy).
func CoverBundle(reason string) string { return "bundle.reason:" + reason }

// CoverToken covers a token-service denial reason.
func CoverToken(reason string) string { return "token.reason:" + reason }

// CoverRoute covers a worker-facing control plane route.
func CoverRoute(path string) string { return "route:" + path }

// PositiveControl runs fn as the subtest "positive control" of category and
// records whether it passed. Run refuses to start a category's attack cases
// before its control passed, so no case can pass because the harness rejects
// everything.
func (s *Stack) PositiveControl(t *testing.T, category string, fn func(t *testing.T)) {
	t.Helper()
	ok := t.Run("positive control "+category, fn)
	s.mu.Lock()
	if s.controls == nil {
		s.controls = map[string]bool{}
	}
	s.controls[category] = ok
	s.mu.Unlock()
}

// ControlPassed reports whether category's positive control has passed.
func (s *Stack) ControlPassed(category string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.controls[category]
}

// Run runs cases against s as subtests of t, after category's positive
// control, and asserts for every case: the attacker's status, body and
// headers; the assertion sources the case names; the upstream hit count; and,
// last, AssertNoLeak. Cases run serially: the stack is shared.
func Run(t *testing.T, s *Stack, category string, cases []Case) {
	t.Helper()
	if !s.ControlPassed(category) {
		t.Fatalf("security: category %q: the positive control has not passed; refusing to run attack cases against a stack that may reject everything", category)
	}
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) { s.runCase(t, c) })
	}
}

// RunCase runs one case against s on t and asserts everything Run does, without
// the subtest: the harness's own tests use it with a recording TB to prove a
// wrong expectation or a leak fails.
func (s *Stack) RunCase(t testing.TB, c Case) { s.runCase(t, c) }

func (s *Stack) runCase(t testing.TB, c Case) {
	t.Helper()
	if c.Attack == nil {
		t.Fatalf("security: case %q has no Attack", c.Name)
	}
	w := s.Workers[0]
	if c.Worker != "" {
		w = s.Worker(c.Worker)
	}
	if bad := validateCase(c); len(bad) > 0 {
		for _, b := range bad {
			t.Errorf("case %q is malformed: %s", c.Name, b)
		}
		return
	}
	if c.Setup != nil {
		c.Setup(t, s)
	}
	before := s.snapshot(t, w, c)
	obs := c.Attack(t, s)
	after := s.snapshot(t, w, c)

	if c.WantStatus != 0 && obs.Status != c.WantStatus {
		t.Errorf("status = %d, want %d (body %s)", obs.Status, c.WantStatus, tail(obs.Body, 300))
	}
	if c.WantBody != "" && !strings.Contains(obs.Body, c.WantBody) {
		t.Errorf("body does not contain %q: %s", c.WantBody, tail(obs.Body, 300))
	}
	for name, want := range c.WantHeader {
		got := obs.Header.Get(name)
		if got == "" || want != "*" && got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
	if d := after.hits - before.hits; d != c.WantUpstreamHits {
		t.Errorf("upstream hits = %d, want %d", d, c.WantUpstreamHits)
	}
	switch c.Path {
	case PathWorker:
		if c.WantResult != "" || c.WantReason != "" {
			if d := after.identity - before.identity; d != 1 {
				t.Errorf("warden_identity_verify_total{result=%q,reason=%q} rose by %v, want 1", c.WantResult, c.WantReason, d)
			}
		}
	case PathBundle:
		if c.WantReason != "" {
			if d := after.bundleRejected - before.bundleRejected; d != 1 {
				t.Errorf("warden_bundle_rejected_total{reason=%q} rose by %v, want 1", c.WantReason, d)
			}
		}
	case PathToken:
		if c.Unauthenticated {
			if rows := after.tokenEvents[before.tokenEventCount:]; len(rows) != 0 {
				t.Errorf("new token_events rows = %+v, want none for a caller that did not authenticate", rows)
			}
			logs := after.logs[before.logLen:]
			if !strings.Contains(logs, "token_exchange_unauthenticated") || !strings.Contains(logs, `"reason":"`+c.WantReason+`"`) {
				t.Errorf("the logs written during the case carry no token_exchange_unauthenticated warning with reason %q", c.WantReason)
			}
		} else if c.WantResult != "" || c.WantReason != "" {
			rows := after.tokenEvents[before.tokenEventCount:]
			if len(rows) != 1 || rows[0].Outcome != c.WantResult || rows[0].Reason != c.WantReason {
				t.Errorf("new token_events rows = %+v, want exactly one with outcome %q reason %q", rows, c.WantResult, c.WantReason)
			}
		}
	}
	if c.WantDeny != "" {
		var got []string
		for _, e := range after.deny[before.denyCount:] {
			got = append(got, e.Reason)
		}
		if !contains(got, c.WantDeny) {
			t.Errorf("new deny events carry reasons %v, want one with %q", got, c.WantDeny)
		}
	}
	if c.WantAudit != "" {
		var got []string
		for _, r := range after.audit[before.auditCount:] {
			got = append(got, r.Action)
		}
		if len(got) != 1 || got[0] != c.WantAudit {
			t.Errorf("new admin audit rows = %v, want exactly [%s]", got, c.WantAudit)
		}
	}
	if c.WantLog != "" && !strings.Contains(after.logs[before.logLen:], c.WantLog) {
		t.Errorf("the logs written during the case do not contain %q", c.WantLog)
	}
	s.AssertNoLeak(t, LeakCheck{
		Responses:     obs.Responses,
		Replies:       obs.Replies,
		AllowSwapUpTo: before.hits + c.WantUpstreamHits,
	})
}

type snap struct {
	hits            int
	identity        float64
	bundleRejected  float64
	tokenEvents     []TokenEvent
	tokenEventCount int
	deny            []denyEvent
	denyCount       int
	audit           []AuditRow
	auditCount      int
	logs            string
	logLen          int
}

type denyEvent struct{ Reason string }

// snapshot reads every assertion source a case may name. It reads only the
// sources the case uses, so a case that asserts nothing on a source does not
// pay for it.
func (s *Stack) snapshot(t testing.TB, w *Worker, c Case) snap {
	t.Helper()
	s.WaitIdle(t)
	sn := snap{hits: s.Upstream.Hits(), logs: s.logs.String()}
	sn.logLen = len(sn.logs)
	labels := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range m {
			if v != "" {
				out[k] = v
			}
		}
		return out
	}
	if c.Path == PathWorker && (c.WantResult != "" || c.WantReason != "") {
		sn.identity = s.Metric(t, w, "warden_identity_verify_total", labels(map[string]string{"result": c.WantResult, "reason": c.WantReason}))
	}
	if c.Path == PathBundle && c.WantReason != "" {
		sn.bundleRejected = s.Metric(t, w, "warden_bundle_rejected_total", labels(map[string]string{"reason": c.WantReason}))
	}
	if c.Path == PathToken && (c.WantResult != "" || c.WantReason != "") {
		sn.tokenEvents = s.TokenEvents(t)
		sn.tokenEventCount = len(sn.tokenEvents)
	}
	if c.WantDeny != "" {
		for _, e := range s.DenyEvents(t, w) {
			sn.deny = append(sn.deny, denyEvent{Reason: e.Reason})
		}
		sn.denyCount = len(sn.deny)
	}
	if c.WantAudit != "" {
		sn.audit = s.AuditRows(t, "")
		sn.auditCount = len(sn.audit)
	}
	return sn
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// validateCase checks that a case's Covers claims are backed by its assertions,
// so a case cannot claim a reason it does not check: every case pins a status,
// and each identity, token or bundle reason it covers must be the WantReason of
// a case on the matching path.
func validateCase(c Case) []string {
	var bad []string
	if c.WantStatus == 0 {
		bad = append(bad, "WantStatus is not set")
	}
	prefixes := map[string]Path{"identity.reason:": PathWorker, "token.reason:": PathToken, "bundle.reason:": PathBundle}
	for _, cov := range c.Covers {
		for prefix, path := range prefixes {
			reason, ok := strings.CutPrefix(cov, prefix)
			if !ok {
				continue
			}
			if c.Path != path {
				bad = append(bad, "covers "+cov+" but Path is "+string(c.Path)+", want "+string(path))
			} else if c.WantReason != reason {
				bad = append(bad, "covers "+cov+" but WantReason is "+strconv.Quote(c.WantReason))
			}
		}
	}
	return bad
}

// Run1 runs one case built inline: base carries the expectations, name and
// attack complete it. It is for a test that mixes an inline assertion with a
// case and needs the same checks and leak invariant, without a package-level
// case that the enum-completeness test would also see.
func (s *Stack) Run1(t *testing.T, base Case, name string, attack func(t testing.TB, s *Stack) Observed) {
	t.Helper()
	base.Name, base.Attack, base.Covers = name, attack, nil
	t.Run(name, func(t *testing.T) { s.runCase(t, base) })
}
