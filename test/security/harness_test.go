package security

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/tokensvc"
	"github.com/ethosagent/warden/test/fakes"
)

// recordingTB records failures instead of failing the test, so the harness's
// own tests can prove that a wrong expectation, a leak or a vacuous case makes
// the assertions fail. Fatalf records and returns: only code paths that use
// Errorf are run through it.
type recordingTB struct {
	testing.TB
	msgs []string
}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}
func (r *recordingTB) Fatalf(format string, args ...any) { r.Errorf(format, args...) }
func (r *recordingTB) Failed() bool                      { return len(r.msgs) > 0 }
func (r *recordingTB) text() string                      { return strings.Join(r.msgs, "\n") }

// workerVerifiesWardenTokens says what credential the controls present: the
// exchanged Warden token, which a bundle-pinned worker verifies since
// W-P2-WBND-01 (#111). Set it false to present the user's OIDC ID token
// instead (attribution only).
var workerVerifiesWardenTokens = true

// agentSetup registers agent id with a fresh key and the group eng.
func agentSetup(t *testing.T, s *Stack, id string) *Agent {
	t.Helper()
	return s.RegisterAgent(t, id, fakes.NewAgentKey(t, id+"-key-1"), "eng")
}

// credentialFor is what the control presents to worker w for user sub.
func credentialFor(t *testing.T, s *Stack, a *Agent, sub string) (credential, wardenToken string) {
	t.Helper()
	wardenToken = s.MintWardenToken(t, a, sub, "eng")
	if workerVerifiesWardenTokens {
		return wardenToken, wardenToken
	}
	return s.UserToken(sub, []string{"eng"}), wardenToken
}

type wardenClaims struct {
	Sub string `json:"sub"`
	Iss string `json:"iss"`
	Aud any    `json:"aud"`
	Act struct {
		Sub string `json:"sub"`
	} `json:"act"`
	Cnf struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
	Exp int64 `json:"exp"`
	Iat int64 `json:"iat"`
}

func decodeClaims(t testing.TB, tok string) wardenClaims {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("a Warden token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode the Warden token payload: %v", err)
	}
	var c wardenClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse the Warden token payload: %v", err)
	}
	return c
}

// TestHarness_ValidFlow is the positive control the whole suite stands on: an
// admin registers agent-a, a user exchanges a fakes.OIDCIssuer ID token at
// POST /oauth2/token for a Warden token bound to the agent's key, and the
// credential is accepted on all three transports, each reaching the upstream
// exactly once with the swapped secret and without any identity header.
func TestHarness_ValidFlow(t *testing.T) {
	s := StartStack(t, StackOptions{})
	a := agentSetup(t, s, "agent-a")
	w := s.Worker("agent-a")

	cred, warden := credentialFor(t, s, a, "user-1")
	c := decodeClaims(t, warden)
	if c.Sub != "user-1" || c.Act.Sub != "agent-a" || c.Cnf.JKT != a.Key.Thumbprint() || c.Exp <= c.Iat {
		t.Fatalf("the exchanged Warden token claims: sub %q act.sub %q cnf.jkt matches the agent key %t exp>iat %t",
			c.Sub, c.Act.Sub, c.Cnf.JKT == a.Key.Thumbprint(), c.Exp > c.Iat)
	}
	if seq := s.Metric(t, w, "warden_bundle_seq", nil); seq <= 0 {
		t.Fatalf("warden_bundle_seq = %v, want above 0 (a signed bundle is applied)", seq)
	}

	verifyValid := func() float64 {
		return s.Metric(t, w, "warden_identity_verify_total", map[string]string{"result": "valid"})
	}
	validBefore := verifyValid()
	wantVerifies := 0.0
	for _, tr := range Transports {
		hits := s.Upstream.Hits()
		resp := s.Do(t, w, Via(tr, cred))
		if resp.Status != http.StatusOK {
			t.Fatalf("%s: status %d, want 200 (CONNECT %d, body %s)", tr, resp.Status, resp.ConnectStatus, tail(resp.Body, 300))
		}
		if got := s.Upstream.Hits() - hits; got != 1 {
			t.Fatalf("%s: %d upstream hits, want exactly 1", tr, got)
		}
		req := s.Upstream.Requests()[hits]
		if got := req.Header.Get("Authorization"); got != "Bearer "+SwappedSecret {
			t.Errorf("%s: the upstream saw an Authorization header that is not the swapped secret", tr)
		}
		// One verification per credential the worker reads: the CONNECT token
		// always, and the X-Warden-Identity header of the terminated transport.
		wantVerifies++
		if tr == TransportTerminated {
			wantVerifies++
		}
	}
	if got := verifyValid() - validBefore; got != wantVerifies {
		t.Errorf(`warden_identity_verify_total{result="valid"} rose by %v, want %v (one per credential read)`, got, wantVerifies)
	}
	s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
}

// TestHarness_Budget pins how long a stack takes to be ready under -race.
func TestHarness_Budget(t *testing.T) {
	start := time.Now()
	s := StartStack(t, StackOptions{})
	took := time.Since(start)
	if took > 10*time.Second {
		t.Errorf("the stack took %s to be ready, want under 10s", took.Round(time.Millisecond))
	}
	for _, w := range s.Workers {
		if seq := s.Metric(t, w, "warden_bundle_seq", nil); seq <= 0 {
			t.Errorf("%s: warden_bundle_seq = %v at ready", w.Name, seq)
		}
	}
}

// TestHarness_Topology pins what StartStack promises: two workers bound to
// agent-a and agent-b, each with its own enrolled certificate that the control
// plane's strict-certs mode accepts, and a worker without a certificate refused.
func TestHarness_Topology(t *testing.T) {
	s := StartStack(t, StackOptions{})
	if len(s.Workers) != 2 || s.Workers[0].AgentID != "agent-a" || s.Workers[1].AgentID != "agent-b" {
		t.Fatalf("workers = %+v, want agent-a and agent-b", s.Workers)
	}
	if s.Workers[0].TokenEnv == s.Workers[1].TokenEnv {
		t.Error("two workers share one enrollment token env var")
	}
	for _, w := range s.Workers {
		if r := s.FetchBundle(t, w); r.Status != http.StatusOK || r.Header.Get("Content-Type") == "" {
			t.Errorf("%s: GET /policy with its certificate = %d, want 200", w.Name, r.Status)
		}
	}
	if r := s.Send(t, s.CPClient(t, nil), http.MethodGet, "/policy", nil, nil); r.Status != http.StatusUnauthorized {
		t.Errorf("GET /policy without a certificate = %d, want 401", r.Status)
	}
	if rows := s.AuditRows(t, "worker.enroll"); len(rows) == 0 && len(s.AuditRows(t, "")) == 0 {
		t.Error("the admin audit table is empty: admin audit is not on")
	}
}

// TestHarness_Matrix runs the matrix runner end to end: positive controls
// first, then the smoke cases the harness itself owns. Later tickets register
// their cases next to these.
func TestHarness_Matrix(t *testing.T) {
	s := StartStack(t, StackOptions{})
	a := agentSetup(t, s, "agent-a")

	s.PositiveControl(t, "worker", func(t *testing.T) {
		cred, _ := credentialFor(t, s, a, "user-1")
		for _, tr := range Transports {
			if r := s.Do(t, s.Worker("agent-a"), Via(tr, cred)); r.Status != http.StatusOK {
				t.Fatalf("%s: status %d, want 200", tr, r.Status)
			}
		}
	})
	s.PositiveControl(t, "token", func(t *testing.T) {
		if r, tok := s.Exchange(t, a, s.UserToken("user-1", []string{"eng"}), nil); tok == "" {
			t.Fatalf("exchange = %d %s, want a token", r.Status, r.Body)
		}
	})
	s.PositiveControl(t, "cp-route", func(t *testing.T) {
		if r := s.FetchBundle(t, s.Worker("agent-a")); r.Status != http.StatusOK {
			t.Fatalf("GET /policy with the worker certificate = %d, want 200", r.Status)
		}
	})
	for _, cat := range []string{"worker", "token", "cp-route"} {
		if !s.ControlPassed(cat) {
			t.Fatalf("the %s positive control did not pass", cat)
		}
	}
	Run(t, s, "worker", smokeWorker)
	Run(t, s, "token", smokeToken)
	Run(t, s, "cp-route", smokeRoute)
}

var smokeWorker = []Case{{
	Name: "no credential on CONNECT is challenged",
	Path: PathWorker,
	Attack: func(t testing.TB, s *Stack) Observed {
		return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, "")))
	},
	WantStatus:       http.StatusProxyAuthRequired,
	WantHeader:       map[string]string{"Proxy-Authenticate": `Basic realm="warden"`},
	WantBody:         "identity_required",
	WantDeny:         "identity_required",
	WantUpstreamHits: 0,
}, {
	Name: "a CONNECT token that is not a JWT is challenged and counted as invalid",
	Path: PathWorker,
	Attack: func(t testing.TB, s *Stack) Observed {
		return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, "not-a-jwt")))
	},
	WantStatus:       http.StatusProxyAuthRequired,
	WantBody:         "identity_required",
	WantResult:       "invalid",
	WantReason:       "malformed",
	WantDeny:         "identity_required",
	WantUpstreamHits: 0,
}}

var smokeToken = []Case{{
	Name: "a subject token signed with alg none is refused and recorded",
	Path: PathToken,
	Attack: func(t testing.TB, s *Stack) Observed {
		return SeenReply(s.exchangeAs(t, "agent-a", s.UserToken("user-1", []string{"eng"}, fakes.WithAlg("none"))))
	},
	WantStatus: http.StatusBadRequest,
	WantBody:   "invalid_grant",
	WantResult: "denied",
	WantReason: "subject_invalid",
}}

var smokeRoute = []Case{{
	Name: "no client certificate on /policy is refused",
	Path: PathCPRoute,
	Attack: func(t testing.TB, s *Stack) Observed {
		return SeenReply(s.Send(t, s.CPClient(t, nil), http.MethodGet, "/policy", nil, nil))
	},
	WantStatus: http.StatusUnauthorized,
}}

// TestHarness_RunnerIsNotVacuous proves the runner fails on what it must: a
// wrong status, an unexpected upstream hit, a missing assertion source and a
// planted leak. Without this, a runner that asserts nothing would pass every
// attack case.
func TestHarness_RunnerIsNotVacuous(t *testing.T) {
	s := StartStack(t, StackOptions{})
	agentSetup(t, s, "agent-a")
	s.PositiveControl(t, "x", func(*testing.T) {})
	deny := func(tb testing.TB, s *Stack) Observed {
		return Seen(s.Do(tb, s.Worker("agent-a"), Via(TransportConnect, "")))
	}
	reached := func(tb testing.TB, s *Stack) Observed {
		cred := s.UserToken("user-1", []string{"eng"})
		return Seen(s.Do(tb, s.Worker("agent-a"), Via(TransportConnect, cred)))
	}
	for _, c := range []struct {
		name string
		c    Case
		want string
	}{
		{"wrong status", Case{Name: "x", Path: PathWorker, Attack: deny, WantStatus: http.StatusOK}, "status = 407, want 200"},
		{"wrong body", Case{Name: "x", Path: PathWorker, Attack: deny, WantStatus: http.StatusProxyAuthRequired, WantBody: "nope"}, "body does not contain"},
		{"missing header", Case{Name: "x", Path: PathWorker, Attack: deny, WantStatus: http.StatusProxyAuthRequired, WantHeader: map[string]string{"X-Nope": "*"}}, "header X-Nope"},
		{"upstream reached", Case{Name: "x", Path: PathWorker, Attack: reached, WantStatus: http.StatusOK}, "upstream hits = 1, want 0"},
		{"metric did not move", Case{Name: "x", Path: PathWorker, Attack: deny, WantStatus: http.StatusProxyAuthRequired, WantResult: "invalid", WantReason: "bad_signature"}, "rose by 0, want 1"},
		{"deny event missing", Case{Name: "x", Path: PathWorker, Attack: deny, WantStatus: http.StatusProxyAuthRequired, WantDeny: "policy_no_match"}, "new deny events carry"},
		{"audit row missing", Case{Name: "x", Path: PathWorker, Attack: deny, WantStatus: http.StatusProxyAuthRequired, WantAudit: "agent.create"}, "new admin audit rows"},
		{"log missing", Case{Name: "x", Path: PathWorker, Attack: deny, WantStatus: http.StatusProxyAuthRequired, WantLog: "no such log line"}, "do not contain"},
		{"claims a reason it does not check", Case{Name: "x", Path: PathWorker, Attack: deny, WantStatus: http.StatusProxyAuthRequired, Covers: []string{CoverIdentity("bad_signature")}}, "covers identity.reason:bad_signature but WantReason"},
		{"claims a reason on the wrong path", Case{Name: "x", Path: PathCPRoute, Attack: deny, WantStatus: http.StatusProxyAuthRequired, WantReason: "bad_signature", Covers: []string{CoverIdentity("bad_signature")}}, "but Path is cp-route"},
		{"no status pinned", Case{Name: "x", Path: PathWorker, Attack: deny}, "WantStatus is not set"},
		{"token row missing", Case{Name: "x", Path: PathToken, Attack: func(tb testing.TB, s *Stack) Observed { return Observed{Status: 400} }, WantStatus: 400, WantResult: "denied", WantReason: "replay"}, "new token_events rows"},
	} {
		rec := &recordingTB{TB: t}
		s.RunCase(rec, c.c)
		if !rec.Failed() || !strings.Contains(rec.text(), c.want) {
			t.Errorf("%s: RunCase passed or failed for another reason; want a failure containing %q, got %q", c.name, c.want, rec.text())
		}
	}
	// And the same attack with the right expectations passes cleanly.
	rec := &recordingTB{TB: t}
	s.RunCase(rec, smokeWorker[0])
	if rec.Failed() {
		t.Errorf("the smoke case failed: %s", rec.text())
	}
	if s.ControlPassed("never-run") {
		t.Error("ControlPassed is true for a category whose control never ran")
	}
}

// TestNoLeakGuard proves AssertNoLeak fails when a planted secret appears on
// any surface it guards, and that its message names the kind and the surface
// without printing the value.
func TestNoLeakGuard(t *testing.T) {
	s := StartStack(t, StackOptions{})
	const canary = "canary-token-0123456789abcdef"
	s.Track("planted token", canary)

	rec := &recordingTB{TB: t}
	s.AssertNoLeak(rec, LeakCheck{})
	if rec.Failed() {
		t.Fatalf("a clean stack failed the invariant: %s", rec.text())
	}

	check := func(name, wantSurface string, lc LeakCheck) {
		t.Helper()
		rec := &recordingTB{TB: t}
		s.AssertNoLeak(rec, lc)
		if !rec.Failed() || !strings.Contains(rec.text(), "planted token") || !strings.Contains(rec.text(), wantSurface) {
			t.Errorf("%s: AssertNoLeak = %q, want a failure naming a planted token in %q", name, rec.text(), wantSurface)
		}
		if strings.Contains(rec.text(), canary) {
			t.Errorf("%s: the failure message prints the secret", name)
		}
	}
	check("agent response", "agent response", LeakCheck{Responses: []Response{{Status: 200, Body: "echo " + canary}}})
	check("attacker reply", "attacker reply", LeakCheck{Replies: []Reply{{Status: 200, Header: http.Header{"X-Echo": {canary}}}}})

	// A key PEM in a JSON log line: the newlines are escaped, so only the
	// per-line and body tracking can find it.
	pem := "-----BEGIN TEST KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5\nYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw\n-----END TEST KEY-----\n"
	s.Track("planted key PEM", pem)
	line, err := json.Marshal(map[string]string{"msg": "oops", "key": pem})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(s.logs, "%s\n", line)
	rec2 := &recordingTB{TB: t}
	s.AssertNoLeak(rec2, LeakCheck{})
	if !strings.Contains(rec2.text(), "planted key PEM") || !strings.Contains(rec2.text(), "logs") {
		t.Errorf("a key PEM in a JSON log line was not found: %q", rec2.text())
	}

	// A planted log line is the acceptance criterion's case.
	fmt.Fprintf(s.logs, `{"level":"INFO","msg":"oops","token":%q}`+"\n", canary)
	check("log line", "logs", LeakCheck{})
}

// TestNoLeakGuard_Upstream covers the upstream-side rules: a tracked token in
// an upstream request, a proxy-only header at the upstream, and the swapped
// secret outside an allowed case.
func TestNoLeakGuard_Upstream(t *testing.T) {
	s := StartStack(t, StackOptions{})
	cl := s.UpstreamClient(t)
	send := func(hdr http.Header) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+s.Upstream.Addr()+"/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = hdr
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("direct upstream request: %v", err)
		}
		_ = resp.Body.Close()
	}
	assertFails := func(name, want string, lc LeakCheck) {
		t.Helper()
		rec := &recordingTB{TB: t}
		s.AssertNoLeak(rec, lc)
		if !rec.Failed() || !strings.Contains(rec.text(), want) {
			t.Errorf("%s: AssertNoLeak = %q, want a failure containing %q", name, rec.text(), want)
		}
	}

	s.Track("planted token", "canary-token-fedcba9876543210")
	send(http.Header{"X-Echo": {"canary-token-fedcba9876543210"}})
	assertFails("token at the upstream", "upstream request 0", LeakCheck{AllowSwapUpTo: 1})

	s2 := StartStack(t, StackOptions{})
	send2 := func(hdr http.Header) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+s2.Upstream.Addr()+"/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = hdr
		resp, err := s2.UpstreamClient(t).Do(req)
		if err != nil {
			t.Fatalf("direct upstream request: %v", err)
		}
		_ = resp.Body.Close()
	}
	send2(http.Header{"Authorization": {"Bearer " + SwappedSecret}})
	rec := &recordingTB{TB: t}
	s2.AssertNoLeak(rec, LeakCheck{AllowSwapUpTo: 1})
	if rec.Failed() {
		t.Errorf("the swapped secret in an allowed request failed the invariant: %s", rec.text())
	}
	rec = &recordingTB{TB: t}
	s2.AssertNoLeak(rec, LeakCheck{AllowSwapUpTo: 0})
	if !rec.Failed() || !strings.Contains(rec.text(), "swapped secret") {
		t.Errorf("the swapped secret in a request of a denied case passed: %q", rec.text())
	}
	send2(http.Header{"Proxy-Authorization": {"Basic abc"}})
	rec = &recordingTB{TB: t}
	s2.AssertNoLeak(rec, LeakCheck{AllowSwapUpTo: 2})
	if !rec.Failed() || !strings.Contains(rec.text(), "Proxy-Authorization reached the upstream") {
		t.Errorf("Proxy-Authorization at the upstream passed: %q", rec.text())
	}
}

// ---- enum completeness ----

// bundleReasons reads the bundle package's rejection reasons from its source,
// so a reason added there without a test breaks the build. They are the string
// literals of the reasonError values in internal/bundle/errors.go, plus the
// worker-side invalid_policy rejection.
func bundleReasons(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../../internal/bundle/errors.go", nil, 0)
	if err != nil {
		t.Fatalf("parse internal/bundle/errors.go: %v", err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || len(cl.Elts) != 2 {
			return true
		}
		id, ok := cl.Type.(*ast.Ident)
		if !ok || id.Name != "reasonError" {
			return true
		}
		if lit, ok := cl.Elts[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil {
				out = append(out, v)
			}
		}
		return true
	})
	return append(out, config.BundleReasonInvalidPolicy)
}

// workerFacingRoutes are the control plane routes workers and agents call.
var workerFacingRoutes = []string{
	"/policy", "/control/heartbeat", "/central/ingest", "/control/enroll", "/control/renew", "/oauth2/token",
}

func allEnumItems(t *testing.T) []string {
	t.Helper()
	var items []string
	for _, r := range identity.Reasons() {
		items = append(items, CoverIdentity(string(r)))
	}
	br := bundleReasons(t)
	if len(br) < 13 {
		t.Fatalf("found only %d bundle reasons in internal/bundle/errors.go: the parse no longer matches the source", len(br))
	}
	for _, r := range br {
		items = append(items, CoverBundle(r))
	}
	for _, r := range tokensvc.AllReasons() {
		items = append(items, CoverToken(string(r)))
	}
	for _, r := range workerFacingRoutes {
		items = append(items, CoverRoute(r))
	}
	return items
}

var ticketRe = regexp.MustCompile(`^W-P2-SECT-0[2-7]$`)

// TestEnumCompleteness fails when any identity.Reason, bundle.Reason,
// token-service denial reason or worker-facing CP route has neither a
// registered case nor a pending.go entry, when pending.go names something that
// does not exist or that a case now covers, and when a worker-facing route
// is not mounted.
func TestEnumCompleteness(t *testing.T) {
	all := allEnumItems(t)
	exists := map[string]bool{}
	for _, it := range all {
		exists[it] = true
	}
	covered := map[string]bool{}
	for _, c := range allCases() {
		for _, it := range c.Covers {
			if !exists[it] {
				t.Errorf("case %q covers %q, which is not an enum value or worker-facing route", c.Name, it)
			}
			covered[it] = true
		}
	}
	pend := map[string]string{}
	for _, p := range pending {
		switch {
		case !exists[p.Item]:
			t.Errorf("pending.go lists %q, which does not exist (remove the entry)", p.Item)
		case covered[p.Item]:
			t.Errorf("pending.go still lists %q, which a registered case covers (remove the entry)", p.Item)
		case !ticketRe.MatchString(p.Ticket):
			t.Errorf("pending.go entry %q names ticket %q, want W-P2-SECT-02..07", p.Item, p.Ticket)
		case pend[p.Item] != "":
			t.Errorf("pending.go lists %q twice", p.Item)
		}
		pend[p.Item] = p.Ticket
	}
	for _, it := range all {
		if !covered[it] && pend[it] == "" {
			t.Errorf("%s has no case and no pending.go entry: add a case that covers it, or a pending entry naming the ticket that will", it)
		}
	}
}

// TestWorkerFacingRoutesAreMounted pins the route list: each is mounted (a
// request without credentials is refused, never 404).
func TestWorkerFacingRoutesAreMounted(t *testing.T) {
	s := StartStack(t, StackOptions{})
	cl := s.CPClient(t, nil)
	for _, route := range workerFacingRoutes {
		mounted := false
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			if s.Send(t, cl, m, route, nil, nil).Status != http.StatusNotFound {
				mounted = true
			}
		}
		if !mounted {
			t.Errorf("%s answers 404 to GET and POST: the route list in TestEnumCompleteness is stale", route)
		}
	}
}

// TestCanary proves the stage gates the build: with WARDEN_SECURITY_CANARY=1 it
// fails, so "WARDEN_SECURITY_CANARY=1 scripts/check.sh" must exit non-zero with
// a FAIL for this package. Without the variable it does nothing.
func TestCanary(t *testing.T) {
	if os.Getenv("WARDEN_SECURITY_CANARY") == "1" {
		t.Fatal("WARDEN_SECURITY_CANARY=1: this failure is the point; it proves test/security gates scripts/check.sh")
	}
}
