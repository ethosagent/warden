package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"
)

const (
	bgUser     = "ops-admin"
	bgPassword = "correct horse battery staple"
	bgWrongPW  = "definitely-the-wrong-password"
)

var (
	bgHashOnce sync.Once
	bgHashVal  string
)

// bgHash is the argon2id hash of bgPassword, computed once for the package.
func bgHash(t *testing.T) string {
	t.Helper()
	bgHashOnce.Do(func() {
		h, err := HashPassword(bgPassword, rand.Reader)
		if err != nil {
			panic(err)
		}
		bgHashVal = h
	})
	return bgHashVal
}

// fakePublisher records every Finding.
type fakePublisher struct {
	mu sync.Mutex
	fs []integration.Finding
}

func (p *fakePublisher) PublishFinding(f integration.Finding) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fs = append(p.fs, f)
}

func (p *fakePublisher) all() []integration.Finding {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]integration.Finding(nil), p.fs...)
}

type bgRig struct {
	srv   *Server
	h     http.Handler
	clk   *clocktest.Fake
	pub   *fakePublisher
	rec   *fakeRecorder // nil with audit off
	logs  *syncBuf
	calls atomic.Int64 // argon2 verifications
	hash  string       // the hash file's path
}

type bgOpts struct {
	disabled bool
	noAudit  bool
	noPub    bool
}

func newBGRig(t *testing.T, o bgOpts) *bgRig {
	t.Helper()
	r := &bgRig{clk: clocktest.NewFake(time.Unix(1_800_000_000, 0)), pub: &fakePublisher{}, logs: &syncBuf{}}
	r.hash = filepath.Join(t.TempDir(), "hash")
	if err := os.WriteFile(r.hash, []byte(bgHash(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cc := config.ConsoleConfig{
		Auth:    config.ConsoleAuthOIDC,
		OIDC:    config.ConsoleOIDC{RedirectURL: testRedirectHTTPS},
		Roles:   testConsoleRoles,
		Session: config.ConsoleSession{Idle: 30 * time.Minute, Absolute: 12 * time.Hour},
	}
	if !o.disabled {
		cc.BreakGlass = config.ConsoleBreakGlass{
			Enabled: true, Username: bgUser, PasswordHashFile: r.hash, SessionTTL: time.Hour,
		}
	}
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: openSessionDB(t),
		Console: cc, Clock: r.clk, Now: r.clk.Now,
		Logger: slog.New(slog.NewTextHandler(r.logs, nil)),
	})
	if !o.noPub {
		srv.findings = r.pub
	}
	if !o.noAudit {
		r.rec = &fakeRecorder{}
		srv.enableAdminAudit(r.rec, r.rec.probe, fakeMAC)
	}
	if srv.breakGlass != nil {
		srv.breakGlass.verify = func(p PHC, pw string) bool {
			r.calls.Add(1)
			return p.Verify(pw)
		}
	}
	r.srv, r.h = srv, srv.Handler()
	return r
}

// post sends a break-glass login from addr.
func (r *bgRig) post(addr, user, password string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": user, "password": password})
	return r.send(addr, http.MethodPost, "application/json", string(body), nil)
}

func (r *bgRig) send(addr, method, ctype, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://cp.example/auth/breakglass", strings.NewReader(body))
	req.RemoteAddr = addr + ":4242"
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

func (r *bgRig) cookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == r.srv.sessionCookie.Name {
			return c
		}
	}
	return nil
}

func (r *bgRig) me(raw string) *httptest.ResponseRecorder {
	return authReq(r.h, r.srv, http.MethodGet, "/auth/me", raw, "")
}

func errBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	s, _ := m["error"].(string)
	return s
}

func countLogs(logs, msg string) int {
	return strings.Count(logs, "msg="+msg)
}

func TestBreakGlass_DisabledReturns404(t *testing.T) {
	r := newBGRig(t, bgOpts{disabled: true})
	rec := r.post("192.0.2.1", bgUser, bgPassword)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled: %d, want 404", rec.Code)
	}
	if len(r.rec.inputs()) != 0 || len(r.pub.all()) != 0 {
		t.Fatal("a disabled break-glass route wrote an audit row or a Finding")
	}
}

func TestBreakGlass_NotMountedWithoutOIDC(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: openSessionDB(t),
		Console: config.ConsoleConfig{BreakGlass: config.ConsoleBreakGlass{Enabled: true, Username: bgUser}}})
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("auth none: %d, want 404", rec.Code)
	}
}

func TestBreakGlass_Success(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	rec := r.post("192.0.2.1", bgUser, bgPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	ck := r.cookie(rec)
	if ck == nil || !ck.Secure || !ck.HttpOnly {
		t.Fatalf("cookie = %+v, want a Secure HttpOnly console cookie", ck)
	}
	var resp struct {
		OK        bool   `json:"ok"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.OK {
		t.Fatalf("body = %s (%v)", rec.Body.String(), err)
	}
	if want := r.clk.Now().Add(time.Hour).UTC().Format(time.RFC3339); resp.ExpiresAt != want {
		t.Errorf("expiresAt = %q, want %q", resp.ExpiresAt, want)
	}
	if strings.Contains(rec.Body.String(), ck.Value) {
		t.Error("response body leaks the session id")
	}

	sess, live, err := r.srv.sessions.Lookup(context.Background(), ck.Value)
	if err != nil || !live {
		t.Fatalf("session lookup: live=%v err=%v", live, err)
	}
	if sess.AuthMethod != "breakglass" || sess.Sub != "breakglass:"+bgUser {
		t.Fatalf("session = %+v", sess)
	}
	me := r.me(ck.Value)
	var got map[string]string
	_ = json.Unmarshal(me.Body.Bytes(), &got)
	if me.Code != http.StatusOK || got["role"] != "admin" || got["authMethod"] != "breakglass" {
		t.Fatalf("/auth/me = %d %v, want admin via breakglass", me.Code, got)
	}
	// An admin-only route is open to it.
	if rec := authReq(r.h, r.srv, http.MethodGet, "/dashboard/api/sessions", ck.Value, ""); rec.Code != http.StatusOK {
		t.Errorf("GET /dashboard/api/sessions as break-glass admin: %d", rec.Code)
	}

	// Activity never extends the absolute expiry.
	r.clk.Advance(30 * time.Minute)
	r.srv.sessions.now = r.clk.Now
	if r.me(ck.Value).Code != http.StatusOK {
		t.Fatal("session dead at +30m")
	}
	r.clk.Advance(31 * time.Minute) // now+1h01m
	if code := r.me(ck.Value).Code; code != http.StatusUnauthorized {
		t.Fatalf("session at +1h01m: %d, want 401", code)
	}

	fs := r.pub.all()
	if len(fs) != 1 || fs[0].Severity != integration.SevCritical || fs[0].RuleID != "breakglass_login" ||
		fs[0].DedupKey != "breakglass_login:success:"+shortHash(sess.IDHash) {
		t.Fatalf("findings = %+v, want one critical success", fs)
	}
	rows := r.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %+v, want 1", rows)
	}
	row := rows[0]
	if row.Action != "auth.breakglass" || row.Outcome != adminaudit.OutcomeOK || row.AuthMethod != adminaudit.AuthMethodBreakglass ||
		row.Actor.Sub != "breakglass:"+bgUser || row.ClientIP != "192.0.2.1" || row.TargetRef != shortHash(sess.IDHash) {
		t.Fatalf("row = %+v", row)
	}
}

func TestBreakGlass_SecondLoginRevokesFirst(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	first := r.cookie(r.post("192.0.2.1", bgUser, bgPassword))
	second := r.cookie(r.post("192.0.2.1", bgUser, bgPassword))
	if first == nil || second == nil || first.Value == second.Value {
		t.Fatal("want two distinct sessions")
	}
	if code := r.me(first.Value).Code; code != http.StatusUnauthorized {
		t.Errorf("first session after second login: %d, want 401", code)
	}
	if code := r.me(second.Value).Code; code != http.StatusOK {
		t.Errorf("second session: %d, want 200", code)
	}
}

func TestBreakGlass_RateLimit(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	for i := 0; i < 5; i++ {
		if rec := r.post("192.0.2.1", bgUser, bgWrongPW); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, rec.Code)
		}
	}
	before := r.calls.Load()
	rec := r.post("192.0.2.1", bgUser, bgPassword) // correct credentials, 6th attempt
	if rec.Code != http.StatusTooManyRequests || errBody(t, rec) != "rate_limited" {
		t.Fatalf("6th attempt: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	if r.cookie(rec) != nil {
		t.Error("a limited request got a session")
	}
	for i := 0; i < 3; i++ {
		r.post("192.0.2.1", bgUser, bgPassword)
	}
	if r.calls.Load() != before {
		t.Fatalf("argon2 ran %d times for limited requests", r.calls.Load()-before)
	}
	// 5 denied rows plus one rate_limited row, however many limited requests.
	var limited int
	for _, row := range r.rec.inputs() {
		if row.Details["reason"] == "rate_limited" {
			limited++
		}
	}
	if rows := r.rec.inputs(); len(rows) != 6 || limited != 1 {
		t.Fatalf("audit rows = %d (rate_limited %d), want 6 and 1", len(rows), limited)
	}

	// Another address is unaffected.
	if rec := r.post("192.0.2.2", bgUser, bgPassword); rec.Code != http.StatusOK {
		t.Fatalf("other address: %d, want 200", rec.Code)
	}

	// After the window the first address may try again, and a new window starts
	// for the rate-limited row.
	r.clk.Advance(15*time.Minute + time.Second)
	if rec := r.post("192.0.2.1", bgUser, bgPassword); rec.Code != http.StatusOK {
		t.Fatalf("after the window: %d, want 200", rec.Code)
	}
}

func TestBreakGlass_GlobalCeiling(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	for i := 0; i < 20; i++ {
		addr := "198.51.100." + string(rune('1'+i/5)) // 4 addresses x 5 failures
		if rec := r.post(addr, bgUser, bgWrongPW); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, rec.Code)
		}
	}
	before := r.calls.Load()
	rec := r.post("203.0.113.9", bgUser, bgPassword)
	if rec.Code != http.StatusTooManyRequests || errBody(t, rec) != "rate_limited" || r.calls.Load() != before {
		t.Fatalf("past the global ceiling: %d %s (argon2 calls +%d)", rec.Code, rec.Body.String(), r.calls.Load()-before)
	}
	r.clk.Advance(16 * time.Minute)
	if rec := r.post("203.0.113.9", bgUser, bgPassword); rec.Code != http.StatusOK {
		t.Fatalf("after the window: %d", rec.Code)
	}
}

func TestBreakGlass_BusyWhenVerifySlotsFull(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	for i := 0; i < breakGlassVerifySlots; i++ {
		r.srv.breakGlass.sem <- struct{}{}
	}
	before := r.calls.Load()
	rec := r.post("192.0.2.1", bgUser, bgPassword)
	if rec.Code != http.StatusTooManyRequests || errBody(t, rec) != "busy" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("busy: %d %s", rec.Code, rec.Body.String())
	}
	if r.calls.Load() != before || len(r.rec.inputs()) != 0 {
		t.Error("a busy refusal ran argon2 or wrote a row")
	}
}

func TestBreakGlass_NoEnumerationNoLeak(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	badUser := "no-such-operator-xyzzy"
	wrongPW := r.post("192.0.2.1", bgUser, bgWrongPW)
	before := r.calls.Load()
	wrongUser := r.post("192.0.2.2", badUser, bgPassword)
	if r.calls.Load()-before != 1 {
		t.Errorf("wrong username ran argon2 %d times, want 1", r.calls.Load()-before)
	}
	if r.calls.Load() != 2 {
		t.Errorf("total argon2 runs = %d, want 2", r.calls.Load())
	}
	for _, rec := range []*httptest.ResponseRecorder{wrongPW, wrongUser} {
		if rec.Code != http.StatusUnauthorized || errBody(t, rec) != "invalid_credentials" {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
	}
	if wrongPW.Body.String() != wrongUser.Body.String() {
		t.Error("the two 401 bodies differ")
	}
	rows := r.rec.inputs()
	if len(rows) != 2 || rows[0].Outcome != "denied" || rows[1].Outcome != "denied" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Actor.Sub != "breakglass:"+bgUser || rows[1].Actor.Sub != "breakglass:unknown" {
		t.Fatalf("actors = %q, %q", rows[0].Actor.Sub, rows[1].Actor.Sub)
	}
	dump, _ := json.Marshal([]any{rows, r.pub.all()})
	all := string(dump) + r.logs.String()
	for _, secret := range []string{badUser, bgPassword, bgWrongPW} {
		if strings.Contains(all, secret) {
			t.Errorf("logs, rows or findings contain %q", secret)
		}
	}
	// Logs carry the configured username nowhere either.
	if strings.Contains(r.logs.String(), bgUser) {
		t.Error("logs contain the configured username")
	}
	if n := countLogs(r.logs.String(), "breakglass_login"); n != 2 {
		t.Errorf("breakglass_login lines = %d, want 2", n)
	}
	for _, f := range r.pub.all() {
		if f.Severity != integration.SevHigh || f.DedupKey != "breakglass_login:failure" {
			t.Errorf("finding = %+v", f)
		}
	}
}

func TestBreakGlass_RequestChecks(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	good := `{"username":"` + bgUser + `","password":"` + bgPassword + `"}`
	tests := []struct {
		name   string
		method string
		ctype  string
		body   string
		hdr    map[string]string
		want   int
	}{
		{"method", http.MethodGet, "application/json", good, nil, http.StatusMethodNotAllowed},
		{"content type", http.MethodPost, "text/plain", good, nil, http.StatusUnsupportedMediaType},
		{"no content type", http.MethodPost, "", good, nil, http.StatusUnsupportedMediaType},
		{"foreign origin", http.MethodPost, "application/json", good, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"big body", http.MethodPost, "application/json", `{"username":"` + strings.Repeat("a", 5<<10) + `"}`, nil, http.StatusRequestEntityTooLarge},
		{"unknown field", http.MethodPost, "application/json", `{"username":"a","password":"b","extra":1}`, nil, http.StatusBadRequest},
		{"trailing data", http.MethodPost, "application/json", good + `{}`, nil, http.StatusBadRequest},
		{"not json", http.MethodPost, "application/json", `nope`, nil, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := r.send("192.0.2.1", tc.method, tc.ctype, tc.body, tc.hdr)
			if rec.Code != tc.want {
				t.Fatalf("%d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
	if tc := r.send("192.0.2.1", http.MethodGet, "application/json", good, nil); tc.Header().Get("Allow") != http.MethodPost {
		t.Errorf("Allow = %q", tc.Header().Get("Allow"))
	}
	if r.calls.Load() != 0 || len(r.rec.inputs()) != 0 {
		t.Fatalf("a rejected request ran argon2 (%d) or wrote rows", r.calls.Load())
	}
	// The matching Origin is accepted.
	rec := r.send("192.0.2.1", http.MethodPost, "application/json", good, map[string]string{"Origin": "https://cp.example"})
	if rec.Code != http.StatusOK {
		t.Fatalf("same-origin login: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBreakGlass_AuditFailureDeniesLogin(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	r.rec.set(errors.New("disk full"), nil)
	rec := r.post("192.0.2.1", bgUser, bgPassword)
	if rec.Code != http.StatusServiceUnavailable || errBody(t, rec) != "audit_unavailable" {
		t.Fatalf("audit down: %d %s", rec.Code, rec.Body.String())
	}
	if r.cookie(rec) != nil {
		t.Error("a cookie was set")
	}
	list, err := r.srv.sessions.List(context.Background())
	if err != nil || len(list) != 0 {
		t.Fatalf("sessions after a failed audit = %v (%v), want none", list, err)
	}
}

func TestBreakGlass_NoAuditStillLogsIn(t *testing.T) {
	r := newBGRig(t, bgOpts{noAudit: true})
	if rec := r.post("192.0.2.1", bgUser, bgPassword); rec.Code != http.StatusOK {
		t.Fatalf("audit off: %d", rec.Code)
	}
	if len(r.pub.all()) != 1 || countLogs(r.logs.String(), "breakglass_login") != 1 {
		t.Fatal("audit off must still log and publish")
	}
}

func TestBreakGlass_NoPipelineStillLoud(t *testing.T) {
	r := newBGRig(t, bgOpts{noPub: true})
	if r.srv.pipeline != nil {
		t.Fatal("test assumes no alert pipeline")
	}
	rec := r.post("192.0.2.1", bgUser, bgPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d", rec.Code)
	}
	if rows := r.rec.inputs(); len(rows) != 1 || rows[0].Outcome != adminaudit.OutcomeOK {
		t.Fatalf("rows = %+v", rows)
	}
	logs := r.logs.String()
	if n := countLogs(logs, "breakglass_login"); n != 1 {
		t.Errorf("breakglass_login lines = %d, want 1", n)
	}
	var ok bool
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "msg=breakglass_login") {
			ok = strings.Contains(line, "level=ERROR") && strings.Contains(line, "outcome=ok") && strings.Contains(line, "client_ip=192.0.2.1")
		}
	}
	if !ok {
		t.Errorf("breakglass_login line is not an ERROR with outcome and client_ip:\n%s", logs)
	}
	if !strings.Contains(logs, "msg=finding_not_published") || !strings.Contains(logs, "rule=breakglass_login") {
		t.Errorf("publishFinding did not log finding_not_published:\n%s", logs)
	}
}

func TestBreakGlass_HashReload(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	if err := os.Remove(r.hash); err != nil {
		t.Fatal(err)
	}
	rec := r.post("192.0.2.1", bgUser, bgPassword)
	if rec.Code != http.StatusServiceUnavailable || errBody(t, rec) != "breakglass_unavailable" {
		t.Fatalf("unreadable hash: %d %s", rec.Code, rec.Body.String())
	}
	if r.cookie(rec) != nil {
		t.Error("a cookie was set")
	}
	if list, _ := r.srv.sessions.List(context.Background()); len(list) != 0 {
		t.Fatal("a session exists after an unavailable hash")
	}
	if !strings.Contains(r.logs.String(), "level=ERROR") {
		t.Error("no ERROR log for the unreadable hash")
	}
	// Rotate: a new hash for a new password takes effect without a restart.
	newPW := "a brand new rotated passphrase"
	h, err := HashPassword(newPW, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.hash, []byte(h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := r.post("192.0.2.1", bgUser, bgPassword); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password after rotation: %d, want 401", rec.Code)
	}
	if rec := r.post("192.0.2.2", bgUser, newPW); rec.Code != http.StatusOK {
		t.Fatalf("new password after rotation: %d, want 200", rec.Code)
	}
}

// TestBreakGlass_SessionSweepKeepsLiveSession pins that the idle sweep never
// removes a break-glass session before its absolute expiry.
func TestBreakGlass_SessionSweepKeepsLiveSession(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	ck := r.cookie(r.post("192.0.2.1", bgUser, bgPassword))
	r.srv.sessions.now = r.clk.Now
	r.clk.Advance(45 * time.Minute) // past the 30m idle limit of other sessions
	if n, err := r.srv.sessions.SweepExpired(context.Background()); err != nil || n != 0 {
		t.Fatalf("sweep removed %d (%v)", n, err)
	}
	if r.me(ck.Value).Code != http.StatusOK {
		t.Fatal("break-glass session died of idleness")
	}
}

func TestBreakGlass_SessionStoreFailureIsAuditedAndRefused(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	if _, err := r.srv.cfg.State.SQL().Exec(`DROP TABLE sessions`); err != nil {
		t.Fatal(err)
	}
	rec := r.post("192.0.2.1", bgUser, bgPassword)
	if rec.Code != http.StatusServiceUnavailable || errBody(t, rec) != "session_unavailable" || r.cookie(rec) != nil {
		t.Fatalf("session store down: %d %s", rec.Code, rec.Body.String())
	}
	rows := r.rec.inputs()
	if len(rows) != 1 || rows[0].Outcome != adminaudit.OutcomeError || rows[0].Details["reason"] != "session_unavailable" {
		t.Fatalf("rows = %+v, want one error row", rows)
	}
}
