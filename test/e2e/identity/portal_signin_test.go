//go:build e2e

package identity

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/harness/compose"

	_ "modernc.org/sqlite" // reads the copied CP state DB (idp_links)
)

// Portal sign-in against the real reference stack (W-P3-CSIG-07): the CP runs
// consent.enabled with the warden-portal Dex client and the IdP link on
// (configs/config.e2e-identity-cp.yaml), and consent.store is aws against the
// stack's fake Secrets Manager (fake-aws, test/e2e/fakeaws). A seeded LDAP
// user signs in through /portal/login with the same cookie-jar browser the
// console SSO test uses (browserLogin in helpers_test.go).
//
// Nothing here prints a password, code, cookie, CSRF token, ID token or
// refresh token: every one of them is collected in a portalSecrets set that
// the last subtest sweeps the CP, worker and fake-aws logs for.

const (
	portalUser     = "alice"
	portalEmail    = "alice@example.org"
	portalClientID = "warden-portal"
	// portalCookie is the session cookie: __Host- because the redirectURL is https.
	portalCookie = "__Host-warden_portal"
	// fakeAWSService and its loopback control listener (test/e2e/fakeaws).
	fakeAWSService = "fake-aws"
	fakeAWSControl = "http://127.0.0.1:8082"
	// cpStateDB is the CP's state file under --state-dir /data.
	cpStateDB = "/data/warden-cp.db"
)

// portalSession is a signed-in portal user: the browser holding the
// __Host-warden_portal cookie plus what GET /portal/api/me reported.
type portalSession struct {
	client *http.Client
	trace  loginTrace
	cookie string // the raw session cookie value: secret
	csrf   string // secret

	Sub         string
	Email       string
	LinkStatus  string
	RelinkDueAt string
}

// portalSecrets collects every secret value a test handled, for the leak sweep.
type portalSecrets struct{ vals []string }

func (s *portalSecrets) add(v ...string) {
	for _, x := range v {
		if x != "" {
			s.vals = append(s.vals, x)
		}
	}
}

// sweep fails t when text holds any collected secret. It names only what and
// the index of the secret, never the value.
func (s *portalSecrets) sweep(t testing.TB, what, text string) {
	t.Helper()
	for i, v := range s.vals {
		if strings.Contains(text, v) {
			t.Errorf("%s contains collected secret #%d (a password, code, cookie, CSRF token, ID token or refresh token)", what, i)
		}
	}
}

// portalLogin signs user in to the portal through Dex and reads /portal/api/me.
func portalLogin(user string) (*portalSession, error) {
	b, err := newBrowser()
	if err != nil {
		return nil, err
	}
	tr, err := browserLogin(b, user, "/portal/login", "/portal")
	if err != nil {
		return nil, err
	}
	ps := &portalSession{client: b, trace: tr}
	cp, err := url.Parse(compose.CPBase)
	if err != nil {
		return nil, err
	}
	for _, c := range b.Jar.Cookies(cp) {
		if c.Name == portalCookie {
			ps.cookie = c.Value
		}
	}
	if ps.cookie == "" {
		return nil, fmt.Errorf("login as %q set no %s cookie", user, portalCookie)
	}
	code, body, err := ps.do(http.MethodGet, "/portal/api/me", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET /portal/api/me after login as %q: status %d, want 200", user, code)
	}
	var me struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		CSRF  string `json:"csrf"`
		Link  struct {
			Status      string `json:"status"`
			RelinkDueAt string `json:"relinkDueAt"`
		} `json:"link"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		return nil, fmt.Errorf("GET /portal/api/me: not JSON: %w", err)
	}
	if me.Sub == "" || me.CSRF == "" {
		return nil, fmt.Errorf("GET /portal/api/me after login as %q: no sub or csrf", user)
	}
	ps.Sub, ps.Email, ps.csrf = me.Sub, me.Email, me.CSRF
	ps.LinkStatus, ps.RelinkDueAt = me.Link.Status, me.Link.RelinkDueAt
	return ps, nil
}

// do sends one request to the CP with the portal cookie and extra headers.
func (ps *portalSession) do(method, path string, hdr map[string]string) (int, []byte, error) {
	req, err := http.NewRequest(method, compose.CPBase+path, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := ps.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, redactURLError(err))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

func (ps *portalSession) mustDo(t testing.TB, method, path string, hdr map[string]string) (int, []byte) {
	t.Helper()
	code, b, err := ps.do(method, path, hdr)
	if err != nil {
		t.Fatalf("identity: portal %s: %v", path, err)
	}
	return code, b
}

func portalLoginAs(t testing.TB, user string) *portalSession {
	t.Helper()
	ps, err := portalLogin(user)
	if err != nil {
		t.Fatalf("identity: portal login as %q: %v", user, err)
	}
	return ps
}

// errorCode decodes a CP {"error":"<code>"} body.
func errorCode(body []byte) string {
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &out)
	return out.Error
}

// storedSecret reads one secret from fake-aws's control listener inside its
// container. ok is false when the name is absent. The value is never logged.
func storedSecret(t testing.TB, name string) (string, bool) {
	t.Helper()
	cid := serviceContainer(t, fakeAWSService)
	res := compose.Run(".", compose.ComposeDeadline, "docker", "exec", cid,
		"wget", "-q", "-O", "-", fakeAWSControl+"/_secret?name="+url.QueryEscape(name))
	if res.Exit != 0 {
		return "", false
	}
	return res.Stdout, true
}

// storedNames lists the secret names fake-aws holds.
func storedNames(t testing.TB) []string {
	t.Helper()
	cid := serviceContainer(t, fakeAWSService)
	res := compose.Run(".", compose.ComposeDeadline, "docker", "exec", cid, "wget", "-q", "-O", "-", fakeAWSControl+"/_names")
	if res.Exit != 0 {
		t.Fatalf("identity: fake-aws /_names: exit %d: %s", res.Exit, firstLine(res.Stderr))
	}
	var names []string
	if err := json.Unmarshal([]byte(res.Stdout), &names); err != nil {
		t.Fatalf("identity: fake-aws /_names is not JSON: %v", err)
	}
	return names
}

// idpLinkRow is one idp_links row, every column.
type idpLinkRow struct {
	Iss, Sub, UserKey, Email, SecretKey, RefreshRef string
	Generation                                      int64
	LinkedAt, RefreshIssuedAt, RelinkDueAt          int64
	LastRefreshAt                                   sql.NullInt64
	LastRefreshStatus                               string
	OffboardedAt                                    sql.NullInt64
}

// copyStateDB copies the CP's state DB (and its WAL and shm, when present)
// out of the container into a fresh temp dir and returns the DB path and the
// raw bytes of every copied file (for the "no token in the DB" check).
func copyStateDB(t testing.TB) (string, [][]byte) {
	t.Helper()
	cid := serviceContainer(t, compose.SvcCP)
	dir := t.TempDir()
	var raw [][]byte
	for _, suffix := range []string{"", "-wal", "-shm"} {
		dst := filepath.Join(dir, "warden-cp.db"+suffix)
		res := compose.Run(".", compose.ComposeDeadline, "docker", "cp", cid+":"+cpStateDB+suffix, dst)
		if res.Exit != 0 {
			if suffix == "" {
				t.Fatalf("identity: docker cp %s: exit %d: %s", cpStateDB, res.Exit, firstLine(res.Stderr))
			}
			continue
		}
		b, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		raw = append(raw, b)
	}
	return filepath.Join(dir, "warden-cp.db"), raw
}

// readIdPLinks returns every idp_links row of a copied state DB, plus the
// table's column names.
func readIdPLinks(t testing.TB, path string) ([]idpLinkRow, []string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("identity: open the copied state DB: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT iss, sub, user_key, email, secret_key, refresh_ref, generation,
		linked_at, refresh_issued_at, relink_due_at, last_refresh_at, last_refresh_status, offboarded_at
		FROM idp_links`)
	if err != nil {
		t.Fatalf("identity: query idp_links: %v", err)
	}
	defer rows.Close()
	var out []idpLinkRow
	for rows.Next() {
		var r idpLinkRow
		if err := rows.Scan(&r.Iss, &r.Sub, &r.UserKey, &r.Email, &r.SecretKey, &r.RefreshRef, &r.Generation,
			&r.LinkedAt, &r.RefreshIssuedAt, &r.RelinkDueAt, &r.LastRefreshAt, &r.LastRefreshStatus, &r.OffboardedAt); err != nil {
			t.Fatalf("identity: scan idp_links: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("identity: idp_links rows: %v", err)
	}
	cols, err := db.Query(`SELECT name FROM pragma_table_info('idp_links') ORDER BY cid`)
	if err != nil {
		t.Fatalf("identity: idp_links columns: %v", err)
	}
	defer cols.Close()
	var names []string
	for cols.Next() {
		var n string
		if err := cols.Scan(&n); err != nil {
			t.Fatalf("identity: %v", err)
		}
		names = append(names, n)
	}
	return out, names
}

// linkFor returns the row of (iss, sub).
func linkFor(t testing.TB, rows []idpLinkRow, iss, sub string) idpLinkRow {
	t.Helper()
	for _, r := range rows {
		if r.Iss == iss && r.Sub == sub {
			return r
		}
	}
	t.Fatalf("identity: idp_links has no row for the signed-in user (%d rows)", len(rows))
	return idpLinkRow{}
}

// portalRefresh redeems a refresh token at Dex's token endpoint as the
// warden-portal client. It returns the new grant, or the HTTP status and Dex's
// error code on a refusal. Nothing is logged.
func portalRefresh(t testing.TB, refreshToken string) (grant, int, string) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	req, err := http.NewRequest(http.MethodPost, dexURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("identity: build the refresh request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(portalClientID, devEnv(t, "WARDEN_PORTAL_DEX_CLIENT_SECRET"))
	resp, err := hostClient.Do(req)
	if err != nil {
		t.Fatalf("identity: dex refresh request failed: %v", redactURLError(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	_ = json.Unmarshal(body, &out)
	return grant{IDToken: out.IDToken, RefreshToken: out.RefreshToken}, resp.StatusCode, out.Error
}

// wrongAudEvents counts allow events for host whose identity was refused with
// wrong_aud.
func wrongAudEvents(t testing.TB, host string) int {
	t.Helper()
	n := 0
	for _, e := range statusEvents(t, host, "invalid") {
		if e.IdentityReason == "wrong_aud" {
			n++
		}
	}
	return n
}

// TestPortalSignIn proves the consent sign-in done-when on the reference
// stack, in order (each step builds on the one before): sign-in and session,
// the stored refresh token and that it refreshes at Dex, the value-free
// idp_links row, console isolation, CSRF, the worker verifier refusing a
// warden-portal token, a second sign-in, Dex down, and the log sweep.
func TestPortalSignIn(t *testing.T) {
	requireStack(t)

	var leaks portalSecrets
	leaks.add(devEnv(t, "DEX_TEST_PASSWORD"), devEnv(t, "WARDEN_PORTAL_DEX_CLIENT_SECRET"))
	wantSub, _ := idClaims(t, dexToken(t, portalUser))["sub"].(string)
	if wantSub == "" {
		t.Fatalf("alice's Dex ID token has no sub")
	}
	userKey, err := secrets.UserKey(dexURL, wantSub)
	if err != nil {
		t.Fatalf("identity: user key: %v", err)
	}
	secretKey, err := secrets.IdPLinkKey(userKey)
	if err != nil {
		t.Fatalf("identity: idp link key: %v", err)
	}
	backendName := config.DefaultConsentStoreNamePrefix + secretKey

	// A reused stack (E2E_STACK_RUNNING=1) may already hold alice's link:
	// generations are checked relative to where this run starts.
	var startGen int64
	{
		path, _ := copyStateDB(t)
		rows, _ := readIdPLinks(t, path)
		for _, r := range rows {
			if r.Iss == dexURL && r.Sub == wantSub {
				startGen = r.Generation
			}
		}
	}

	var (
		alice        *portalSession
		firstToken   string // the refresh token the first login stored
		rotatedFirst string // what Dex returned when the test redeemed firstToken
		portalIDTok  string // an ID token minted for warden-portal
	)

	t.Run("alice signs in at /portal with a portal session", func(t *testing.T) {
		alice = portalLoginAs(t, portalUser)
		leaks.add(alice.cookie, alice.csrf)
		leaks.add(alice.trace.secrets()...)
		if len(alice.trace.codes) == 0 {
			t.Errorf("the login never passed an authorization code to /portal/callback")
		}
		if len(alice.trace.flowParams) != 2 {
			t.Errorf("the /portal/login redirect carried %d of state and nonce, want both", len(alice.trace.flowParams))
		}
		if !strings.HasPrefix(alice.trace.LoginRedirect, dexURL+"/") {
			t.Errorf("/portal/login redirected to %q, want Dex's public issuer %s", alice.trace.LoginRedirect, dexURL)
		}
		if alice.Sub != wantSub || alice.Email != portalEmail {
			t.Errorf("/portal/api/me: sub matches %v, email %q; want alice's Dex sub and %s", alice.Sub == wantSub, alice.Email, portalEmail)
		}
		if alice.LinkStatus != "linked" || alice.RelinkDueAt == "" {
			t.Errorf("/portal/api/me link: status %q relinkDueAt %q, want linked with a due date", alice.LinkStatus, alice.RelinkDueAt)
		}
		code, body := alice.mustDo(t, http.MethodGet, "/portal", nil)
		if code != http.StatusOK || !bytes.Contains(body, []byte(portalEmail)) {
			t.Errorf("GET /portal as alice: status %d, page names alice %v; want 200 naming her", code, bytes.Contains(body, []byte(portalEmail)))
		}
	})
	if alice == nil {
		t.Fatalf("no portal session: the remaining checks cannot run")
	}

	t.Run("consent.store holds idp/<userKey> and the token refreshes at Dex", func(t *testing.T) {
		if !slices.Contains(storedNames(t), backendName) {
			t.Fatalf("fake-aws holds no %s<idp/userKey> secret after the login", config.DefaultConsentStoreNamePrefix)
		}
		tok, ok := storedSecret(t, backendName)
		if !ok || tok == "" {
			t.Fatalf("the stored IdP link secret is missing or empty")
		}
		firstToken = tok
		leaks.add(firstToken)
		g, status, code := portalRefresh(t, firstToken)
		leaks.add(g.IDToken, g.RefreshToken)
		if status != http.StatusOK || g.IDToken == "" {
			t.Fatalf("refreshing the stored token at Dex as %s: status %d error %q, want 200 with an ID token", portalClientID, status, code)
		}
		rotatedFirst, portalIDTok = g.RefreshToken, g.IDToken
		c := idClaims(t, g.IDToken)
		if !contains(c.strList("aud"), portalClientID) || contains(c.strList("aud"), "warden") {
			t.Errorf("refreshed ID token aud = %v, want %s and not warden", c.strList("aud"), portalClientID)
		}
		if sub, _ := c["sub"].(string); sub != wantSub {
			t.Errorf("the refreshed ID token is not alice's")
		}
	})

	t.Run("idp_links holds only the reference, generation and dates", func(t *testing.T) {
		if firstToken == "" {
			t.Skip("no stored token from the previous step")
		}
		path, raw := copyStateDB(t)
		rows, cols := readIdPLinks(t, path)
		wantCols := []string{"iss", "sub", "user_key", "email", "secret_key", "refresh_ref", "generation",
			"linked_at", "refresh_issued_at", "relink_due_at", "last_refresh_at", "last_refresh_status", "offboarded_at"}
		if !slices.Equal(cols, wantCols) {
			t.Errorf("idp_links columns = %v, want exactly %v (no value-bearing column)", cols, wantCols)
		}
		r := linkFor(t, rows, dexURL, wantSub)
		if r.UserKey != userKey || r.SecretKey != secretKey || r.Email != portalEmail || r.Generation != startGen+1 {
			t.Errorf("idp_links row: user_key ok %v, secret_key ok %v, email %q, generation %d; want the user key, idp/<userKey>, %s, %d",
				r.UserKey == userKey, r.SecretKey == secretKey, r.Email, r.Generation, portalEmail, startGen+1)
		}
		if r.RefreshRef != secrets.Ref(firstToken).String() {
			t.Errorf("refresh_ref is not the stored token's Reference")
		}
		if r.RelinkDueAt <= r.RefreshIssuedAt || r.LinkedAt == 0 {
			t.Errorf("dates: linked_at %d refresh_issued_at %d relink_due_at %d", r.LinkedAt, r.RefreshIssuedAt, r.RelinkDueAt)
		}
		for i, b := range raw {
			if bytes.Contains(b, []byte(firstToken)) {
				t.Errorf("copied state file #%d holds the refresh token", i)
			}
		}
	})

	t.Run("the portal cookie opens no console route", func(t *testing.T) {
		for _, path := range []string{"/dashboard/api/traffic", "/dashboard/api/settings", "/central/secrets", "/auth/me"} {
			if code, _ := alice.mustDo(t, http.MethodGet, path, nil); code != http.StatusUnauthorized {
				t.Errorf("GET %s with the portal cookie: status %d, want 401", path, code)
			}
		}
	})

	t.Run("a portal POST without CSRF or with a foreign Origin is 403", func(t *testing.T) {
		code, body := alice.mustDo(t, http.MethodPost, "/portal/logout", nil)
		if code != http.StatusForbidden || errorCode(body) != "csrf" {
			t.Errorf("POST /portal/logout without %s: status %d error %q, want 403 csrf", csrfHeader, code, errorCode(body))
		}
		code, body = alice.mustDo(t, http.MethodPost, "/portal/logout", map[string]string{csrfHeader: alice.csrf, "Origin": "https://evil.example.test"})
		if code != http.StatusForbidden || errorCode(body) != "csrf" {
			t.Errorf("POST /portal/logout with a foreign Origin: status %d error %q, want 403 csrf", code, errorCode(body))
		}
		if code, _ := alice.mustDo(t, http.MethodGet, "/portal/api/me", nil); code != http.StatusOK {
			t.Errorf("alice's session after the refused logouts: status %d, want 200", code)
		}
	})

	t.Run("the worker verifier rejects an ID token minted for warden-portal", func(t *testing.T) {
		if portalIDTok == "" {
			t.Skip("no warden-portal ID token from the refresh step")
		}
		before := wrongAudEvents(t, allowedHost)
		status, res := routedCurl(t, portalIDTok, allowedHost)
		leaks.sweep(t, "agent-1 output", res.Stdout+res.Stderr)
		// Attribute mode allows the request and records the refused identity.
		if res.Exit != 0 || !strings.HasPrefix(status, "200 ") {
			t.Fatalf("routed request with the portal token: exit %d, status %q; want 200 (stderr: %s)", res.Exit, status, firstLine(res.Stderr))
		}
		err := compose.PollUntil(attribWait, func() (bool, string) {
			n := wrongAudEvents(t, allowedHost)
			return n > before, fmt.Sprintf("%d wrong_aud events, want more than %d", n, before)
		})
		if err != nil {
			t.Fatalf("the worker never recorded the warden-portal token as invalid/wrong_aud: %v", err)
		}
		for _, e := range statusEvents(t, allowedHost, "invalid") {
			if e.IdentityReason == "wrong_aud" && (e.UserSub != "" || e.UserEmail != "") {
				t.Errorf("a wrong_aud event carries a user (sub set %v, email %q)", e.UserSub != "", e.UserEmail)
			}
		}
	})

	t.Run("a second sign-in replaces the stored token", func(t *testing.T) {
		again := portalLoginAs(t, portalUser)
		leaks.add(again.cookie, again.csrf)
		leaks.add(again.trace.secrets()...)
		tok, ok := storedSecret(t, backendName)
		if !ok || tok == "" {
			t.Fatalf("the stored IdP link secret is missing after the second login")
		}
		leaks.add(tok)
		if tok == firstToken {
			t.Errorf("the second login stored the same refresh token as the first")
		}
		path, _ := copyStateDB(t)
		rows, _ := readIdPLinks(t, path)
		if r := linkFor(t, rows, dexURL, wantSub); r.Generation != startGen+2 || r.RefreshRef != secrets.Ref(tok).String() {
			t.Errorf("idp_links after the second login: generation %d, refresh_ref matches %v; want %d and the new token's Reference",
				r.Generation, r.RefreshRef == secrets.Ref(tok).String(), startGen+2)
		}
		// W-P3-CSIG-03 is correct either way (the generation check); this only
		// records what Dex does with the first login's chain.
		if rotatedFirst != "" {
			g, status, code := portalRefresh(t, rotatedFirst)
			leaks.add(g.IDToken, g.RefreshToken)
			if status == http.StatusOK {
				t.Logf("Dex kept the first sign-in's refresh chain valid for %s after a second sign-in", portalClientID)
			} else {
				t.Logf("Dex invalidated the first sign-in's refresh chain for %s after a second sign-in (status %d, error %q)", portalClientID, status, code)
			}
		}
	})

	t.Run("with Dex stopped /portal/login is 503 while sessions and /policy work", func(t *testing.T) {
		dex := serviceContainer(t, "dex")
		cp := serviceContainer(t, compose.SvcCP)
		docker := func(args ...string) error {
			if res := compose.Run(".", compose.ComposeDeadline, "docker", args...); res.Exit != 0 {
				return fmt.Errorf("docker %s: exit %d: %s", strings.Join(args, " "), res.Exit, firstLine(res.Stderr))
			}
			return nil
		}
		t.Cleanup(func() {
			if err := restoreDexAndCP(docker, dex, cp); err != nil {
				t.Errorf("restore the stack after the Dex outage: %v", err)
			}
		})
		// Restart the CP with Dex already down, so the portal's discovery has
		// never succeeded in this process (a CP that discovered Dex before the
		// outage keeps its cached endpoints and would still redirect).
		if err := docker("stop", "-t", "5", dex); err != nil {
			t.Fatal(err)
		}
		if err := docker("restart", "-t", "10", cp); err != nil {
			t.Fatal(err)
		}
		if err := waitCPHealthy(); err != nil {
			t.Fatalf("the CP did not come back with Dex down: %v", err)
		}
		code, body := bearerGet(t, "/portal/login")
		if code != http.StatusServiceUnavailable || errorCode(body) != "idp_unavailable" {
			t.Errorf("GET /portal/login with Dex down: status %d error %q, want 503 idp_unavailable", code, errorCode(body))
		}
		if code, _ := alice.mustDo(t, http.MethodGet, "/portal/api/me", nil); code != http.StatusOK {
			t.Errorf("alice's portal session with Dex down (after a CP restart): status %d, want 200", code)
		}
		if code, body := bearerGet(t, "/policy"); code != http.StatusOK {
			t.Errorf("GET /policy with Dex down: status %d, want 200 (body %.200s)", code, body)
		}
	})

	t.Run("no log line holds a password, code, cookie or token", func(t *testing.T) {
		leaks.add(portalIDTok)
		for _, svc := range []string{compose.SvcCP, compose.SvcWorker1, fakeAWSService} {
			// docker logs by container: compose.ComposeRun knows only the base
			// e2e files, not the identity overrides that add fake-aws.
			res := compose.Run(".", compose.ComposeDeadline, "docker", "logs", serviceContainer(t, svc))
			if res.Exit != 0 {
				t.Fatalf("identity: docker logs %s failed (exit %d): %s", svc, res.Exit, firstLine(res.Stderr))
			}
			leaks.sweep(t, svc+" logs", res.Stdout+res.Stderr)
		}
	})
}
