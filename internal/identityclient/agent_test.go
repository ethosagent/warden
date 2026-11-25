package identityclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/internal/keys"
)

func TestEnrollAgentKey(t *testing.T) {
	key, err := identityclient.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "warden", "agents")
	path := filepath.Join(dir, "agent-1.key")
	if err := identityclient.SaveAgentKey(path, key, false); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v mode %v, want 0600", err, st)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("key dir: %v mode %v, want 0700", err, st)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".tmp-*")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}

	if err := identityclient.SaveAgentKey(path, key, false); !errors.Is(err, identityclient.ErrKeyExists) {
		t.Fatalf("second enroll without force = %v, want ErrKeyExists", err)
	}
	other, _ := identityclient.GenerateAgentKey()
	if err := identityclient.SaveAgentKey(path, other, true); err != nil {
		t.Fatalf("enroll with force: %v", err)
	}
	loaded, err := identityclient.LoadAgentKey(path)
	if err != nil || loaded.PublicJWK() != other.PublicJWK() {
		t.Fatalf("load after force: %v", err)
	}

	jwk := loaded.PublicJWK()
	raw, _ := json.Marshal(jwk)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, has := m["d"]; has {
		t.Fatalf("public JWK has a private member: %s", raw)
	}
	thumb, err := keys.Thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if m["kty"] != "OKP" || m["crv"] != "Ed25519" || m["alg"] != "EdDSA" || m["kid"] != thumb {
		t.Fatalf("JWK = %s, want OKP Ed25519 EdDSA with kid %s", raw, thumb)
	}
	if _, err := keys.ParseJWK(raw); err != nil {
		t.Fatalf("the printed JWK does not parse: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := identityclient.LoadAgentKey(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("a 0644 key = %v, want an error naming %s", err, path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identityclient.LoadAgentKey(path); err == nil || strings.Contains(err.Error(), "not a key") {
		t.Fatalf("a junk key file = %v, want an error without its content", err)
	}
	if _, err := identityclient.LoadAgentKey(filepath.Join(dir, "missing.key")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing key = %v, want fs.ErrNotExist", err)
	}
	if _, err := identityclient.DefaultAgentKeyPath("../evil"); err == nil {
		t.Fatal("an id with a path separator got a default key path")
	}
	if s := key.String() + slog.Any("k", key).String(); strings.Contains(s, "PRIVATE") || strings.Contains(s, "priv") {
		t.Fatalf("key forms leak: %s", s)
	}
}

func TestClientAssertion(t *testing.T) {
	key, err := identityclient.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "https://cp.example.com/oauth2/token"
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	raw, err := identityclient.SignClientAssertion(context.Background(), key, "agent-1", endpoint, now)
	if err != nil {
		t.Fatal(err)
	}
	h, payload, input, sig, err := keys.ParseCompact(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicJWK().PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub.(ed25519.PublicKey), input, sig) {
		t.Fatal("the assertion does not verify against the public JWK")
	}
	if h.Alg != "EdDSA" || h.Kid != key.PublicJWK().Kid {
		t.Fatalf("header = %+v, want EdDSA and the thumbprint kid", h)
	}
	var c struct {
		Iss, Sub, Aud, JTI string
		Iat, Exp           int64
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	if c.Iss != "agent-1" || c.Sub != "agent-1" || c.Aud != endpoint || c.Iat != now.Unix() || c.Exp-c.Iat != 60 {
		t.Fatalf("claims = %+v", c)
	}

	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		a, err := identityclient.SignClientAssertion(context.Background(), key, "agent-1", endpoint, now)
		if err != nil {
			t.Fatal(err)
		}
		_, p, _, _, err := keys.ParseCompact(a)
		if err != nil {
			t.Fatal(err)
		}
		var cl struct{ JTI string }
		if err := json.Unmarshal(p, &cl); err != nil {
			t.Fatal(err)
		}
		if len(cl.JTI) != 22 { // 128 bits, unpadded base64url
			t.Fatalf("jti %q is not 128 bits of base64url", cl.JTI)
		}
		seen[cl.JTI] = true
	}
	if len(seen) != 1000 {
		t.Fatalf("1000 assertions gave %d distinct jti values", len(seen))
	}
	if _, err := identityclient.SignClientAssertion(context.Background(), key, "bad id", endpoint, now); err == nil {
		t.Fatal("an invalid agent id was signed")
	}
	if _, err := identityclient.SignClientAssertion(context.Background(), key.WithKID("registered-kid"), "agent-1", endpoint, now); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeRequest(t *testing.T) {
	a := newAgentRig(t)
	a.ex.Scope = "read write"
	a.ex.Audience = "https://issuer.example.com/oauth2/token"
	tok, err := a.ex.Exchange(context.Background(), "subject-secret")
	if err != nil {
		t.Fatal(err)
	}
	f := a.cp.lastForm()
	want := map[string]string{
		"grant_type":            "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":         "subject-secret",
		"subject_token_type":    "urn:ietf:params:oauth:token-type:id_token",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"audience":              "warden-worker",
		"scope":                 "read write",
	}
	for k, v := range want {
		if f.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, f.Get(k), v)
		}
	}
	_, payload, _, _, err := keys.ParseCompact(f.Get("client_assertion"))
	if err != nil || !strings.Contains(string(payload), `"aud":"https://issuer.example.com/oauth2/token"`) {
		t.Errorf("assertion audience override not used: %v %s", err, payload)
	}
	if tok.Lifetime() != 900*time.Second || tok.Scope != "read" || !tok.Expiry.Equal(a.clock.Now().Add(900*time.Second)) {
		t.Errorf("token = lifetime %v scope %q expiry %v", tok.Lifetime(), tok.Scope, tok.Expiry)
	}
	if h := a.cp.hdrs[0]; h.Get("Authorization") != "" || !strings.HasPrefix(h.Get("Content-Type"), "application/x-www-form-urlencoded") {
		t.Errorf("headers = %v", h)
	}
	if strings.Contains(tok.String(), tok.AccessToken) {
		t.Error("WardenToken.String shows the token")
	}

	for _, bad := range []string{"", "/oauth2/token", "http://cp.example.com/oauth2/token", "https://cp.example.com/oauth2/token?x=1", "https://u:p@cp.example.com/t"} {
		if err := identityclient.ValidateTokenEndpoint(bad); err == nil {
			t.Errorf("token endpoint %q accepted", bad)
		}
	}
	for _, ok := range []string{"https://cp.example.com/oauth2/token", "http://localhost:8443/oauth2/token", "http://127.0.0.1:1/oauth2/token"} {
		if err := identityclient.ValidateTokenEndpoint(ok); err != nil {
			t.Errorf("token endpoint %q refused: %v", ok, err)
		}
	}
}

func TestExchangeErrors(t *testing.T) {
	a := newAgentRig(t)
	logs := &bytes.Buffer{}
	a.ex.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var slept []time.Duration
	newSource := func() *identityclient.WardenTokenSource {
		s := identityclient.NewWardenTokenSource(a.ex, staticSubject{tok: "subject-secret"})
		s.Now, s.Log = a.clock.Now, a.ex.Log
		s.Sleep = func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			a.clock.Advance(d)
			return nil
		}
		return s
	}

	denied := func(status int, code string) {
		t.Helper()
		before := a.cp.calls()
		a.cp.reply(oauthErr(status, code))
		_, err := newSource().Token(context.Background())
		var d identityclient.ErrExchangeDenied
		if !errors.As(err, &d) || d.Code != code {
			t.Fatalf("%d %s: err = %v, want ErrExchangeDenied{%s}", status, code, err, code)
		}
		if n := a.cp.calls() - before; n != 1 {
			t.Fatalf("%s was tried %d times, want 1 (never retried)", code, n)
		}
	}
	denied(401, "invalid_client")
	denied(400, "invalid_grant")
	denied(400, "unauthorized_client")
	denied(400, "invalid_scope")

	// 429 with Retry-After: the exchanger reports it, the source waits at
	// least that long and then succeeds.
	r429 := oauthErr(429, "rate_limited")
	r429.retryAfter = "3"
	a.cp.reply(r429)
	_, err := a.ex.Exchange(context.Background(), "subject-secret")
	var rl identityclient.ErrRateLimited
	if !errors.As(err, &rl) || rl.RetryAfter != 3*time.Second {
		t.Fatalf("429 = %v, want ErrRateLimited{3s}", err)
	}
	a.cp.reply(r429)
	tok, err := newSource().Token(context.Background())
	if err != nil || tok.AccessToken == "" {
		t.Fatalf("429 then success: %v", err)
	}
	if len(slept) != 1 || slept[0] < 3*time.Second {
		t.Fatalf("waits = %v, want one of at least 3s", slept)
	}

	// 503 temporarily_unavailable honours Retry-After too.
	slept = nil
	r503 := oauthErr(503, "temporarily_unavailable")
	r503.retryAfter = "5"
	a.cp.reply(r503)
	if _, err := newSource().Token(context.Background()); err != nil {
		t.Fatalf("503 then success: %v", err)
	}
	if len(slept) != 1 || slept[0] != 5*time.Second {
		t.Fatalf("503 waits = %v, want [5s]", slept)
	}
	// A persistent 503 ends as ErrUnavailable after the attempts.
	slept = nil
	a.cp.reply(r503, r503, r503)
	if _, err := newSource().Token(context.Background()); !errors.As(err, new(identityclient.ErrUnavailable)) {
		t.Fatalf("persistent 503 = %v, want ErrUnavailable", err)
	}

	// Unknown code, junk bodies and a dead server never echo the body.
	a.cp.reply(oauthErr(400, "CP-BODY-MARKER-code"))
	_, err = a.ex.Exchange(context.Background(), "subject-secret")
	if !errors.As(err, new(identityclient.ErrExchangeDenied)) || strings.Contains(err.Error(), "MARKER") {
		t.Fatalf("unknown code = %v", err)
	}
	a.cp.reply(cpReply{status: 200, body: `{"access_token":"x"}`}, cpReply{status: 302, body: "CP-BODY-MARKER"})
	for i := 0; i < 2; i++ {
		if _, err := a.ex.Exchange(context.Background(), "subject-secret"); !errors.Is(err, identityclient.ErrBadExchangeResponse) {
			t.Fatalf("junk reply %d = %v, want ErrBadExchangeResponse", i, err)
		}
	}
	a.cp.srv.Close()
	if _, err := a.ex.Exchange(context.Background(), "subject-secret"); !errors.Is(err, identityclient.ErrCPUnreachable) {
		t.Fatalf("dead server = %v, want ErrCPUnreachable", err)
	}

	if m := contains(logs.String(), "subject-secret", "warden-token-secret", "CP-BODY-MARKER", "client_assertion"); m != "" {
		t.Fatalf("the log holds %q:\n%s", m, logs.String())
	}
}

func TestExchangeRefreshAtTwoThirds(t *testing.T) {
	a := newAgentRig(t)
	src := identityclient.NewWardenTokenSource(a.ex, staticSubject{tok: "subject-secret"})
	src.Now = a.clock.Now
	var rotated atomic.Int32
	src.OnRotate(func() { rotated.Add(1) })
	waitRotated := func(n int32) {
		t.Helper()
		dl := time.Now().Add(10 * time.Second)
		for rotated.Load() < n && time.Now().Before(dl) {
			runtime.Gosched()
		}
	}

	first, err := src.Token(context.Background())
	waitRotated(1)
	if err != nil || a.cp.calls() != 1 || rotated.Load() != 1 {
		t.Fatalf("first token: %v calls=%d rotated=%d", err, a.cp.calls(), rotated.Load())
	}
	// Cached: no exchange until the refresh point, which is in [540s, 600s].
	elapsed := time.Duration(0)
	for ; a.cp.calls() == 1 && elapsed <= 900*time.Second; elapsed += time.Second {
		a.clock.Advance(time.Second)
		cur, err := src.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if a.cp.calls() == 1 && cur.AccessToken != first.AccessToken {
			t.Fatal("the cached token changed without an exchange")
		}
	}
	if elapsed < 540*time.Second || elapsed > 601*time.Second {
		t.Fatalf("second exchange after %v, want between 540s and 600s", elapsed)
	}
	waitRotated(2)
	if rotated.Load() != 2 {
		t.Fatalf("OnRotate ran %d times, want 2", rotated.Load())
	}

	// The jitter bounds are exact when pinned.
	for _, c := range []struct {
		jitter float64
		want   time.Duration
	}{{0, 600 * time.Second}, {0.999999, 540 * time.Second}} {
		b := newAgentRig(t)
		s := identityclient.NewWardenTokenSource(b.ex, staticSubject{tok: "subject-secret"})
		s.Now, s.Jitter = b.clock.Now, func() float64 { return c.jitter }
		if _, err := s.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
		b.clock.Advance(c.want - 2*time.Second)
		_, _ = s.Token(context.Background())
		if b.cp.calls() != 1 {
			t.Fatalf("jitter %v: exchanged before %v", c.jitter, c.want)
		}
		b.clock.Advance(3 * time.Second)
		_, _ = s.Token(context.Background())
		if b.cp.calls() != 2 {
			t.Fatalf("jitter %v: no exchange at %v", c.jitter, c.want)
		}
	}
}

func TestExchangeSingleFlight(t *testing.T) {
	a := newAgentRig(t)
	a.cp.gate = make(chan struct{})
	src := identityclient.NewWardenTokenSource(a.ex, staticSubject{tok: "subject-secret"})
	src.Now = a.clock.Now
	var joined atomic.Int32
	src.SetJoinHook(func() { joined.Add(1) })

	var wg sync.WaitGroup
	got := make([]string, 8)
	errs := make([]error, 8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := src.Token(context.Background())
			got[i], errs[i] = tok.AccessToken, err
		}()
	}
	<-a.cp.hit // the one request is in flight
	// Release it only once every caller has joined the flight.
	for joined.Load() < int32(len(got)) {
		runtime.Gosched()
	}
	close(a.cp.gate)
	wg.Wait()
	for i := range got {
		if errs[i] != nil || got[i] != got[0] || got[i] == "" {
			t.Fatalf("caller %d: %q %v", i, got[i], errs[i])
		}
	}
	if n := a.cp.calls(); n != 1 {
		t.Fatalf("%d concurrent callers made %d requests, want 1", len(got), n)
	}
}

func TestExchangeServesCurrentTokenOnFailure(t *testing.T) {
	a := newAgentRig(t)
	src := identityclient.NewWardenTokenSource(a.ex, staticSubject{tok: "subject-secret"})
	src.Now, src.Jitter = a.clock.Now, func() float64 { return 0 }
	first, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Past the refresh point the control plane is down: the valid token is
	// served, and the retries back off instead of hammering.
	a.clock.Advance(601 * time.Second)
	a.cp.srv.Close()
	for i := 0; i < 3; i++ {
		cur, err := src.Token(context.Background())
		if err != nil || cur.AccessToken != first.AccessToken {
			t.Fatalf("call %d: %v, want the current token", i, err)
		}
	}
	// Past exp there is nothing to serve.
	a.clock.Advance(300 * time.Second)
	if _, err := src.Token(context.Background()); !errors.Is(err, identityclient.ErrCPUnreachable) {
		t.Fatalf("expired and down = %v, want ErrCPUnreachable", err)
	}
	if _, ok := src.Current(); ok {
		t.Fatal("Current serves an expired token")
	}
}

func TestExchangeRefreshForcesExchange(t *testing.T) {
	a := newAgentRig(t)
	src := identityclient.NewWardenTokenSource(a.ex, staticSubject{tok: "subject-secret"})
	src.Now = a.clock.Now
	first, _ := src.Token(context.Background())
	a.clock.Advance(3 * time.Second) // past the 2s floor
	again, err := src.Refresh(context.Background())
	if err != nil || again.AccessToken == first.AccessToken || a.cp.calls() != 2 {
		t.Fatalf("Refresh: %v calls=%d", err, a.cp.calls())
	}
}

func TestExchangeLoginRequiredNoPrompt(t *testing.T) {
	r := newRig(t)
	r.login(t)
	r.out.Reset()
	a := newAgentRig(t)
	a.cp.expiresIn = 3000
	a.ex.Now = r.clock.Now
	src := identityclient.NewWardenTokenSource(a.ex, r.cl)
	src.Now, src.Jitter = r.clock.Now, func() float64 { return 0 }

	first, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The issuer now rejects the refresh token. The ID token is past 2/3 of
	// its life and the Warden token is past its refresh point, but not its exp.
	r.idp.mu.Lock()
	r.idp.refresh = "revoked"
	r.idp.mu.Unlock()
	r.clock.Advance(2050 * time.Second)
	cur, err := src.Token(context.Background())
	if err != nil || cur.AccessToken != first.AccessToken {
		t.Fatalf("with the login gone and a valid token: %v, want the current token", err)
	}
	if r.out.Len() != 0 {
		t.Fatalf("something was written to the prompt writer: %q", r.out.String())
	}
	if a.cp.calls() != 1 {
		t.Fatalf("the control plane saw %d requests, want 1 (no subject, no exchange)", a.cp.calls())
	}
	// After the Warden token's exp the login requirement surfaces.
	r.clock.Advance(1100 * time.Second)
	if _, err := src.Token(context.Background()); !errors.Is(err, identityclient.ErrLoginRequired) {
		t.Fatalf("expired with no login = %v, want ErrLoginRequired", err)
	}
	if r.out.Len() != 0 {
		t.Fatalf("something was written to the prompt writer: %q", r.out.String())
	}
}

func TestSubjectTokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "subject")
	if err := os.WriteFile(p, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := identityclient.FileSubject{Path: p}
	if tok, err := f.Subject(context.Background()); err != nil || tok != "first-token" {
		t.Fatalf("subject = %q %v", tok, err)
	}
	if err := os.WriteFile(p, []byte("second-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, _ := f.Subject(context.Background()); tok != "second-token" {
		t.Fatalf("the file was not re-read: %q", tok)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Subject(context.Background()); err == nil || !strings.Contains(err.Error(), p) || strings.Contains(err.Error(), "second-token") {
		t.Fatalf("a 0640 subject file = %v, want an error naming the path", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Subject(context.Background()); err == nil {
		t.Fatal("an empty subject file was accepted")
	}
}

func TestAgentConfig(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if identityclient.AgentMode(identityclient.AgentFlags{}, get) {
		t.Fatal("agent mode with no agent id")
	}
	env[identityclient.EnvAgentID] = "agent-1"
	env[identityclient.EnvTokenEndpoint] = "https://cp.example.com/oauth2/token"
	env[identityclient.EnvAgentKeyFile] = "/keys/a.key"
	env[identityclient.EnvCPCA] = "/ca.pem"
	cfg, err := identityclient.LoadAgentConfig(identityclient.AgentFlags{Scope: " read  write "}, get)
	if err != nil || cfg.KeyFile != "/keys/a.key" || cfg.CPCA != "/ca.pem" || cfg.Scope != "read write" {
		t.Fatalf("env config = %+v %v", cfg, err)
	}
	cfg, err = identityclient.LoadAgentConfig(identityclient.AgentFlags{AgentID: "agent-2", KeyFile: "/flag.key"}, get)
	if err != nil || cfg.AgentID != "agent-2" || cfg.KeyFile != "/flag.key" {
		t.Fatalf("flags must win: %+v %v", cfg, err)
	}
	delete(env, identityclient.EnvTokenEndpoint)
	if _, err := identityclient.LoadAgentConfig(identityclient.AgentFlags{}, get); err == nil {
		t.Fatal("no token endpoint was accepted: there is no implied default")
	}
	env[identityclient.EnvTokenEndpoint] = "https://cp.example.com/oauth2/token"
	env[identityclient.EnvAgentID] = "bad id"
	if _, err := identityclient.LoadAgentConfig(identityclient.AgentFlags{}, get); err == nil {
		t.Fatal("an invalid agent id was accepted")
	}
}

func TestParseWardenToken(t *testing.T) {
	payload := `{"sub":"user-1","scope":"read","exp":1900000000,"act":{"sub":"agent-1"},"cnf":{"jkt":"abc"}}`
	tok := "e30." + b64(payload) + ".sig"
	info, err := identityclient.ParseWardenToken(tok)
	if err != nil || info.Subject != "user-1" || info.ActorSub != "agent-1" || info.JKT != "abc" || info.Scope != "read" || info.Expiry.Unix() != 1900000000 {
		t.Fatalf("info = %+v %v", info, err)
	}
	if _, err := identityclient.ParseWardenToken("nope"); err == nil {
		t.Fatal("junk parsed")
	}
}
