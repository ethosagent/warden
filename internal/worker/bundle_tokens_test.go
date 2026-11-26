package worker

import (
	"context"
	"encoding/json"
	"encoding/pem"
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

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/proxy"
)

const (
	tokTestIssuer = "https://cp.example.test"
	tokTestAgent  = "agent-a"
)

// tokenBundle is what one test bundle carries besides the allowlist.
type tokenBundle struct {
	seq    int64
	issuer string
	cpID   string
	// jwks is the tokenJWKS section: raw JSON, so a test can break it.
	jwks   json.RawMessage
	agents []config.RegisteredAgent
}

// tokenCP is a signed-bundle control plane for the token key tests. It counts
// every request that is not a poll of the policy endpoint, so a test can prove the worker never
// goes looking for keys.
type tokenCP struct {
	cp      *bundleCP
	rp      *config.RemoteProvider
	mk      func(tokenBundle) []byte
	others  atomic.Int64
	logs    *syncBuffer
	logger  *slog.Logger
	etagSeq int
}

func newTokenCP(t *testing.T, clk *clocktest.Fake, pinned bool) *tokenCP {
	t.Helper()
	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	tc := &tokenCP{cp: &bundleCP{}, logs: &syncBuffer{}}
	tc.logger = slog.New(slog.NewTextHandler(tc.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" { // the endpoint the provider polls
			tc.others.Add(1)
		}
		tc.cp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	rp, err := config.NewRemoteProvider(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rp.CloseIdleConnections)
	if err := rp.SetCACert(caPath); err != nil {
		t.Fatal(err)
	}
	if pinned {
		if err := rp.SetBundleTrust(config.BundleTrust{Pins: []keys.JWK{pin}, Skew: time.Minute, Now: clk.Now, Logger: tc.logger}); err != nil {
			t.Fatal(err)
		}
	}
	tc.rp = rp
	tc.mk = func(b tokenBundle) []byte {
		policy := map[string]any{"allowlist": []map[string]string{{"domain": "a.example.com"}}}
		if len(b.agents) > 0 {
			policy["registeredAgents"] = b.agents
		}
		pol, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		bd := bundle.Bundle{
			Seq: b.seq, PolicyVersion: b.seq, IssuedAt: bundleStart, ExpiresAt: bundleStart.Add(time.Hour),
			CPID: b.cpID, Policy: pol, TokenIssuer: b.issuer,
		}
		if len(b.jwks) > 0 {
			bd.Sections = map[string]json.RawMessage{config.BundleSectionTokenJWKS: b.jwks}
		}
		raw, err := bundle.Sign(context.Background(), bd, nil, sg)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	return tc
}

// serve makes tb the bundle the control plane serves.
func (tc *tokenCP) serve(tb tokenBundle) {
	tc.etagSeq++
	tc.cp.set(tc.mk(tb), "e"+string(rune('0'+tc.etagSeq)))
}

// tokenKey is a token signing key and its JWKS document.
type tokenKey struct {
	sg  keys.Signer
	jkt string
}

func newTokenKey(t *testing.T) tokenKey {
	t.Helper()
	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	return tokenKey{sg: sg, jkt: sg.KID()}
}

func jwksOf(t *testing.T, ks ...tokenKey) json.RawMessage {
	t.Helper()
	set := keys.JWKS{}
	for _, k := range ks {
		j, err := keys.PublicJWK(k.sg.Public(), keys.AlgEdDSA)
		if err != nil {
			t.Fatal(err)
		}
		set.Keys = append(set.Keys, j)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// wardenToken signs a Warden token the way the token service does.
func wardenToken(t *testing.T, k tokenKey, now time.Time, mod func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"ver": 1, "iss": tokTestIssuer, "aud": identity.WardenAudience, "sub": "user-1",
		"act": map[string]string{"sub": tokTestAgent}, "sid": "wts_1", "jti": "j1",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"cnf": map[string]string{"jkt": "tp"},
	}
	if mod != nil {
		mod(claims)
	}
	tok, err := keys.SignCompact(context.Background(), k.sg, keys.Header{Alg: keys.AlgEdDSA, Kid: k.sg.KID(), Typ: identity.WardenTokenTyp}, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newBindingWiring(tc *tokenCP, clk *clocktest.Fake, idIssuer string) *identityWiring {
	return &identityWiring{logger: tc.logger, now: clk.Now, issuer: idIssuer}
}

// tokenStatus verifies tok on w's Warden verifier.
func tokenStatus(t *testing.T, w *identityWiring, tok string) (identity.Status, identity.Reason) {
	t.Helper()
	if w.warden == nil {
		return identity.StatusUnverified, identity.ReasonJWKSUnavailable
	}
	_, st, r := w.warden.Verify(context.Background(), tok)
	return st, r
}

// TestBundleAppliesTokenKeys: a worker with pinned bundle keys takes its token
// keys from the verified bundle, swaps them when a bundle rotates the key, and
// never asks anything for keys but the policy endpoint.
func TestBundleAppliesTokenKeys(t *testing.T) {
	clk := clocktest.NewFake(bundleStart.Add(time.Minute))
	tc := newTokenCP(t, clk, true)
	k1, k2 := newTokenKey(t), newTokenKey(t)
	jkt := newTokenKey(t).jkt
	agent := config.RegisteredAgent{ID: tokTestAgent, Status: config.RegisteredAgentActive, JKT: []string{jkt}}

	tc.serve(tokenBundle{seq: 1, issuer: tokTestIssuer, cpID: "cp", jwks: jwksOf(t, k1), agents: []config.RegisteredAgent{agent}})
	if err := tc.rp.Pull(); err != nil {
		t.Fatal(err)
	}
	w := newBindingWiring(tc, clk, "https://idp.example.test")
	w.applyBinding(tc.rp)

	t1 := wardenToken(t, k1, clk.Now(), nil)
	t2 := wardenToken(t, k2, clk.Now(), nil)
	if st, r := tokenStatus(t, w, t1); st != identity.StatusValid {
		t.Fatalf("K1 token under bundle 1: %s/%s", st, r)
	}
	if st, r := tokenStatus(t, w, t2); st != identity.StatusInvalid || r != identity.ReasonUnknownKID {
		t.Fatalf("K2 token under bundle 1: %s/%s, want invalid/unknown_kid", st, r)
	}
	snap := w.warden.Snapshot()
	a, ok := snap.Agent(tokTestAgent)
	if snap.Generation() != 1 || !ok || !a.Active {
		t.Fatalf("snapshot generation %d agent %+v %v", snap.Generation(), a, ok)
	}
	if _, has := a.JKT[jkt]; !has {
		t.Fatal("the agent's thumbprint is not in the snapshot")
	}

	// Bundle 2 rotates the key and disables the agent. The long poll applies it.
	disabled := agent
	disabled.Status = config.RegisteredAgentDisabled
	tc.serve(tokenBundle{seq: 2, issuer: tokTestIssuer, cpID: "cp", jwks: jwksOf(t, k2), agents: []config.RegisteredAgent{disabled}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	changed, err := tc.rp.PollLong(ctx, time.Second)
	if err != nil || !changed {
		t.Fatalf("PollLong = %v, %v, want a change", changed, err)
	}
	w.applyBinding(tc.rp)
	if st, r := tokenStatus(t, w, t1); st != identity.StatusInvalid || r != identity.ReasonUnknownKID {
		t.Fatalf("K1 token after the rotation: %s/%s, want invalid/unknown_kid", st, r)
	}
	if st, r := tokenStatus(t, w, t2); st != identity.StatusValid {
		t.Fatalf("K2 token after the rotation: %s/%s", st, r)
	}
	if a, _ := w.warden.Snapshot().Agent(tokTestAgent); a.Active {
		t.Fatal("the disabled agent is still active in the snapshot")
	}
	if n := tc.others.Load(); n != 0 {
		t.Fatalf("%d requests to something other than the policy endpoint: the worker must never fetch keys", n)
	}

	// Applying the same bundle again installs nothing new.
	before := strings.Count(tc.logs.String(), "warden token keys applied")
	w.applyBinding(tc.rp)
	if after := strings.Count(tc.logs.String(), "warden token keys applied"); after != before {
		t.Fatalf("the same bundle was installed twice (%d -> %d)", before, after)
	}
}

// TestBundleTokenKeysFailClosed: every way the bundle can fail to name usable
// token keys leaves Warden tokens unverified, and none falls back to the
// control plane id or to identity.issuer.
func TestBundleTokenKeysFailClosed(t *testing.T) {
	k1 := newTokenKey(t)
	cases := []struct {
		name     string
		pinned   bool
		bundle   tokenBundle
		idIssuer string
		wantLog  string
	}{
		{"no pins (legacy wire)", false, tokenBundle{}, "https://idp.example.test", ""},
		{"empty tokenIssuer is not the cpID", true,
			tokenBundle{seq: 1, issuer: "", cpID: tokTestIssuer, jwks: jwksOf(t, k1)}, "https://idp.example.test", ""},
		{"tokenIssuer equals identity.issuer", true,
			tokenBundle{seq: 1, issuer: tokTestIssuer, cpID: "cp", jwks: jwksOf(t, k1)}, tokTestIssuer, "tokenIssuer equals identity.issuer"},
		{"issuer equal up to a trailing slash and case", true,
			tokenBundle{seq: 1, issuer: tokTestIssuer, cpID: "cp", jwks: jwksOf(t, k1)}, "HTTPS://cp.example.test/", "tokenIssuer equals identity.issuer"},
		{"no JWKS section", true,
			tokenBundle{seq: 1, issuer: tokTestIssuer, cpID: "cp"}, "https://idp.example.test", ""},
		{"JWKS that is not a key set", true,
			tokenBundle{seq: 1, issuer: tokTestIssuer, cpID: "cp", jwks: json.RawMessage(`"nope"`)}, "https://idp.example.test", "token JWKS is not usable"},
		{"JWKS with a private member", true,
			tokenBundle{seq: 1, issuer: tokTestIssuer, cpID: "cp", jwks: json.RawMessage(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}]}`)}, "https://idp.example.test", "token JWKS is not usable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := clocktest.NewFake(bundleStart.Add(time.Minute))
			cp := newTokenCP(t, clk, tc.pinned)
			if tc.pinned {
				cp.serve(tc.bundle)
			} else {
				cp.cp.set([]byte(`{"allowlist":[{"domain":"a.example.com"}]}`), "legacy")
			}
			if err := cp.rp.Pull(); err != nil {
				t.Fatal(err)
			}
			w := newBindingWiring(cp, clk, tc.idIssuer)
			w.applyBinding(cp.rp)
			// A token its issuer and key would verify, if a snapshot allowed it.
			for _, iss := range []string{tokTestIssuer, "cp"} {
				tok := wardenToken(t, k1, clk.Now(), func(c map[string]any) { c["iss"] = iss })
				if st, r := tokenStatus(t, w, tok); st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
					t.Fatalf("iss %q: %s/%s, want unverified/jwks_unavailable", iss, st, r)
				}
			}
			logs := cp.logs.String()
			if tc.wantLog != "" && strings.Count(logs, tc.wantLog) != 1 {
				t.Fatalf("want exactly one %q log:\n%s", tc.wantLog, logs)
			}
			if tc.wantLog != "" && !strings.Contains(logs, "level=ERROR") {
				t.Fatalf("not logged at error level:\n%s", logs)
			}
			if strings.Contains(logs, "eyJ") {
				t.Fatalf("a token-shaped string was logged:\n%s", logs)
			}
			// Asking again for the same bundle does not log again.
			w.applyBinding(cp.rp)
			if tc.wantLog != "" && strings.Count(cp.logs.String(), tc.wantLog) != 1 {
				t.Fatalf("the refusal was logged again for the same bundle:\n%s", cp.logs.String())
			}
		})
	}
}

// TestBundleTokenKeysRecoverWhenIssuersDiffer: the refusal lifts when the
// next bundle (or identity.issuer) no longer collides, and a token verifies.
func TestBundleTokenKeysRecoverWhenIssuersDiffer(t *testing.T) {
	clk := clocktest.NewFake(bundleStart.Add(time.Minute))
	tc := newTokenCP(t, clk, true)
	k1 := newTokenKey(t)
	tc.serve(tokenBundle{seq: 1, issuer: tokTestIssuer, cpID: "cp", jwks: jwksOf(t, k1)})
	if err := tc.rp.Pull(); err != nil {
		t.Fatal(err)
	}
	w := newBindingWiring(tc, clk, tokTestIssuer)
	w.applyBinding(tc.rp)
	tok := wardenToken(t, k1, clk.Now(), nil)
	if st, _ := tokenStatus(t, w, tok); st != identity.StatusUnverified {
		t.Fatalf("while colliding: %s", st)
	}
	// identity.issuer changes in a settings apply on the same bundle: the
	// binding is rebuilt against it.
	w.issuer = "https://idp.example.test"
	w.applyBinding(tc.rp)
	if st, r := tokenStatus(t, w, tok); st != identity.StatusValid {
		t.Fatalf("after the issuers differ: %s/%s", st, r)
	}
}

// bindingClient is a ControlPlaneClient whose binding inputs the test sets.
type bindingClient struct {
	fakeControlPlaneClient
	mu2     sync.Mutex
	inputs  config.BindingInputs
	ok      bool
	onRead  func()
	readCnt int
}

func (c *bindingClient) BindingInputs() (config.BindingInputs, bool) {
	c.mu2.Lock()
	fn, in, ok := c.onRead, c.inputs, c.ok
	c.readCnt++
	c.mu2.Unlock()
	if fn != nil {
		fn()
	}
	return in, ok
}

// TestApplierBindsTokenKeysUnderTheApplyLock: SettingsApplier.Apply reads the
// binding inputs on the apply goroutine while holding the serial evaluator's
// lock, and installs the snapshot with the bundle seq as its generation.
func TestApplierBindsTokenKeysUnderTheApplyLock(t *testing.T) {
	a, _, _ := newTestApplier(t)
	logs := &syncBuffer{}
	w := newIdentityWiring(a.p, "default", slog.New(slog.NewTextHandler(logs, nil)))
	a.identity = w
	a.serial = &serialEvaluator{}
	k1 := newTokenKey(t)
	bc := &bindingClient{ok: true, inputs: config.BindingInputs{Seq: 7, TokenIssuer: tokTestIssuer, TokenJWKS: jwksOf(t, k1)}}
	var heldAtRead atomic.Bool
	bc.onRead = func() {
		// The lock is taken by the caller when it is not free here.
		if a.serial.mu.TryLock() {
			a.serial.mu.Unlock()
			return
		}
		heldAtRead.Store(true)
	}
	a.cp = bc
	a.Apply()
	if !heldAtRead.Load() {
		t.Fatal("BindingInputs was read without the serial evaluator's lock")
	}
	if g := w.warden.Snapshot().Generation(); g != 7 {
		t.Fatalf("generation = %d, want the bundle seq 7", g)
	}
	if st, r := tokenStatus(t, w, wardenToken(t, k1, time.Now(), nil)); st != identity.StatusValid {
		t.Fatalf("token after Apply: %s/%s", st, r)
	}

	t.Run("no verified bundle installs nothing", func(t *testing.T) {
		a2, _, _ := newTestApplier(t)
		w2 := newIdentityWiring(a2.p, "default", slog.New(slog.NewTextHandler(logs, nil)))
		a2.identity, a2.serial = w2, &serialEvaluator{}
		a2.cp = &bindingClient{}
		a2.Apply()
		if w2.warden != nil && w2.warden.Snapshot() != nil {
			t.Fatal("a snapshot was installed without a verified bundle")
		}
	})
}

// TestSerialEvaluatorLocked: locked excludes the evaluator applies.
func TestSerialEvaluatorLocked(t *testing.T) {
	ev := &serialEvaluator{PolicyEvaluator: &recordingEvaluator{}, raw: &recordingEvaluator{}}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		ev.locked(func() { close(entered); <-release })
		close(done)
	}()
	<-entered
	replaced := make(chan struct{})
	go func() { ev.Replace(config.Policy{}); close(replaced) }()
	select {
	case <-replaced:
		t.Fatal("Replace ran while locked() held the lock")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-done
	<-replaced
}

// TestSettingsApplierAcceptIdPTokens: the dispatcher builds the IdP verifier
// only when IdP tokens are accepted, an agent can run with no identity.issuer
// when they are not, and flipping the setting rebuilds the verifier.
func TestSettingsApplierAcceptIdPTokens(t *testing.T) {
	no, yes := false, true
	a, fake, builds, _, _ := identityApplier(t)
	w := a.identity

	fake.settings = &config.SettingsWire{
		Identity: &config.IdentitySettings{DefaultMode: "attribute", AcceptDexTokens: &no},
	}
	a.Apply()
	if w.live.mode != proxy.IdentityModeAttribute || w.live.v == nil {
		t.Fatalf("live = mode %q verifier %v, want attribute with a dispatcher", w.live.mode, w.live.v)
	}
	if _, ok := w.live.v.(*identity.MultiVerifier); !ok {
		t.Fatalf("the live verifier is %T, want the dispatcher", w.live.v)
	}
	if *builds != 0 {
		t.Fatalf("%d IdP verifier builds with IdP tokens refused, want 0", *builds)
	}
	first := w.live.v

	// An IdP token is refused as unbound without any IdP code running.
	idp := "https://idp.example.test"
	fake.settings = &config.SettingsWire{
		Identity: &config.IdentitySettings{DefaultMode: "attribute", Issuer: idp, Audience: "warden", InternalIssuerURL: idp, AcceptDexTokens: &no},
	}
	a.Apply()
	if w.live.v == first {
		t.Fatal("a new issuer did not rebuild the dispatcher")
	}
	if *builds != 0 {
		t.Fatalf("%d IdP builds with acceptDexTokens false", *builds)
	}

	fake.settings = &config.SettingsWire{
		Identity: &config.IdentitySettings{DefaultMode: "attribute", Issuer: idp, Audience: "warden", InternalIssuerURL: idp, AcceptDexTokens: &yes},
	}
	a.Apply()
	if *builds != 1 {
		t.Fatalf("%d IdP builds after enabling IdP tokens, want 1", *builds)
	}
	again := w.live.v
	a.Apply()
	if *builds != 1 || w.live.v != again {
		t.Fatal("an unchanged identity block rebuilt the dispatcher")
	}
}
