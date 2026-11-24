package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// fakeBundleKeys is a bundleKeys with a swappable bundle signer and token
// JWKS. It records every purpose Active was asked for, so a test can prove
// only the bundle purpose ever signs.
type fakeBundleKeys struct {
	mu       sync.Mutex
	signer   keys.Signer
	token    keys.JWKS
	asked    map[string]bool
	subs     []func(string)
	failSign bool
}

func newFakeBundleKeys(t *testing.T) *fakeBundleKeys {
	t.Helper()
	f := &fakeBundleKeys{asked: map[string]bool{}}
	f.rotateBundle(t)
	f.rotateToken(t)
	return f
}

func (f *fakeBundleKeys) rotateBundle(t *testing.T) keys.Signer {
	t.Helper()
	s, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.signer = s
	f.mu.Unlock()
	return s
}

func (f *fakeBundleKeys) rotateToken(t *testing.T) {
	t.Helper()
	s, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(s.Public(), keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.token = keys.JWKS{Keys: []keys.JWK{jwk}}
	f.mu.Unlock()
}

func (f *fakeBundleKeys) Active(purpose string) (keys.Signer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked[purpose] = true
	if purpose != keys.PurposeBundle || f.signer == nil {
		return nil, keys.ErrNoActiveKey
	}
	if f.failSign {
		return failingSigner{f.signer}, nil
	}
	return f.signer, nil
}

func (f *fakeBundleKeys) JWKS(purpose string) keys.JWKS {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch purpose {
	case keys.PurposeToken:
		return f.token
	case keys.PurposeBundle:
		if f.signer == nil {
			return keys.JWKS{}
		}
		jwk, err := keys.PublicJWK(f.signer.Public(), f.signer.Alg())
		if err != nil {
			return keys.JWKS{}
		}
		return keys.JWKS{Keys: []keys.JWK{jwk}}
	}
	return keys.JWKS{}
}

func (f *fakeBundleKeys) Subscribe(fn func(string)) func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = append(f.subs, fn)
	return func() {}
}

// fire delivers a transition of purpose to every subscriber, synchronously.
func (f *fakeBundleKeys) fire(purpose string) {
	f.mu.Lock()
	subs := append([]func(string){}, f.subs...)
	f.mu.Unlock()
	for _, fn := range subs {
		fn(purpose)
	}
}

func (f *fakeBundleKeys) pins() []keys.JWK {
	return f.JWKS(keys.PurposeBundle).Keys
}

type failingSigner struct{ keys.Signer }

func (failingSigner) Sign(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("backend unavailable")
}

type btHarness struct {
	s    *Server
	ps   *policyServer
	fk   *fakeBundleKeys
	clk  *clocktest.Fake
	logs *syncBuf
	db   *cpstate.DB
}

var btStart = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// newBundleHarness boots a versioned Server in the given mode over db (a fresh
// state DB when nil), imports the initial version and starts the publisher
// like Run does.
func newBundleHarness(t *testing.T, mode, policyPath string, db *cpstate.DB, fk *fakeBundleKeys, clk *clocktest.Fake, mod func(*BundlesConfig)) *btHarness {
	t.Helper()
	if db == nil {
		db = openPolicyState(t)
	}
	if fk == nil {
		fk = newFakeBundleKeys(t)
	}
	if clk == nil {
		clk = clocktest.NewFake(btStart)
	}
	bc := BundlesConfig{Mode: mode}
	if mod != nil {
		mod(&bc)
	}
	logs := &syncBuf{}
	s := New(Config{
		PolicyPath:  policyPath,
		State:       db,
		PolicyStore: PolicyStoreVersioned,
		Bundles:     bc,
		bundleKeys:  fk,
		Clock:       clk,
		Logger:      slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &btHarness{s: s, ps: s.policy, fk: fk, clk: clk, logs: logs, db: db}
	if err := s.policy.startBundles(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

type btResp struct {
	code int
	hdr  http.Header
	body []byte
}

func (h *btHarness) get(t *testing.T, accept, inm string) btResp {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/policy", nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if inm != "" {
		req.Header.Set("If-None-Match", inm)
	}
	rec := httptest.NewRecorder()
	h.ps.ServePolicy(rec, req)
	return btResp{code: rec.Code, hdr: rec.Header(), body: rec.Body.Bytes()}
}

func (h *btHarness) bundleResp(t *testing.T) btResp {
	t.Helper()
	r := h.get(t, BundleMediaType, "")
	if r.code != http.StatusOK {
		t.Fatalf("GET /policy (bundle) = %d %s", r.code, r.body)
	}
	return r
}

func (h *btHarness) verify(t *testing.T, raw []byte, applied bundle.State) bundle.Verified {
	t.Helper()
	v, err := bundle.Verify(raw, h.fk.pins(), applied, bundle.Options{Now: h.clk.Now(), Skew: time.Minute})
	if err != nil {
		t.Fatalf("bundle.Verify: %v", err)
	}
	return v
}

func (h *btHarness) latest(t *testing.T) PublishEntry {
	t.Helper()
	e, ok, err := h.ps.versions.LatestPublish(context.Background())
	if err != nil || !ok {
		t.Fatalf("LatestPublish = %v, %v", ok, err)
	}
	return e
}

func (h *btHarness) publishRows(t *testing.T) []PublishEntry {
	t.Helper()
	rows, err := h.ps.versions.PublishLog(context.Background(), 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func btCreateAllow(t *testing.T, h *btHarness, domain string) {
	t.Helper()
	head := mustHead(t, h.ps.versions)
	doc := docWithAllow(baseDoc(t, h.s), domain)
	if _, changed, err := h.ps.versions.Create(context.Background(), doc, testAuthor, "", SourcePolicy, head); err != nil || !changed {
		t.Fatalf("Create = %v, %v", changed, err)
	}
}

func btPayload(t *testing.T, raw []byte) bundle.Bundle {
	t.Helper()
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	p, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var b bundle.Bundle
	if err := json.Unmarshal(p, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func btState(v bundle.Verified) bundle.State {
	return bundle.State{Seq: v.Seq, ContentSHA256: v.ContentSHA256, IssuedAt: v.Bundle.IssuedAt}
}

// TestBundlesOffByteIdentical: with --bundles off (the default, or spelled
// out) GET /policy equals the golden body and ETag captured on main before
// bundles existed, even for a request that asks for the envelope, and the
// bundle tables stay empty.
func TestBundlesOffByteIdentical(t *testing.T) {
	wantBody, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantETag, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.etag"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", BundlesOff} {
		for _, accept := range []string{"", BundleMediaType, "application/json"} {
			db := openPolicyState(t)
			s := New(Config{PolicyPath: overlayFixture(t), State: db, PolicyStore: PolicyStoreVersioned, Bundles: BundlesConfig{Mode: mode}})
			if s.policy.bundlesOn() {
				t.Fatalf("mode %q: publisher built with bundles off", mode)
			}
			if err := s.importInitialVersion(context.Background()); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/policy", nil)
			if accept != "" {
				req.Header.Set("Accept", accept)
			}
			rec := httptest.NewRecorder()
			s.policy.ServePolicy(rec, req)
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), wantBody) {
				t.Errorf("mode %q accept %q: /policy = %d %q, want the golden body", mode, accept, rec.Code, rec.Body.String())
			}
			if got := strings.Trim(rec.Header().Get("ETag"), `"`); got != trimETag(string(wantETag)) {
				t.Errorf("mode %q accept %q: ETag = %q, want %q", mode, accept, got, wantETag)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			var n int
			if err := db.SQL().QueryRow(`SELECT count(*) FROM bundle_state`).Scan(&n); err != nil || n != 0 {
				t.Errorf("bundle_state rows = %d (%v), want none with bundles off", n, err)
			}
		}
	}
}

// TestBundleServeEnvelopeVerifies: an offered envelope verifies against the
// control plane's bundle public key, carries the publish log's newest seq, keeps
// the credential out of the signed payload and in the sidecar, and signs with
// the bundle purpose only.
func TestBundleServeEnvelopeVerifies(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writeCredentialPolicyFile(t), nil, nil, nil, nil)
	r := h.bundleResp(t)
	if ct := r.hdr.Get("Content-Type"); ct != BundleMediaType {
		t.Errorf("Content-Type = %q, want %q", ct, BundleMediaType)
	}
	v := h.verify(t, r.body, bundle.State{})
	if want := h.latest(t).Seq; v.Seq != want {
		t.Errorf("bundle seq = %d, want the newest publish_log seq %d", v.Seq, want)
	}
	if v.Bundle.PolicyVersion != 1 {
		t.Errorf("policyVersion = %d, want 1", v.Bundle.PolicyVersion)
	}
	if v.Credentials == nil || v.Credentials.SecretAccessKey != policyStoreSecret || v.Credentials.AccessKeyID != "AKIAPVER01" {
		t.Errorf("sidecar credentials not carried: %+v", v.Credentials)
	}
	// The signed payload holds no secretAccessKey, no secret value, and no
	// access key id.
	var env bundle.Envelope
	if err := json.Unmarshal(r.body, &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	for _, banned := range []string{policyStoreSecret, "AKIAPVER01", `"secretAccessKey"`} {
		if bytes.Contains(payload, []byte(banned)) {
			t.Errorf("signed payload contains %q", banned)
		}
	}
	if v.Bundle.CredentialsSHA256 == "" {
		t.Error("payload carries no credentialsSha256")
	}
	var wire policyWire
	if err := json.Unmarshal(v.Bundle.Policy, &wire); err != nil || wire.Settings == nil || wire.Settings.Secrets == nil || wire.Settings.Secrets.Region != "us-east-1" {
		t.Errorf("policy lost the credential-free secrets block: %s (%v)", v.Bundle.Policy, err)
	}
	var jwks keys.JWKS
	if err := json.Unmarshal(v.Bundle.Sections[sectionTokenJWKS], &jwks); err != nil || len(jwks.Keys) != 1 {
		t.Errorf("tokenJWKS section = %s (%v), want the token JWKS", v.Bundle.Sections[sectionTokenJWKS], err)
	}
	if v.Bundle.CPID == "" || !strings.HasPrefix(v.Bundle.CPID, "cp_") {
		t.Errorf("cpID = %q", v.Bundle.CPID)
	}
	if !v.Bundle.ExpiresAt.Equal(v.Bundle.IssuedAt.Add(DefaultBundleMaxAge)) {
		t.Errorf("expiresAt = %s, want issuedAt + %s", v.Bundle.ExpiresAt, DefaultBundleMaxAge)
	}
	// Logs name seq, kid and a digest, never the credential.
	logs := h.logs.String()
	if !strings.Contains(logs, `"msg":"bundle signed"`) || !strings.Contains(logs, `"seq":`) || !strings.Contains(logs, `"digest":`) {
		t.Errorf("no bundle signed log line: %s", logs)
	}
	for _, banned := range []string{policyStoreSecret, "AKIAPVER01"} {
		if strings.Contains(logs, banned) {
			t.Errorf("logs contain the credential %q", banned)
		}
	}
	// Only the bundle purpose ever signs.
	h.fk.mu.Lock()
	defer h.fk.mu.Unlock()
	if len(h.fk.asked) != 1 || !h.fk.asked[keys.PurposeBundle] {
		t.Errorf("signers requested for purposes %v, want only bundle", h.fk.asked)
	}
}

// TestBundleNegotiation: the Accept header and the mode pick the format; each
// format answers If-None-Match against its own ETag.
func TestBundleNegotiation(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	legacy := h.get(t, "", "")
	if legacy.code != http.StatusOK || legacy.hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("legacy = %d %s", legacy.code, legacy.hdr.Get("Content-Type"))
	}
	wantLegacyETag := etagFor(mustWire(t, legacy.body))
	if got := strings.Trim(legacy.hdr.Get("ETag"), `"`); got != wantLegacyETag {
		t.Errorf("legacy ETag = %q, want the unchanged content hash %q", got, wantLegacyETag)
	}
	if bytes.Contains(legacy.body, []byte(`"payload"`)) {
		t.Error("legacy body is an envelope")
	}
	for _, accept := range []string{"*/*", "application/json", BundleMediaType + ";q=0", "text/html, application/json;q=0.9"} {
		if r := h.get(t, accept, ""); !bytes.Equal(r.body, legacy.body) {
			t.Errorf("Accept %q did not get the legacy wire: %s", accept, r.body)
		}
	}
	for _, accept := range []string{BundleMediaType, "application/json, " + BundleMediaType + ";q=0.5", strings.ToUpper(BundleMediaType)} {
		if r := h.get(t, accept, ""); !bytes.Contains(r.body, []byte(`"payload"`)) {
			t.Errorf("Accept %q did not get the envelope: %s", accept, r.body)
		}
	}
	env := h.bundleResp(t)
	envETag := env.hdr.Get("ETag")
	if envETag == "" || envETag == legacy.hdr.Get("ETag") {
		t.Fatalf("envelope ETag %q must be its own (legacy %q)", envETag, legacy.hdr.Get("ETag"))
	}
	if r := h.get(t, BundleMediaType, envETag); r.code != http.StatusNotModified {
		t.Errorf("envelope If-None-Match = %d, want 304", r.code)
	}
	if r := h.get(t, "", legacy.hdr.Get("ETag")); r.code != http.StatusNotModified {
		t.Errorf("legacy If-None-Match = %d, want 304", r.code)
	}
	// Each ETag is only good for its own format.
	if r := h.get(t, BundleMediaType, legacy.hdr.Get("ETag")); r.code != http.StatusOK {
		t.Errorf("envelope request with the legacy ETag = %d, want 200", r.code)
	}
	if r := h.get(t, "", envETag); r.code != http.StatusOK {
		t.Errorf("legacy request with the envelope ETag = %d, want 200", r.code)
	}
	// Method and auth are still the old handler's.
	rec := httptest.NewRecorder()
	h.ps.ServePolicy(rec, httptest.NewRequest(http.MethodPost, "/policy", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", rec.Code)
	}
}

func mustWire(t *testing.T, body []byte) policyWire {
	t.Helper()
	var w policyWire
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

// TestBundleNegotiationRequire: require answers a request without the header
// with 406 and the fixed error, and still serves the envelope.
func TestBundleNegotiationRequire(t *testing.T) {
	h := newBundleHarness(t, BundlesRequire, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	for _, accept := range []string{"", "application/json", "*/*"} {
		r := h.get(t, accept, "")
		if r.code != http.StatusNotAcceptable || strings.TrimSpace(string(r.body)) != `{"error":"signed_bundle_required"}` {
			t.Errorf("Accept %q = %d %s, want 406 signed_bundle_required", accept, r.code, r.body)
		}
		if r.hdr.Get("Content-Type") != "application/json" {
			t.Errorf("406 Content-Type = %q", r.hdr.Get("Content-Type"))
		}
	}
	if r := h.get(t, "", "anything"); r.code != http.StatusNotAcceptable {
		t.Errorf("legacy conditional request = %d, want 406", r.code)
	}
	if r := h.bundleResp(t); !bytes.Contains(r.body, []byte(`"payload"`)) {
		t.Error("require did not serve the envelope")
	}
}

// TestBundleNegotiationWorkerAuth: the 406 and the envelope sit behind the
// worker authentication; an unauthenticated request never learns the mode.
func TestBundleNegotiationWorkerAuth(t *testing.T) {
	db := openPolicyState(t)
	fk := newFakeBundleKeys(t)
	s := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), State: db, PolicyStore: PolicyStoreVersioned,
		Bundles: BundlesConfig{Mode: BundlesRequire}, bundleKeys: fk, Token: "s3cret",
		Clock: clocktest.NewFake(btStart),
	})
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.policy.startBundles(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, accept := range []string{"", BundleMediaType} {
		req := httptest.NewRequest(http.MethodGet, "/policy", nil)
		req.Header.Set("Accept", accept)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Accept %q without a token = %d, want 401", accept, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/policy", nil)
	req.Header.Set("Accept", BundleMediaType)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("authenticated envelope request = %d", rec.Code)
	}
}

// TestBundleServeLongPollWakes: a held request for either format returns the
// moment its format changes, against that format's ETag.
func TestBundleServeLongPollWakes(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	env := h.bundleResp(t)
	etag := env.hdr.Get("ETag")
	legacy := h.get(t, "", "")

	type result struct {
		r  btResp
		at time.Time
	}
	hold := func(accept, inm string) chan result {
		out := make(chan result, 1)
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/policy?wait=30s", nil)
			req.Header.Set("Accept", accept)
			req.Header.Set("If-None-Match", inm)
			rec := httptest.NewRecorder()
			h.ps.ServePolicy(rec, req)
			out <- result{btResp{rec.Code, rec.Header(), rec.Body.Bytes()}, time.Now()}
		}()
		return out
	}
	envWait := hold(BundleMediaType, etag)
	legacyWait := hold("", legacy.hdr.Get("ETag"))
	time.Sleep(50 * time.Millisecond) // both parked (a wake before the park is served by the re-check anyway)
	start := time.Now()
	btCreateAllow(t, h, "new.example.com")
	for name, ch := range map[string]chan result{"envelope": envWait, "legacy": legacyWait} {
		select {
		case res := <-ch:
			if res.r.code != http.StatusOK || res.at.Sub(start) > time.Second {
				t.Errorf("%s waiter = %d after %s, want 200 within 1s", name, res.r.code, res.at.Sub(start))
			}
			if name == "envelope" {
				if h.verify(t, res.r.body, bundle.State{}).Seq != h.latest(t).Seq {
					t.Error("woken envelope is not the newest seq")
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waiter not woken", name)
		}
	}
}

// TestBundleSeqFromPublishLog: block-list changes, rollbacks and token key
// changes each move the seq forward; a bundle key change and an idle refresh
// do not; and the seq always equals the newest publish_log row.
func TestBundleSeqFromPublishLog(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	cur := h.verify(t, h.bundleResp(t).body, bundle.State{})
	seqNow := func() bundle.Verified {
		t.Helper()
		v := h.verify(t, h.bundleResp(t).body, bundle.State{})
		if v.Seq != h.latest(t).Seq {
			t.Fatalf("bundle seq %d != newest publish_log seq %d", v.Seq, h.latest(t).Seq)
		}
		return v
	}
	moved := func(what string) {
		t.Helper()
		next := seqNow()
		if next.Seq <= cur.Seq {
			t.Fatalf("%s: seq %d -> %d, want higher", what, cur.Seq, next.Seq)
		}
		cur = next
	}

	// A block-list change.
	if _, err := h.s.blocks.Add(context.Background(), BlockEntry{Email: "alice@corp.com"}, "cli:tester"); err != nil {
		t.Fatal(err)
	}
	moved("block list change")
	if !strings.Contains(string(cur.Bundle.Policy), "alice@corp.com") {
		t.Errorf("block list missing from the signed policy: %s", cur.Bundle.Policy)
	}

	// A policy save, then a rollback to the first version: the rollback is a new
	// head version, so its seq moves forward even though the content is old.
	btCreateAllow(t, h, "two.example.com")
	moved("policy save")
	v1, err := h.ps.versions.Get(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	head := mustHead(t, h.ps.versions)
	if _, changed, err := h.ps.versions.Create(context.Background(), v1.Doc, testAuthor, "rollback", SourceRollback, head); err != nil || !changed {
		t.Fatalf("rollback Create = %v, %v", changed, err)
	}
	moved("policy rollback")

	// Idle: nothing changed, nothing re-signs, no new row.
	rowsBefore := len(h.publishRows(t))
	etagBefore := h.bundleResp(t).hdr.Get("ETag")
	h.ps.Refresh()
	if got := h.bundleResp(t).hdr.Get("ETag"); got != etagBefore || len(h.publishRows(t)) != rowsBefore {
		t.Error("a Refresh with nothing changed re-signed or appended a row")
	}

	// A token key change appends a token_jwks row, moves the seq and wakes a
	// held bundle request within a second.
	held := make(chan btResp, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/policy?wait=30s", nil)
		req.Header.Set("Accept", BundleMediaType)
		req.Header.Set("If-None-Match", etagBefore)
		rec := httptest.NewRecorder()
		h.ps.ServePolicy(rec, req)
		held <- btResp{rec.Code, rec.Header(), rec.Body.Bytes()}
	}()
	time.Sleep(50 * time.Millisecond)
	h.fk.rotateToken(t)
	start := time.Now()
	h.fk.fire(keys.PurposeToken)
	select {
	case r := <-held:
		if r.code != http.StatusOK || time.Since(start) > time.Second {
			t.Errorf("held request = %d after %s, want 200 within 1s", r.code, time.Since(start))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("token rotation did not wake the long poll")
	}
	moved("token key change")
	if rows := h.publishRows(t); rows[len(rows)-1].Reason != publishReasonTokenJWKS {
		t.Errorf("newest row reason = %q, want %q", rows[len(rows)-1].Reason, publishReasonTokenJWKS)
	}
	var jwks keys.JWKS
	_ = json.Unmarshal(cur.Bundle.Sections[sectionTokenJWKS], &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != h.fk.token.Keys[0].Kid {
		t.Errorf("tokenJWKS does not carry the new token key")
	}
	// A second token event with no change appends nothing.
	rows := len(h.publishRows(t))
	h.fk.fire(keys.PurposeToken)
	if len(h.publishRows(t)) != rows {
		t.Error("a token event with an unchanged JWKS appended a row")
	}

	// A bundle key change re-signs the same seq and content: a refresh.
	oldKID := h.fk.signer.KID()
	h.fk.rotateBundle(t)
	rows = len(h.publishRows(t))
	h.fk.fire(keys.PurposeBundle)
	if len(h.publishRows(t)) != rows {
		t.Error("a bundle key change appended a publish_log row")
	}
	// The old pin is gone from the fake, so verify against the new key and
	// check the refresh semantics against the previously applied state.
	next := h.verify(t, h.bundleResp(t).body, btState(cur))
	if next.Seq != cur.Seq || next.ContentSHA256 != cur.ContentSHA256 || !next.Refresh || next.KID == oldKID {
		t.Errorf("bundle key change: seq %d content same=%v refresh=%v kid %s (old %s), want a refresh by the new key",
			next.Seq, next.ContentSHA256 == cur.ContentSHA256, next.Refresh, next.KID, oldKID)
	}
}

// TestBundleSeqPersistsAcrossRestart: a restart on the same state keeps the
// control plane id and the seq, and the first envelope after it is a refresh
// of the one before, never an equivocation; a token JWKS change made while
// the control plane was down takes a row of its own at the next start.
func TestBundleSeqPersistsAcrossRestart(t *testing.T) {
	db := openPolicyState(t)
	fk := newFakeBundleKeys(t)
	path := writePolicyFile(t, "api.openai.com")
	clk := clocktest.NewFake(btStart)
	h1 := newBundleHarness(t, BundlesOffer, path, db, fk, clk, nil)
	v1 := h1.verify(t, h1.bundleResp(t).body, bundle.State{})
	clk.Advance(time.Minute)

	h2 := newBundleHarness(t, BundlesOffer, path, db, fk, clk, nil)
	v2 := h2.verify(t, h2.bundleResp(t).body, btState(v1))
	if v2.Bundle.CPID != v1.Bundle.CPID {
		t.Errorf("cpID changed across a restart: %s -> %s", v1.Bundle.CPID, v2.Bundle.CPID)
	}
	if v2.Seq != v1.Seq || v2.ContentSHA256 != v1.ContentSHA256 || !v2.Refresh {
		t.Errorf("restart: seq %d -> %d, refresh=%v, want the same seq as a refresh", v1.Seq, v2.Seq, v2.Refresh)
	}

	// A token key rotated while down.
	fk.rotateToken(t)
	clk.Advance(time.Minute)
	h3 := newBundleHarness(t, BundlesOffer, path, db, fk, clk, nil)
	v3 := h3.verify(t, h3.bundleResp(t).body, btState(v2))
	if v3.Seq <= v2.Seq {
		t.Errorf("a token JWKS change during downtime kept seq %d (was %d)", v3.Seq, v2.Seq)
	}
	if rows := h3.publishRows(t); rows[len(rows)-1].Reason != publishReasonTokenJWKS {
		t.Errorf("newest row = %q, want token_jwks", rows[len(rows)-1].Reason)
	}
}

// TestBundleSignFailureKeepsLast: with no bundle key (ErrNoActiveKey) or a
// failing backend, /policy keeps serving the last envelope, /healthz reports
// degraded and the log names the seq; a recovered key clears it.
func TestBundleSignFailureKeepsLast(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	first := h.bundleResp(t)
	health := func() string {
		rec := httptest.NewRecorder()
		h.s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/healthz = %d", rec.Code)
		}
		return rec.Body.String()
	}
	if health() != "ok\n" {
		t.Fatalf("healthz before = %q", health())
	}

	h.fk.mu.Lock()
	good := h.fk.signer
	h.fk.signer = nil // ErrNoActiveKey
	h.fk.mu.Unlock()
	btCreateAllow(t, h, "later.example.com")
	if got := h.bundleResp(t); !bytes.Equal(got.body, first.body) || got.hdr.Get("ETag") != first.hdr.Get("ETag") {
		t.Error("with no active bundle key /policy did not keep the last envelope")
	}
	if !strings.Contains(health(), "degraded") {
		t.Errorf("healthz = %q, want degraded", health())
	}
	if !strings.Contains(h.logs.String(), "bundle sign failed") {
		t.Errorf("no bundle sign failed log: %s", h.logs.String())
	}
	// The legacy wire is not held back by the bundle outage.
	if r := h.get(t, "", ""); !bytes.Contains(r.body, []byte("later.example.com")) {
		t.Error("legacy wire stopped updating while bundle signing failed")
	}

	// A signer whose backend fails: same.
	h.fk.mu.Lock()
	h.fk.signer, h.fk.failSign = good, true
	h.fk.mu.Unlock()
	h.fk.fire(keys.PurposeBundle)
	if got := h.bundleResp(t); !bytes.Equal(got.body, first.body) {
		t.Error("with a failing signer /policy did not keep the last envelope")
	}
	if !strings.Contains(h.logs.String(), `"kid":"`+good.KID()+`"`) {
		t.Errorf("sign failure log names no kid: %s", h.logs.String())
	}

	// Recovery signs the newest content and clears the flag.
	h.fk.mu.Lock()
	h.fk.failSign = false
	h.fk.mu.Unlock()
	h.fk.fire(keys.PurposeBundle)
	if health() != "ok\n" {
		t.Errorf("healthz after recovery = %q", health())
	}
	if v := h.verify(t, h.bundleResp(t).body, bundle.State{}); v.Seq != h.latest(t).Seq {
		t.Errorf("recovered bundle seq %d, want %d", v.Seq, h.latest(t).Seq)
	}
}

// TestBundleSignFailureNoEnvelope: with no envelope ever signed, an opted-in
// request gets 503 while a legacy one still gets the policy.
func TestBundleSignFailureNoEnvelope(t *testing.T) {
	fk := newFakeBundleKeys(t)
	fk.failSign = true
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, fk, nil, nil)
	r := h.get(t, BundleMediaType, "")
	if r.code != http.StatusServiceUnavailable || strings.TrimSpace(string(r.body)) != `{"error":"signed_bundle_unavailable"}` || r.hdr.Get("Retry-After") == "" {
		t.Errorf("no envelope = %d %s, want 503 signed_bundle_unavailable", r.code, r.body)
	}
	if r := h.get(t, "", ""); r.code != http.StatusOK {
		t.Errorf("legacy request = %d, want 200", r.code)
	}
	if !h.ps.bundleDegraded() {
		t.Error("not degraded")
	}
}

// TestBundleSignFailureOversize: an envelope over 4 MiB is not published, the
// previous one stays, and the log carries the error.
func TestBundleSignFailureOversize(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	first := h.bundleResp(t)
	doc := baseDoc(t, h.s)
	for i := range 60000 {
		doc.Allowlist = append(doc.Allowlist, config.AllowlistEntry{Domain: "host-" + strings.Repeat("x", 60) + "-" + string(rune('a'+i%26)) + hex.EncodeToString([]byte{byte(i), byte(i >> 8), byte(i >> 16)}) + ".example.com"})
	}
	head := mustHead(t, h.ps.versions)
	if _, changed, err := h.ps.versions.Create(context.Background(), doc, testAuthor, "", SourcePolicy, head); err != nil || !changed {
		t.Fatalf("Create = %v, %v", changed, err)
	}
	if got := h.bundleResp(t); !bytes.Equal(got.body, first.body) {
		t.Error("an oversized envelope replaced the last one")
	}
	if !strings.Contains(h.logs.String(), "bundle too large") || !h.ps.bundleDegraded() {
		t.Errorf("oversize not reported: degraded=%v logs=%s", h.ps.bundleDegraded(), h.logs.String())
	}
}

// TestBundleResign: the ticker re-signs the unchanged content every
// max-age/4 with the same seq and a newer issuedAt (a refresh for a worker),
// and an envelope past its expiry is no longer served.
func TestBundleResign(t *testing.T) {
	clk := clocktest.NewFake(btStart)
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, clk, func(c *BundlesConfig) { c.MaxAge = 4 * time.Hour })
	first := h.verify(t, h.bundleResp(t).body, bundle.State{})
	firstETag := h.bundleResp(t).hdr.Get("ETag")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.ps.resignLoop(ctx, clk); close(done) }()
	defer func() { cancel(); <-done }()

	// Drive the loop by condition: advance an hour until the envelope changes.
	deadline := time.Now().Add(10 * time.Second)
	for h.bundleResp(t).hdr.Get("ETag") == firstETag {
		if time.Now().After(deadline) {
			t.Fatal("the ticker never re-signed")
		}
		if clk.PendingTimers() > 0 {
			clk.Advance(time.Hour)
		}
		time.Sleep(5 * time.Millisecond)
	}
	next := h.verify(t, h.bundleResp(t).body, btState(first))
	if next.Seq != first.Seq || next.ContentSHA256 != first.ContentSHA256 || !next.Refresh {
		t.Errorf("re-sign: seq %d -> %d refresh=%v, want the same seq as a refresh", first.Seq, next.Seq, next.Refresh)
	}
	if !next.Bundle.IssuedAt.After(first.Bundle.IssuedAt) || !next.Bundle.ExpiresAt.After(first.Bundle.ExpiresAt) {
		t.Errorf("re-sign did not move the freshness window: %s/%s -> %s/%s",
			first.Bundle.IssuedAt, first.Bundle.ExpiresAt, next.Bundle.IssuedAt, next.Bundle.ExpiresAt)
	}
	if n := len(h.publishRows(t)); n != 1 {
		t.Errorf("re-signing appended publish_log rows: %d, want 1", n)
	}

	// Stop the loop and let the envelope age out: it is not served expired.
	cancel()
	<-done
	clk.Advance(5 * time.Hour)
	if r := h.get(t, BundleMediaType, ""); r.code != http.StatusServiceUnavailable {
		t.Errorf("an expired envelope was served: %d", r.code)
	}
	if r := h.get(t, "", ""); r.code != http.StatusOK {
		t.Errorf("legacy request after the envelope expired = %d", r.code)
	}
}

// TestBundleSeqFloor: --bundle-seq-floor appends one restore row at the floor
// when the log is below it, the first envelope carries that seq, later changes
// go above it, and a floor at or below the log appends nothing.
func TestBundleSeqFloor(t *testing.T) {
	db := openPolicyState(t)
	fk := newFakeBundleKeys(t)
	path := writePolicyFile(t, "api.openai.com")
	h := newBundleHarness(t, BundlesOffer, path, db, fk, nil, func(c *BundlesConfig) { c.SeqFloor = 100 })
	e := h.latest(t)
	if e.Seq != 100 || e.Reason != publishReasonRestore {
		t.Fatalf("newest row = seq %d reason %q, want seq 100 restore", e.Seq, e.Reason)
	}
	if v := h.verify(t, h.bundleResp(t).body, bundle.State{}); v.Seq != 100 {
		t.Errorf("envelope seq = %d, want 100", v.Seq)
	}
	btCreateAllow(t, h, "after.example.com")
	if v := h.verify(t, h.bundleResp(t).body, bundle.State{}); v.Seq != 101 {
		t.Errorf("seq after the floor = %d, want 101", v.Seq)
	}
	rows := len(h.publishRows(t))
	h2 := newBundleHarness(t, BundlesOffer, path, db, fk, nil, func(c *BundlesConfig) { c.SeqFloor = 50 })
	if len(h2.publishRows(t)) != rows {
		t.Error("a floor below the log appended a row")
	}
	h3 := newBundleHarness(t, BundlesOffer, path, db, fk, nil, func(c *BundlesConfig) { c.SeqFloor = 101 })
	if len(h3.publishRows(t)) != rows {
		t.Error("a floor equal to the newest seq appended a row")
	}
}

// TestBundleStartupChecks: offer and require refuse to start without their
// prerequisites, naming each missing piece and the flag.
func TestBundleStartupChecks(t *testing.T) {
	enabled := config.KeysConfig{Enabled: true}
	cases := []struct {
		name        string
		p           Params
		stateDir    string
		store       string
		kc          config.KeysConfig
		wantErr     []string
		wantNoError bool
	}{
		{name: "off needs nothing", p: Params{}, wantNoError: true},
		{name: "explicit off", p: Params{Bundles: "off"}, wantNoError: true},
		{name: "offer ok", p: Params{Bundles: "offer"}, stateDir: "/s", store: PolicyStoreVersioned, kc: enabled, wantNoError: true},
		{name: "require ok", p: Params{Bundles: "require", BundleMaxAge: time.Hour}, stateDir: "/s", store: PolicyStoreVersioned, kc: enabled, wantNoError: true},
		{name: "offer file store", p: Params{Bundles: "offer"}, stateDir: "/s", store: PolicyStoreFile, kc: enabled, wantErr: []string{"--bundles=offer", "--policy-store=versioned"}},
		{name: "offer no state dir", p: Params{Bundles: "offer"}, store: PolicyStoreVersioned, kc: enabled, wantErr: []string{"--state-dir"}},
		{name: "require no keys", p: Params{Bundles: "require"}, stateDir: "/s", store: PolicyStoreVersioned, wantErr: []string{"--bundles=require", "keys.enabled"}},
		{name: "everything missing", p: Params{Bundles: "offer"}, wantErr: []string{"--state-dir", "--policy-store=versioned", "keys.enabled"}},
		{name: "bad mode", p: Params{Bundles: "yes"}, wantErr: []string{"--bundles", `"yes"`}},
		{name: "short max age", p: Params{Bundles: "offer", BundleMaxAge: time.Minute}, stateDir: "/s", store: PolicyStoreVersioned, kc: enabled, wantErr: []string{"--bundle-max-age"}},
		{name: "negative floor", p: Params{BundleSeqFloor: -1}, wantErr: []string{"--bundle-seq-floor"}},
	}
	for _, tc := range cases {
		_, err := resolveBundles(tc.p, tc.stateDir, tc.store, tc.kc)
		if tc.wantNoError {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: no error", tc.name)
			continue
		}
		for _, w := range tc.wantErr {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q does not name %q", tc.name, err, w)
			}
		}
	}
}

// TestBundleRunRefusesOfferWithoutVersioned: Run itself stops, before it
// listens, naming both flags.
func TestBundleRunRefusesOfferWithoutVersioned(t *testing.T) {
	err := bootErr(t, Params{
		ConfigPath: writeKeysPolicy(t, keysEnabledYAML), StateDir: filepath.Join(t.TempDir(), "state"),
		Bundles: BundlesOffer, PolicyStore: PolicyStoreFile,
	})
	if !strings.Contains(err.Error(), "--bundles=offer") || !strings.Contains(err.Error(), "--policy-store=versioned") {
		t.Errorf("error = %q, want it to name --bundles=offer and --policy-store=versioned", err)
	}
}

// TestBundlePayloadDigestIsPrefixOnly: the log digest is 16 hex and reveals
// nothing of the payload.
func TestBundlePayloadDigestIsPrefixOnly(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	r := h.bundleResp(t)
	var env bundle.Envelope
	_ = json.Unmarshal(r.body, &env)
	raw, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:8])
	if got := payloadDigest(r.body); got != want || len(got) != 16 {
		t.Errorf("digest = %q, want %q", got, want)
	}
	if b := btPayload(t, r.body); b.Seq < 1 {
		t.Errorf("decoded seq = %d", b.Seq)
	}
}
