package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

var bundleT0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

const (
	bundlePolicyA = `{"allowlist":[{"domain":"a.example.com"}]}`
	bundlePolicyB = `{"allowlist":[{"domain":"b.example.com"}]}`
)

// signedCP is a control plane stand-in that serves whatever envelope the test
// set, and records each request's Accept and If-None-Match headers.
type signedCP struct {
	mu     sync.Mutex
	body   []byte
	etag   string
	accept []string
	inm    []string
	hbs    [][]byte // heartbeat bodies, oldest first
	srv    *httptest.Server
}

func newSignedCP(t *testing.T) *signedCP {
	t.Helper()
	c := &signedCP{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.URL.Path == "/control/heartbeat" {
			b, _ := io.ReadAll(r.Body)
			c.hbs = append(c.hbs, b)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		c.accept = append(c.accept, r.Header.Get("Accept"))
		c.inm = append(c.inm, r.Header.Get("If-None-Match"))
		if c.etag != "" && r.Header.Get("If-None-Match") == `"`+c.etag+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if c.etag != "" {
			w.Header().Set("ETag", `"`+c.etag+`"`)
		}
		_, _ = w.Write(c.body)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *signedCP) serve(body []byte, etag string) {
	c.mu.Lock()
	c.body, c.etag = body, etag
	c.mu.Unlock()
}

func (c *signedCP) lastINM() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inm[len(c.inm)-1]
}

type bundleEnv struct {
	t    *testing.T
	cp   *signedCP
	rp   *RemoteProvider
	sg   *signer.LocalSigner
	now  time.Time
	logs *bytes.Buffer
}

func newBundleEnv(t *testing.T) *bundleEnv {
	t.Helper()
	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	e := &bundleEnv{t: t, cp: newSignedCP(t), sg: sg, now: bundleT0.Add(time.Minute), logs: &bytes.Buffer{}}
	rp, err := NewRemoteProvider(e.cp.srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	rp.client, rp.longClient = e.cp.srv.Client(), e.cp.srv.Client()
	if err := rp.SetBundleTrust(BundleTrust{
		Pins: []keys.JWK{pin}, Skew: 5 * time.Minute, Expiry: BundleExpiryKeep,
		Now:    func() time.Time { return e.now },
		Logger: slog.New(slog.NewTextHandler(e.logs, nil)),
	}); err != nil {
		t.Fatal(err)
	}
	e.rp = rp
	return e
}

func (e *bundleEnv) bundle(seq int64, policy string) bundle.Bundle {
	return bundle.Bundle{
		Seq: seq, PolicyVersion: seq, IssuedAt: bundleT0, ExpiresAt: bundleT0.Add(24 * time.Hour),
		CPID: "cp-1", Policy: json.RawMessage(policy),
		Sections: map[string]json.RawMessage{BundleSectionTokenJWKS: json.RawMessage(`{"keys":[]}`)},
	}
}

func (e *bundleEnv) sign(b bundle.Bundle, c *bundle.Credentials) []byte {
	e.t.Helper()
	raw, err := bundle.Sign(context.Background(), b, c, e.sg)
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

// serveSeq signs and serves a bundle and pulls it.
func (e *bundleEnv) pullSeq(seq int64, policy, etag string) error {
	e.cp.serve(e.sign(e.bundle(seq, policy), nil), etag)
	return e.rp.Pull()
}

func (e *bundleEnv) allowed() []string {
	e.t.Helper()
	p, err := e.rp.GetPolicy()
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, a := range p.Allowlist {
		out = append(out, a.Domain)
	}
	return out
}

func flipPayloadByte(t *testing.T, raw []byte) []byte {
	t.Helper()
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	b := []byte(env.Payload)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	env.Payload = string(b)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRemoteProviderSignedBundleTamper(t *testing.T) {
	e := newBundleEnv(t)
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatalf("seq 5: %v", err)
	}
	e.cp.serve(flipPayloadByte(t, e.sign(e.bundle(6, bundlePolicyB), nil)), "e6bad")
	err := e.rp.Pull()
	if !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("tampered bundle: err = %v, want ErrBadSignature", err)
	}
	if got := e.allowed(); len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("policy after a rejection = %v, want the seq 5 policy", got)
	}
	if b, ok := e.rp.Bundle(); !ok || b.Seq != 5 {
		t.Fatalf("Bundle() = %+v, %v, want seq 5", b, ok)
	}
	// The next long-poll carries the rejected ETag, and the CP answers 304.
	changed, err := e.rp.PollLong(context.Background(), time.Millisecond)
	if err != nil || changed {
		t.Fatalf("PollLong = %v, %v, want unchanged", changed, err)
	}
	if got := e.cp.lastINM(); got != `"e6bad"` {
		t.Fatalf("If-None-Match = %s, want the rejected ETag", got)
	}
	// The heartbeat still reports the applied policy, not the rejected one.
	if e.rp.etag != "e5" {
		t.Fatalf("applied etag = %q, want e5", e.rp.etag)
	}
	st := e.rp.BundleStatus()
	if st.LastRejectReason != "bad_signature" || st.Rejected["bad_signature"] != 1 || st.Seq != 5 {
		t.Fatalf("status = %+v", st)
	}
}

func TestRemoteProviderSignedBundleRollbackAndEquivocation(t *testing.T) {
	e := newBundleEnv(t)
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}
	if err := e.pullSeq(4, bundlePolicyB, "e4"); !errors.Is(err, bundle.ErrRollback) {
		t.Fatalf("seq 4: err = %v, want ErrRollback", err)
	}
	if err := e.pullSeq(5, bundlePolicyB, "e5b"); !errors.Is(err, bundle.ErrEquivocation) {
		t.Fatalf("different seq 5: err = %v, want ErrEquivocation", err)
	}
	if got := e.allowed(); len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("policy changed after rejections: %v", got)
	}
	if err := e.pullSeq(6, bundlePolicyB, "e6"); err != nil {
		t.Fatalf("seq 6: %v", err)
	}
	if got := e.allowed(); got[0] != "b.example.com" {
		t.Fatalf("policy = %v, want seq 6", got)
	}
	if st := e.rp.BundleStatus(); st.LastRejectReason != "" || st.Seq != 6 {
		t.Fatalf("a successful apply must clear the last reject: %+v", st)
	}
}

func TestRemoteProviderSignedBundleRejectsUnsignedAndOversize(t *testing.T) {
	e := newBundleEnv(t)
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}
	// The legacy wire is never applied once pins are set.
	e.cp.serve([]byte(bundlePolicyB), "legacy")
	if err := e.rp.Pull(); !errors.Is(err, bundle.ErrUnsigned) {
		t.Fatalf("legacy wire: err = %v, want ErrUnsigned", err)
	}
	e.cp.serve(bytes.Repeat([]byte("x"), bundle.MaxEnvelopeBytes+1), "big")
	if err := e.rp.Pull(); !errors.Is(err, bundle.ErrTooLarge) {
		t.Fatalf("4 MiB + 1 byte: err = %v, want ErrTooLarge", err)
	}
	if got := e.allowed(); got[0] != "a.example.com" {
		t.Fatalf("policy changed: %v", got)
	}
	// Before any bundle, a legacy wire leaves the worker with no policy at all.
	f := newBundleEnv(t)
	f.cp.serve([]byte(bundlePolicyA), "legacy")
	if err := f.rp.Pull(); !errors.Is(err, bundle.ErrUnsigned) {
		t.Fatalf("legacy first: err = %v", err)
	}
	if _, err := f.rp.GetPolicy(); err == nil {
		t.Fatal("a legacy wire was applied under pins")
	}
	if _, ok := f.rp.Bundle(); ok {
		t.Fatal("Bundle() ok with nothing verified")
	}
}

func TestRemoteProviderSignedBundleCredentials(t *testing.T) {
	e := newBundleEnv(t)
	creds := &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s3cr3t-value"}
	pol := `{"allowlist":[{"domain":"a.example.com"}],"settings":{"secrets":{"backend":"aws","region":"us-east-1"}}}`
	e.cp.serve(e.sign(e.bundle(1, pol), creds), "c1")
	if err := e.rp.Pull(); err != nil {
		t.Fatal(err)
	}
	s := e.rp.Settings()
	if s == nil || s.Secrets == nil || s.Secrets.AccessKeyID != "AKIAEXAMPLE" || s.Secrets.SecretAccessKey != "s3cr3t-value" || s.Secrets.Backend != "aws" {
		t.Fatalf("settings secrets = %+v, want the sidecar merged in", s)
	}
	if strings.Contains(e.logs.String(), "s3cr3t-value") || strings.Contains(e.logs.String(), "AKIAEXAMPLE") {
		t.Fatalf("credential in logs: %s", e.logs)
	}

	// A sidecar that does not match credentialsSha256 is a rejection.
	g := newBundleEnv(t)
	good := g.sign(g.bundle(1, pol), creds)
	var env bundle.Envelope
	if err := json.Unmarshal(good, &env); err != nil {
		t.Fatal(err)
	}
	env.Credentials = &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "other-value"}
	bad, _ := json.Marshal(env)
	g.cp.serve(bad, "c2")
	if err := g.rp.Pull(); !errors.Is(err, bundle.ErrCredentialMismatch) {
		t.Fatalf("err = %v, want ErrCredentialMismatch", err)
	}
	if strings.Contains(g.logs.String(), "other-value") {
		t.Fatalf("credential in logs: %s", g.logs)
	}
	if g.rp.Settings() != nil {
		t.Fatal("settings applied from a rejected bundle")
	}
}

func TestRemoteProviderSignedBundleInvalidPolicyKeepsLastKnownGood(t *testing.T) {
	e := newBundleEnv(t)
	ok := `{"allowlist":[{"domain":"a.example.com"}],"registeredAgents":[{"id":"agent-a","status":"disabled","jkt":["` + strings.Repeat("A", 43) + `"]}]}`
	if err := e.pullSeq(1, ok, "e1"); err != nil {
		t.Fatal(err)
	}
	// Validly signed, but the list is one this worker cannot validate (status
	// "paused"): the whole wire is rejected, so the disabled agent stays.
	bad := `{"allowlist":[{"domain":"b.example.com"}],"registeredAgents":[{"id":"agent-a","status":"paused","jkt":["` + strings.Repeat("A", 43) + `"]}]}`
	if err := e.pullSeq(2, bad, "e2"); err == nil {
		t.Fatal("an invalid registeredAgents list was applied")
	}
	p, _ := e.rp.GetPolicy()
	if len(p.RegisteredAgents) != 1 || p.RegisteredAgents[0].Status != RegisteredAgentDisabled || p.Allowlist[0].Domain != "a.example.com" {
		t.Fatalf("policy after rejection = %+v", p)
	}
	if st := e.rp.BundleStatus(); st.LastRejectReason != BundleReasonInvalidPolicy || st.Seq != 1 {
		t.Fatalf("status = %+v", st)
	}
	if _, err := e.rp.PollLong(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := e.cp.lastINM(); got != `"e2"` {
		t.Fatalf("If-None-Match = %s, want the rejected ETag", got)
	}
}

func TestRemoteProviderSignedBundleRefreshAndUnchanged(t *testing.T) {
	e := newBundleEnv(t)
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}
	// Identical re-delivery: not a rejection, nothing changes.
	e.cp.serve(e.sign(e.bundle(5, bundlePolicyA), nil), "e5-again")
	changed, err := e.rp.PollLong(context.Background(), time.Millisecond)
	if err != nil || changed {
		t.Fatalf("identical re-delivery = %v, %v", changed, err)
	}
	// Same content, newer issuedAt: the validity window moves, the policy does
	// not (changed=false, so the worker does not rebuild anything).
	nb := e.bundle(5, bundlePolicyA)
	nb.IssuedAt = bundleT0.Add(time.Hour)
	nb.ExpiresAt = bundleT0.Add(25 * time.Hour)
	e.now = bundleT0.Add(2 * time.Hour)
	e.cp.serve(e.sign(nb, nil), "e5-refresh")
	changed, err = e.rp.PollLong(context.Background(), time.Millisecond)
	if err != nil || changed {
		t.Fatalf("refresh = %v, %v, want unchanged", changed, err)
	}
	if b, _ := e.rp.Bundle(); !b.ExpiresAt.Equal(bundleT0.Add(25 * time.Hour)) {
		t.Fatalf("refresh did not move expiresAt: %v", b.ExpiresAt)
	}
}

func TestRemoteProviderSignedBundleFutureIsRetried(t *testing.T) {
	e := newBundleEnv(t)
	e.now = bundleT0.Add(-time.Hour) // worker clock far behind
	if err := e.pullSeq(1, bundlePolicyA, "e1"); !errors.Is(err, bundle.ErrFuture) {
		t.Fatalf("err = %v, want ErrFuture", err)
	}
	if _, err := e.rp.PollLong(context.Background(), time.Millisecond); !errors.Is(err, bundle.ErrFuture) {
		t.Fatalf("a future bundle must be fetched again: err = %v", err)
	}
	if got := e.cp.lastINM(); got != "" {
		t.Fatalf("If-None-Match = %s, want none for a time-dependent rejection", got)
	}
	e.now = bundleT0.Add(time.Minute)
	if changed, err := e.rp.PollLong(context.Background(), time.Millisecond); err != nil || !changed {
		t.Fatalf("after the clock caught up: %v, %v", changed, err)
	}
}

func TestRemoteProviderSignedBundleBundleAccessorAndStatus(t *testing.T) {
	e := newBundleEnv(t)
	if st := e.rp.BundleStatus(); !st.Enabled || st.Applied {
		t.Fatalf("status before apply = %+v", st)
	}
	if err := e.pullSeq(7, bundlePolicyA, "e7"); err != nil {
		t.Fatal(err)
	}
	b, ok := e.rp.Bundle()
	if !ok || b.Seq != 7 || b.KID != e.sg.KID() || b.CPID != "cp-1" || b.ID == "" || string(b.TokenJWKS()) != `{"keys":[]}` {
		t.Fatalf("Bundle() = %+v, %v", b, ok)
	}
	b.Sections[BundleSectionTokenJWKS][0] = 'X' // a copy: no effect on the provider
	if again, _ := e.rp.Bundle(); string(again.TokenJWKS()) != `{"keys":[]}` {
		t.Fatal("Bundle() exposed internal state")
	}
	if st := e.rp.BundleStatus(); st.Expired {
		t.Fatal("fresh bundle reported expired")
	}
	e.now = bundleT0.Add(24*time.Hour + 6*time.Minute)
	if st := e.rp.BundleStatus(); !st.Expired {
		t.Fatal("bundle past expiresAt + skew not reported expired")
	}
	if !strings.Contains(e.logs.String(), "bundle applied") || !strings.Contains(e.logs.String(), "seq=7") {
		t.Fatalf("logs = %s", e.logs)
	}
	for _, h := range e.cp.accept {
		if h != BundleMediaType {
			t.Fatalf("Accept = %q, want the bundle media type", h)
		}
	}
}

func TestRemoteProviderSignedBundleWarnsOncePerDistinctRejection(t *testing.T) {
	e := newBundleEnv(t)
	raw := flipPayloadByte(t, e.sign(e.bundle(1, bundlePolicyA), nil))
	e.cp.serve(raw, "x")
	for i := 0; i < 3; i++ {
		_ = e.rp.Pull()
	}
	if n := strings.Count(e.logs.String(), "bundle rejected"); n != 1 {
		t.Fatalf("WARN count = %d, want 1:\n%s", n, e.logs)
	}
	e.cp.serve(raw[:len(raw)-3], "y") // different bytes, different digest
	_ = e.rp.Pull()
	if n := strings.Count(e.logs.String(), "bundle rejected"); n != 2 {
		t.Fatalf("WARN count = %d, want 2", n)
	}
}

func TestRemoteProviderWithoutPinsIsLegacy(t *testing.T) {
	cp := newSignedCP(t)
	cp.serve([]byte(bundlePolicyA), "l1")
	rp, err := NewRemoteProvider(cp.srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	rp.client, rp.longClient = cp.srv.Client(), cp.srv.Client()
	if err := rp.Pull(); err != nil {
		t.Fatal(err)
	}
	if cp.accept[0] != "" {
		t.Fatalf("Accept = %q without pins, want none", cp.accept[0])
	}
	if _, ok := rp.Bundle(); ok {
		t.Fatal("Bundle() ok without pins")
	}
	if st := rp.BundleStatus(); st.Enabled {
		t.Fatalf("status = %+v", st)
	}
	if err := rp.SetBundleTrust(BundleTrust{}); err == nil {
		t.Fatal("SetBundleTrust accepted no pins")
	}
	if err := rp.SetBundleTrust(BundleTrust{Pins: []keys.JWK{{}}}); err == nil {
		t.Fatal("SetBundleTrust accepted no clock")
	}
}

func TestRemoteProviderSignedBundleExpiredIsRetried(t *testing.T) {
	e := newBundleEnv(t)
	e.now = bundleT0.Add(48 * time.Hour) // past expiresAt + skew
	err := e.pullSeq(1, bundlePolicyA, "e1")
	if !errors.Is(err, bundle.ErrExpired) || !IsBundleRejection(err) {
		t.Fatalf("err = %v, want a bundle rejection wrapping ErrExpired", err)
	}
	if _, err := e.rp.PollLong(context.Background(), time.Millisecond); !errors.Is(err, bundle.ErrExpired) {
		t.Fatalf("an expired bundle must be fetched again: %v", err)
	}
	if got := e.cp.lastINM(); got != "" {
		t.Fatalf("If-None-Match = %s, want none for a clock-dependent rejection", got)
	}
	st := e.rp.BundleStatus()
	if !st.LastRejectAt.Equal(e.now) || len(st.PinnedKIDs) != 1 || st.PinnedKIDs[0] != e.sg.KID() {
		t.Fatalf("status = %+v", st)
	}
}

func TestRemoteProviderSignedBundleInvalidPolicyLeaksNothing(t *testing.T) {
	e := newBundleEnv(t)
	bad := `{"allowlist":[{"domain":"secret-host.example.com"}],"registeredAgents":[{"id":"leaky-agent-id","status":"paused","jkt":["` + strings.Repeat("A", 43) + `"]}]}`
	err := e.pullSeq(1, bad, "e1")
	if err == nil || !IsBundleRejection(err) {
		t.Fatalf("err = %v", err)
	}
	for _, out := range []string{err.Error(), e.logs.String()} {
		if strings.Contains(out, "leaky-agent-id") || strings.Contains(out, "secret-host") || strings.Contains(out, "paused") {
			t.Fatalf("payload content leaked: %s", out)
		}
	}
	if !strings.Contains(e.logs.String(), BundleReasonInvalidPolicy) {
		t.Fatalf("no reason in logs: %s", e.logs)
	}
}

func TestRemoteProviderUnpinnedWorkerGetsHintOn406(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotAcceptable)
	}))
	defer srv.Close()
	rp, err := NewRemoteProvider(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	rp.client, rp.longClient = srv.Client(), srv.Client()
	err = rp.Pull()
	if err == nil || !strings.Contains(err.Error(), "controlPlane.bundleKeys") {
		t.Fatalf("err = %v, want a hint naming controlPlane.bundleKeys", err)
	}
	if IsBundleRejection(err) {
		t.Fatal("a 406 is not a bundle rejection")
	}
}

// TestBundleWithoutTokenIssuer: a bundle from a control plane that mints no
// tokens (or an older one) has no tokenIssuer; it verifies and applies, and the
// worker sees an empty issuer, never the cpID.
func TestBundleWithoutTokenIssuer(t *testing.T) {
	e := newBundleEnv(t)
	if err := e.pullSeq(1, bundlePolicyA, "e1"); err != nil {
		t.Fatal(err)
	}
	b, ok := e.rp.Bundle()
	if !ok || b.TokenIssuer != "" {
		t.Fatalf("Bundle() = %+v, %v; want applied with an empty TokenIssuer", b, ok)
	}
	if in, ok := e.rp.BindingInputs(); !ok || in.TokenIssuer != "" {
		t.Fatalf("BindingInputs() = %+v, %v", in, ok)
	}
}

// TestVerifiedBundleTokenIssuerAndBindingInputs: the signed issuer reaches the
// worker, distinct from cpID, together with the token JWKS and the registered
// agents of the same bundle, and the accessor hands out copies.
func TestVerifiedBundleTokenIssuerAndBindingInputs(t *testing.T) {
	e := newBundleEnv(t)
	if _, ok := e.rp.BindingInputs(); ok {
		t.Fatal("BindingInputs ok with nothing verified")
	}
	policy := `{"allowlist":[{"domain":"a.example.com"}],"registeredAgents":[{"id":"agent-a","status":"active","jkt":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]}]}`
	b := e.bundle(3, policy)
	b.TokenIssuer = "https://warden.example.com"
	e.cp.serve(e.sign(b, nil), "e3")
	if err := e.rp.Pull(); err != nil {
		t.Fatal(err)
	}
	vb, ok := e.rp.Bundle()
	if !ok || vb.TokenIssuer != "https://warden.example.com" || vb.TokenIssuer == vb.CPID {
		t.Fatalf("Bundle() = %+v, %v", vb, ok)
	}
	in, ok := e.rp.BindingInputs()
	if !ok || in.Seq != 3 || in.TokenIssuer != vb.TokenIssuer || string(in.TokenJWKS) != `{"keys":[]}` ||
		len(in.Agents) != 1 || in.Agents[0].ID != "agent-a" || len(in.Agents[0].JKT) != 1 || in.Agents[0].JKT[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("BindingInputs() = %+v, %v", in, ok)
	}
	in.Agents[0].JKT[0] = "mutated"
	in.TokenJWKS[0] = 'X'
	if again, _ := e.rp.BindingInputs(); again.Agents[0].JKT[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" || string(again.TokenJWKS) != `{"keys":[]}` {
		t.Fatal("BindingInputs exposed internal state")
	}
}

// heartbeat sends one heartbeat and returns the decoded body it carried.
func (e *bundleEnv) heartbeat() (heartbeatBody, []byte) {
	e.t.Helper()
	if err := e.rp.Heartbeat(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	e.cp.mu.Lock()
	raw := e.cp.hbs[len(e.cp.hbs)-1]
	e.cp.mu.Unlock()
	var hb heartbeatBody
	if err := json.Unmarshal(raw, &hb); err != nil {
		e.t.Fatal(err)
	}
	return hb, raw
}

// TestHeartbeatBundleFields: a pinned worker that rejected seq 6 keeps
// reporting seq 5 and says why; the next apply clears the reason; a worker
// without pins sends none of the new fields.
func TestHeartbeatBundleFields(t *testing.T) {
	e := newBundleEnv(t)
	e.rp.SetCaps(WorkerCaps())

	hb, _ := e.heartbeat()
	if hb.BundleSeq != 0 || hb.LastRejectReason != "" || len(hb.PinnedKIDs) != 1 || !slices.Contains(hb.Caps, CapBundleV1) {
		t.Fatalf("before any bundle: %+v", hb)
	}

	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}
	e.cp.serve(flipPayloadByte(t, e.sign(e.bundle(6, bundlePolicyB), nil)), "e6bad")
	if err := e.rp.Pull(); !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("err = %v", err)
	}
	hb, raw := e.heartbeat()
	if hb.BundleSeq != 5 || hb.LastRejectReason != "bad_signature" || hb.BundleKID == "" ||
		hb.BundleIssuedAt != bundleT0.Format(time.RFC3339) || hb.LastRejectAt != e.now.Format(time.RFC3339) ||
		hb.BundleStale || hb.PolicyETag != "e5" || !slices.Contains(hb.Caps, CapBundleV1) {
		t.Fatalf("after a rejection: %+v", hb)
	}
	if len(raw) > 1024 {
		t.Errorf("heartbeat body is %d bytes, want well under the control plane's 4096", len(raw))
	}
	if !slices.Contains(hb.Caps, CapBlocklistV1) {
		t.Errorf("existing caps lost: %v", hb.Caps)
	}

	if err := e.pullSeq(7, bundlePolicyB, "e7"); err != nil {
		t.Fatal(err)
	}
	if hb, _ = e.heartbeat(); hb.BundleSeq != 7 || hb.LastRejectReason != "" || hb.LastRejectAt != "" {
		t.Fatalf("after the next apply: %+v", hb)
	}

	e.now = bundleT0.Add(48 * time.Hour)
	if hb, _ = e.heartbeat(); !hb.BundleStale {
		t.Fatalf("an expired bundle is not reported stale: %+v", hb)
	}
}

func TestHeartbeatBundleFieldsBoundedAndAbsentWithoutPins(t *testing.T) {
	var hb heartbeatBody
	st := BundleStatus{Enabled: true}
	for i := 0; i < 20; i++ {
		st.PinnedKIDs = append(st.PinnedKIDs, strings.Repeat("k", 43))
	}
	caps := bundleHeartbeat(&hb, []string{"a/v1"}, st)
	if len(hb.PinnedKIDs) != MaxHeartbeatPinnedKIDs || !slices.Equal(caps, []string{"a/v1", CapBundleV1}) {
		t.Fatalf("pinned %d kids, caps %v", len(hb.PinnedKIDs), caps)
	}

	hb = heartbeatBody{}
	if caps := bundleHeartbeat(&hb, []string{"a/v1"}, BundleStatus{}); !slices.Equal(caps, []string{"a/v1"}) {
		t.Fatalf("caps without pins = %v", caps)
	}
	raw, _ := json.Marshal(hb)
	for _, f := range []string{"bundle", "pinnedKids", "lastReject"} {
		if strings.Contains(string(raw), f) {
			t.Errorf("a worker without pins sends %q: %s", f, raw)
		}
	}
}
