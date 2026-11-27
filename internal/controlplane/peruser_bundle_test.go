package controlplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/secrets"
)

// puBlock is a switchable perUserSecrets source for the publisher: the block
// "in the served config" and the answer of the startup check.
type puBlock struct {
	mu       sync.Mutex
	cfg      config.PerUserSecretsConfig
	loadErr  error
	checkErr error
	checked  int
}

func (p *puBlock) load() (config.PerUserSecretsConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg, p.loadErr
}

func (p *puBlock) check(config.PerUserSecretsConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked++
	return p.checkErr
}

func (p *puBlock) set(c config.PerUserSecretsConfig) {
	p.mu.Lock()
	p.cfg = c
	p.mu.Unlock()
}

func (p *puBlock) setCheckErr(err error) {
	p.mu.Lock()
	p.checkErr = err
	p.mu.Unlock()
}

func puOn(agents ...string) config.PerUserSecretsConfig {
	if len(agents) == 0 {
		agents = []string{"agent-a"}
	}
	return config.PerUserSecretsConfig{
		Enabled: true, WorkerCacheTTL: 5 * time.Minute,
		Mappings: []config.PerUserMapping{{
			Placeholder: "GOOGLE_USER_PLACEHOLDER", Provider: "google",
			Scopes:  []string{"https://www.googleapis.com/auth/gmail.readonly"},
			Domains: []string{"gmail.googleapis.com"}, In: []string{"header"}, Agents: agents,
		}},
	}
}

// newPerUserBundleHarness boots a bundle-serving versioned control plane whose
// per-user block comes from src (nil = the feature is not wired).
func newPerUserBundleHarness(t *testing.T, src *puBlock, db *cpstate.DB, clk *clocktest.Fake, keys ...*fakeBundleKeys) *btHarness {
	t.Helper()
	if db == nil {
		db = openPolicyState(t)
	}
	var fk *fakeBundleKeys
	if len(keys) > 0 {
		fk = keys[0]
	} else {
		fk = newFakeBundleKeys(t)
	}
	if clk == nil {
		clk = clocktest.NewFake(btStart)
	}
	logs := &syncBuf{}
	cfg := Config{
		PolicyPath: overlayFixture(t), State: db, PolicyStore: PolicyStoreVersioned,
		Bundles: BundlesConfig{Mode: BundlesOffer}, bundleKeys: fk, Clock: clk,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)),
	}
	if src != nil {
		cfg.PerUserLoad, cfg.PerUserCheck = src.load, src.check
	}
	s := New(cfg)
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &btHarness{s: s, ps: s.policy, fk: fk, clk: clk, logs: logs, db: db}
	if err := s.policy.startBundles(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *btHarness) sections(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	return btPayload(t, h.bundleResp(t).body).Sections
}

func (h *btHarness) epochs(t *testing.T) bundle.UserGrantEpochs {
	t.Helper()
	raw, ok := h.sections(t)[bundle.SectionUserGrantEpochs]
	if !ok {
		t.Fatal("the bundle has no userGrantEpochs section")
	}
	e, err := bundle.ParseUserGrantEpochs(raw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (h *btHarness) reasons(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, r := range h.publishRows(t) {
		out = append(out, r.Reason)
	}
	return out
}

func puUserKey(t *testing.T, sub string) string {
	t.Helper()
	k, err := secrets.UserKey("https://idp.example.com", sub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestBundlePerUserSections: with perUserSecrets enabled the signed bundle
// carries sections.perUserSecrets with the configured mapping and
// workerCacheTTL and sections.userGrantEpochs, both covered by the signature;
// neither is on the legacy wire; no token, secret or subject field is in them.
func TestBundlePerUserSections(t *testing.T) {
	src := &puBlock{cfg: puOn("agent-a", "agent-b")}
	src.cfg.Mappings[0].Scopes = []string{"s1", "s2"}
	src.cfg.Mappings[0].In = []string{"header", "query"}
	h := newPerUserBundleHarness(t, src, nil, nil)

	raw := h.bundleResp(t).body
	v := h.verify(t, raw, bundle.State{})
	secs := v.Bundle.Sections
	if _, ok := secs[sectionTokenJWKS]; !ok {
		t.Error("the tokenJWKS section went missing")
	}
	section, err := bundle.ParsePerUserSecrets(secs[bundle.SectionPerUserSecrets])
	if err != nil || section == nil {
		t.Fatalf("perUserSecrets section = %v, %v", section, err)
	}
	want := bundle.PerUserSecretsSection{WorkerCacheTTLSeconds: 300, Mappings: []bundle.PerUserMappingSection{{
		Placeholder: "GOOGLE_USER_PLACEHOLDER", Provider: "google", Scopes: []string{"s1", "s2"},
		Domains: []string{"gmail.googleapis.com"}, In: []string{"header", "query"}, Agents: []string{"agent-a", "agent-b"},
	}}}
	if !reflect.DeepEqual(*section, want) {
		t.Errorf("perUserSecrets = %+v, want %+v", *section, want)
	}
	if e, err := bundle.ParseUserGrantEpochs(secs[bundle.SectionUserGrantEpochs]); err != nil || e == nil || len(e) != 0 {
		t.Errorf("userGrantEpochs = %v, %v, want present and empty", e, err)
	}
	// Only configured names are in the section JSON, no value-bearing member.
	for _, banned := range []string{"token", "secret", "password", "email", "sub", "client"} {
		if bytes.Contains(bytes.ToLower(secs[bundle.SectionPerUserSecrets]), []byte(banned)) {
			t.Errorf("perUserSecrets section contains %q: %s", banned, secs[bundle.SectionPerUserSecrets])
		}
	}

	// The signature covers the sections: a flipped payload byte in them fails.
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Replace(payload, []byte("gmail.googleapis.com"), []byte("evil.example.com\x20\x20\x20\x20"), 1)
	env.Payload = base64.RawURLEncoding.EncodeToString(forged)
	tampered, _ := json.Marshal(env)
	if _, err := bundle.Verify(tampered, h.fk.pins(), bundle.State{}, bundle.Options{Now: h.clk.Now(), Skew: time.Minute}); err == nil {
		t.Error("a bundle with an edited perUserSecrets section verified")
	}

	// The legacy wire (no bundle Accept header) carries neither section.
	legacy := h.get(t, "", "")
	for _, banned := range []string{"perUserSecrets", "userGrantEpochs", "GOOGLE_USER_PLACEHOLDER", "gmail.googleapis.com"} {
		if bytes.Contains(legacy.body, []byte(banned)) {
			t.Errorf("legacy /policy carries %q", banned)
		}
	}
}

// TestPerUserSectionHasNoValueFields: the section types are walked by
// reflection; every JSON member is on a closed list of names, and no field is
// typed as anything but a string, a string list or an int.
func TestPerUserSectionHasNoValueFields(t *testing.T) {
	allowed := map[string]bool{
		"workerCacheTTLSeconds": true, "mappings": true,
		"placeholder": true, "provider": true, "scopes": true, "domains": true, "in": true, "agents": true,
	}
	banned := regexp.MustCompile(`(?i)token|secret|password|credential|email|sub|key|client|grant`)
	var walk func(rt reflect.Type)
	walk = func(rt reflect.Type) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if !allowed[name] || banned.MatchString(name) {
				t.Errorf("%s.%s: json member %q is not on the closed list of value-free names", rt.Name(), f.Name, name)
			}
			ft := f.Type
			switch {
			case ft.Kind() == reflect.String, ft.Kind() == reflect.Int,
				ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.String:
			case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct:
				walk(ft.Elem())
			default:
				t.Errorf("%s.%s has type %s, which the value-free section does not allow", rt.Name(), f.Name, ft)
			}
		}
	}
	walk(reflect.TypeOf(bundle.PerUserSecretsSection{}))
	// userGrantEpochs is a plain map of user key to epoch: no struct to carry a value.
	if et := reflect.TypeOf(bundle.UserGrantEpochs{}); et.Kind() != reflect.Map || et.Key().Kind() != reflect.String || et.Elem().Kind() != reflect.Int64 {
		t.Errorf("userGrantEpochs is %s, want map[string]int64", et)
	}
}

// TestBundlePerUserOffByteIdentical: with the block absent, present but
// disabled, or not wired at all, the signed payload bytes equal the golden file
// captured before this feature, and the publish log has no per-user row. An
// enabled block that fails the startup check is not served either.
func TestBundlePerUserOffByteIdentical(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "bundle_payload_peruser_off.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*puBlock{
		"not wired": nil,
		"absent":    {},
		"disabled":  {cfg: func() config.PerUserSecretsConfig { c := puOn(); c.Enabled = false; return c }()},
		"enabled but refused by the startup check": {cfg: puOn(), checkErr: errors.New("perUserSecrets.enabled requires consent.store")},
		"enabled but unreadable":                   {cfg: puOn(), loadErr: errors.New("read failed")},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			got, reasons, legacyETag := perUserGoldenPayload(t, src)
			if len(reasons) != 1 {
				t.Errorf("publish log reasons = %v, want only the initial import row", reasons)
			}
			if wantETag, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.etag")); err != nil || legacyETag != strings.TrimSpace(string(wantETag)) {
				t.Errorf("legacy /policy ETag = %q, want golden %q (%v)", legacyETag, wantETag, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("payload differs from golden\n got: %s\nwant: %s", got, want)
			}
			for _, r := range reasons {
				if r == publishReasonPerUserSecrets || r == publishReasonUserGrant {
					t.Errorf("publish log has a %s row with the feature off", r)
				}
			}
		})
	}
}

// perUserGoldenPayload boots a bundle-serving control plane over the overlay
// fixture with every nondeterministic input pinned (clock, cpID, token JWKS)
// and returns the decoded payload bytes of the envelope it serves and the
// publish-log reasons.
func perUserGoldenPayload(t *testing.T, src *puBlock) ([]byte, []string, string) {
	t.Helper()
	db := openPolicyState(t)
	if err := (bundleState{db: db.SQL()}).put(context.Background(), stateCPID, "cp_00000000000000000000000000000001"); err != nil {
		t.Fatal(err)
	}
	fk := newFakeBundleKeys(t)
	fk.token = keys.JWKS{Keys: []keys.JWK{{Kty: "OKP", Crv: "Ed25519", Kid: "golden-token-kid", X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Alg: "EdDSA", Use: "sig"}}}
	cfg := Config{
		PolicyPath: overlayFixture(t), State: db, PolicyStore: PolicyStoreVersioned,
		Bundles: BundlesConfig{Mode: BundlesRequire}, bundleKeys: fk, Clock: clocktest.NewFake(btStart),
		Logger: slog.New(slog.NewJSONHandler(&syncBuf{}, nil)),
	}
	if src != nil {
		cfg.PerUserLoad, cfg.PerUserCheck = src.load, src.check
	}
	s := New(cfg)
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &btHarness{s: s, ps: s.policy, fk: fk, clk: cfg.Clock.(*clocktest.Fake), db: db}
	if err := s.policy.startBundles(context.Background()); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(h.bundleResp(t).body, &env); err != nil {
		t.Fatal(err)
	}
	p, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return p, h.reasons(t), `"` + h.ps.currentETag() + `"`
}

// TestBundlePerUserCheckGate: an enabled block is served only after
// checkPerUserSecretsStartup accepts it, on every build. A block that first
// fails the check is never served; once the check passes it is, with a
// per_user_secrets row; an edit that then fails the check keeps the section
// last served; disabling the block removes both sections.
func TestBundlePerUserCheckGate(t *testing.T) {
	src := &puBlock{cfg: puOn(), checkErr: errors.New("perUserSecrets.enabled requires consent.store")}
	h := newPerUserBundleHarness(t, src, nil, nil)
	if _, ok := h.sections(t)[bundle.SectionPerUserSecrets]; ok {
		t.Fatal("a block that fails the startup check was served")
	}
	if src.checked == 0 {
		t.Fatal("the startup check never ran for an enabled block")
	}

	src.setCheckErr(nil)
	h.ps.Refresh()
	secs := h.sections(t)
	if _, ok := secs[bundle.SectionPerUserSecrets]; !ok {
		t.Fatal("the section is still missing after the check passed")
	}
	if got := h.latest(t).Reason; got != publishReasonPerUserSecrets {
		t.Errorf("newest publish row reason = %q, want %q", got, publishReasonPerUserSecrets)
	}
	seq := h.latest(t).Seq
	h.ps.Refresh()
	if h.latest(t).Seq != seq {
		t.Error("an unchanged block appended a publish row")
	}

	// An edited block that fails the check does not replace what was served.
	edited := puOn("agent-z")
	src.set(edited)
	src.setCheckErr(errors.New("provider not registered"))
	h.ps.Refresh()
	section, _ := bundle.ParsePerUserSecrets(h.sections(t)[bundle.SectionPerUserSecrets])
	if section == nil || section.Mappings[0].Agents[0] != "agent-a" {
		t.Errorf("a refused edit replaced the served section: %+v", section)
	}
	if h.latest(t).Seq != seq {
		t.Error("a refused edit appended a publish row")
	}

	// Disabled: both sections go away, with a row for the change.
	src.setCheckErr(nil)
	src.set(config.PerUserSecretsConfig{})
	h.ps.Refresh()
	secs = h.sections(t)
	if _, ok := secs[bundle.SectionPerUserSecrets]; ok {
		t.Error("perUserSecrets still served after the block was disabled")
	}
	if _, ok := secs[bundle.SectionUserGrantEpochs]; ok {
		t.Error("userGrantEpochs still served after the block was disabled")
	}
	if h.latest(t).Reason != publishReasonPerUserSecrets {
		t.Errorf("disabling appended reason %q", h.latest(t).Reason)
	}
}

// TestBundlePerUserConfigChangeRow: a change of the block appends a
// per_user_secrets publish-log row and a new seq, also across a restart (a
// change made while the control plane was down).
func TestBundlePerUserConfigChangeRow(t *testing.T) {
	src := &puBlock{cfg: puOn()}
	db := openPolicyState(t)
	h := newPerUserBundleHarness(t, src, db, nil)
	first := h.latest(t)
	if first.Reason != publishReasonPerUserSecrets {
		t.Fatalf("enabling at boot logged %q, want %q", first.Reason, publishReasonPerUserSecrets)
	}
	src.set(puOn("agent-a", "agent-b"))
	h.ps.Refresh()
	second := h.latest(t)
	if second.Reason != publishReasonPerUserSecrets || second.Seq <= first.Seq {
		t.Fatalf("a mapping change logged %+v after %+v", second, first)
	}

	// Restart over the same state with the block changed while down.
	src2 := &puBlock{cfg: puOn("agent-c")}
	h2 := newPerUserBundleHarness(t, src2, db, nil, h.fk)
	third := h2.latest(t)
	if third.Reason != publishReasonPerUserSecrets || third.Seq <= second.Seq {
		t.Errorf("a change made while down logged %+v after %+v", third, second)
	}
	// And an unchanged restart appends nothing.
	h3 := newPerUserBundleHarness(t, &puBlock{cfg: puOn("agent-c")}, db, nil, h.fk)
	if got := h3.latest(t); got.Seq != third.Seq {
		t.Errorf("an unchanged restart appended %+v", got)
	}
}

// TestEpochStoreBump: Bump appends a user_grant publish-log row, wakes the
// long-poll waiters, and the next bundle carries the user's epoch (the row's
// seq) keyed by the user key. A second Bump of the same user is larger, also
// after a prune dropped the entry.
func TestEpochStoreBump(t *testing.T) {
	src := &puBlock{cfg: puOn()}
	h := newPerUserBundleHarness(t, src, nil, nil)
	e := h.s.GrantEpochs()
	if e == nil {
		t.Fatal("no epoch store with bundles on")
	}
	alice, bob := puUserKey(t, "alice"), puUserKey(t, "bob")

	_, ch := h.ps.watch.bundleSnapshot()
	before := h.latest(t)
	epoch, err := e.Bump(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	default:
		t.Error("Bump did not wake the long-poll waiters")
	}
	row := h.latest(t)
	if row.Reason != publishReasonUserGrant || row.Seq != epoch || epoch <= before.Seq {
		t.Fatalf("Bump returned %d; newest row %+v (before seq %d)", epoch, row, before.Seq)
	}
	if got := h.epochs(t); len(got) != 1 || got[alice] != epoch {
		t.Fatalf("userGrantEpochs = %v, want {%s: %d}", got, alice, epoch)
	}
	if v := h.verify(t, h.bundleResp(t).body, bundle.State{}); v.Seq != epoch {
		t.Errorf("bundle seq = %d, want the bump's seq %d", v.Seq, epoch)
	}
	if h.degraded() {
		t.Error("the publisher is degraded after a Bump")
	}

	epochBob, err := e.Bump(context.Background(), bob)
	if err != nil || epochBob <= epoch {
		t.Fatalf("second user's epoch = %d, %v; want above %d", epochBob, err, epoch)
	}
	h.clk.Advance(2*config.MaxPerUserWorkerCacheTTL + time.Second)
	rowsBefore := len(h.publishRows(t))
	n, err := e.Prune(context.Background(), h.clk.Now())
	if err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v, want 2", n, err)
	}
	if len(h.publishRows(t)) != rowsBefore {
		t.Error("a prune appended a publish-log row")
	}
	again, err := e.Bump(context.Background(), alice)
	if err != nil || again <= epochBob {
		t.Fatalf("Bump after a prune = %d, %v, want above %d", again, err, epochBob)
	}
	if got := h.epochs(t); len(got) != 1 || got[alice] != again {
		t.Fatalf("userGrantEpochs after the prune and a bump = %v, want only alice at %d", got, again)
	}
}

// TestEpochStorePruneKeepsBundleSignable: a worker that applied the bundle of a
// seq still accepts its re-sign (the resign ticker, a key re-sign) and the one
// a restarted control plane signs after a prune dropped the entry: the bytes
// signed for a seq never change (bundle.Verify would answer ErrEquivocation).
// The pruned entry disappears with the next seq.
func TestEpochStorePruneKeepsBundleSignable(t *testing.T) {
	db := openPolicyState(t)
	src := &puBlock{cfg: puOn()}
	h := newPerUserBundleHarness(t, src, db, nil)
	alice, bob := puUserKey(t, "alice"), puUserKey(t, "bob")
	if _, err := h.s.GrantEpochs().Bump(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	applied := btState(h.verify(t, h.bundleResp(t).body, bundle.State{}))
	seq := h.latest(t).Seq

	h.clk.Advance(time.Hour)
	if n, err := h.s.GrantEpochs().Prune(context.Background(), h.clk.Now()); err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v", n, err)
	}
	h.ps.refresh(true) // the re-sign ticker
	if h.degraded() || strings.Contains(h.logs.String(), "refusing to sign") {
		t.Fatalf("a re-sign after a prune was refused:\n%s", h.logs.String())
	}
	re := h.verify(t, h.bundleResp(t).body, applied) // fails on ErrEquivocation
	if !re.Refresh || re.Seq != seq {
		t.Errorf("re-sign after a prune: refresh=%v seq=%d, want a refresh of seq %d", re.Refresh, re.Seq, seq)
	}

	// A restarted control plane signs the same bytes for the seq.
	h2 := newPerUserBundleHarness(t, &puBlock{cfg: puOn()}, db, clocktest.NewFake(h.clk.Now()), h.fk)
	if h2.degraded() || h2.latest(t).Seq != seq {
		t.Fatalf("restart after a prune: degraded=%v seq=%d want %d", h2.degraded(), h2.latest(t).Seq, seq)
	}
	h2.ps.refresh(true)
	if re2 := h2.verify(t, h2.bundleResp(t).body, applied); !re2.Refresh || re2.Seq != seq {
		t.Errorf("restart: refresh=%v seq=%d, want a refresh of seq %d", re2.Refresh, re2.Seq, seq)
	}

	// The next seq drops the pruned entry.
	if _, err := h2.s.GrantEpochs().Bump(context.Background(), bob); err != nil {
		t.Fatal(err)
	}
	if got := h2.epochs(t); len(got) != 1 || got[alice] != 0 || got[bob] == 0 {
		t.Errorf("userGrantEpochs after the next seq = %v, want only bob", got)
	}
}

// TestEpochStoreBumpOffAndInvalid: with the feature off Bump does nothing
// (no row, epoch 0); a key that is not a secrets.UserKey is refused, so no
// subject or email can reach the section.
func TestEpochStoreBumpOffAndInvalid(t *testing.T) {
	off := newPerUserBundleHarness(t, &puBlock{}, nil, nil)
	rows := len(off.publishRows(t))
	if epoch, err := off.s.GrantEpochs().Bump(context.Background(), puUserKey(t, "alice")); err != nil || epoch != 0 {
		t.Errorf("Bump with the feature off = %d, %v, want 0, nil", epoch, err)
	}
	if len(off.publishRows(t)) != rows {
		t.Error("Bump appended a publish row with the feature off")
	}

	on := newPerUserBundleHarness(t, &puBlock{cfg: puOn()}, nil, nil)
	for _, bad := range []string{"", "alice@example.com", "https://idp|alice", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33)} {
		if _, err := on.s.GrantEpochs().Bump(context.Background(), bad); !errors.Is(err, ErrInvalidGrantUserKey) {
			t.Errorf("Bump(%q) = %v, want ErrInvalidGrantUserKey", bad, err)
		}
	}

	noBundles := New(Config{PolicyPath: overlayFixture(t)})
	if noBundles.GrantEpochs() != nil {
		t.Error("an epoch store exists without signed bundles")
	}
}

// TestEpochStoreBumpDegraded: when the bundle cannot be signed the epoch is
// recorded but Bump reports ErrEpochNotPublished, and the next Bump after the
// signer recovers publishes both.
func TestEpochStoreBumpDegraded(t *testing.T) {
	h := newPerUserBundleHarness(t, &puBlock{cfg: puOn()}, nil, nil)
	h.fk.mu.Lock()
	h.fk.failSign = true
	h.fk.mu.Unlock()
	epoch, err := h.s.GrantEpochs().Bump(context.Background(), puUserKey(t, "alice"))
	if !errors.Is(err, ErrEpochNotPublished) || epoch == 0 {
		t.Fatalf("Bump with a failing signer = %d, %v, want ErrEpochNotPublished", epoch, err)
	}
	h.fk.mu.Lock()
	h.fk.failSign = false
	h.fk.mu.Unlock()
	next, err := h.s.GrantEpochs().Bump(context.Background(), puUserKey(t, "bob"))
	if err != nil || next <= epoch {
		t.Fatalf("Bump after recovery = %d, %v", next, err)
	}
	if got := h.epochs(t); got[puUserKey(t, "alice")] != epoch || got[puUserKey(t, "bob")] != next {
		t.Errorf("userGrantEpochs = %v", got)
	}
}

// perUserGuardServer is a control plane over a policy file with the block
// wired for WritePerUserSecrets, console roles on.
func perUserGuardServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := writePolicyFile(t, "api.openai.com")
	src := &puBlock{}
	s := New(Config{
		PolicyPath: path, Console: authzConsole(defaultRoles()),
		PerUserLoad:  func() (config.PerUserSecretsConfig, error) { return loadPerUserSecrets(path) },
		PerUserCheck: src.check,
	})
	return s, path
}

func puLiveBlock(t *testing.T, path string) config.PerUserSecretsConfig {
	t.Helper()
	c, err := loadPerUserSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestPerUserRolloutGuard: a save that enables the block, or adds an agent to a
// mapping, is a 409 workers_lack_capability naming the connected workers bound
// to that agent that lack usersecrets/v1; force=true by an admin succeeds and
// the audit annotation records force and the worker ids; an editor cannot
// force; other agents' workers, agent-less workers and capable workers do not
// block; a save that adds no agent is never refused.
func TestPerUserRolloutGuard(t *testing.T) {
	s, path := perUserGuardServer(t)
	bg := WithPrincipal(context.Background(), Principal{Kind: PrincipalSession, Groups: []string{groupAdmin}})
	beat(s, "old-a", "agent-a", config.CapBlocklistV1)
	beat(s, "ok-a", "agent-a", config.CapUserSecretsV1)
	beat(s, "old-b", "agent-b", config.CapBlocklistV1)
	beat(s, "anon", "", config.CapBlocklistV1)

	// Enabling for agent-a: refused, naming only old-a.
	var lack *dashboard.WorkersLackCapabilityError
	err := s.WritePerUserSecrets(bg, puOn("agent-a"))
	if !errors.As(err, &lack) || strings.Join(lack.Workers, ",") != "old-a" {
		t.Fatalf("enable with an old worker = %v, want WorkersLackCapabilityError [old-a]", err)
	}
	if puLiveBlock(t, path).Enabled {
		t.Fatal("a refused save reached the config file")
	}

	// An editor cannot force; an admin can, and it is audited.
	forced := dashboard.WithForce(bg)
	editor := WithPrincipal(forced, Principal{Kind: PrincipalSession, Groups: []string{groupEditor}})
	var role *dashboard.RoleRequiredError
	if err := s.WritePerUserSecrets(editor, puOn("agent-a")); !errors.As(err, &role) || role.Need != "admin" {
		t.Fatalf("editor with force = %v, want RoleRequiredError admin", err)
	}
	if puLiveBlock(t, path).Enabled {
		t.Fatal("an editor's forced save reached the config file")
	}
	adminCtx, ann := adminaudit.WithAnnotation(WithPrincipal(forced, Principal{Kind: PrincipalSession, Groups: []string{groupAdmin}}))
	if err := s.WritePerUserSecrets(adminCtx, puOn("agent-a")); err != nil {
		t.Fatalf("forced by an admin = %v", err)
	}
	if !puLiveBlock(t, path).Enabled {
		t.Fatal("the forced save did not reach the config file")
	}
	_, details := ann.Snapshot()
	if details[adminaudit.DetailForce] != "true" || details[adminaudit.DetailWorkersLacking] != "old-a" {
		t.Errorf("audit details = %v, want force and workersLacking old-a", details)
	}

	// Adding agent-b to the mapping is refused for old-b only.
	err = s.WritePerUserSecrets(bg, puOn("agent-a", "agent-b"))
	if !errors.As(err, &lack) || strings.Join(lack.Workers, ",") != "old-b" {
		t.Fatalf("adding agent-b = %v, want [old-b]", err)
	}
	// A save that adds no agent (a scope change) is never refused, though old-a is connected.
	changed := puOn("agent-a")
	changed.Mappings[0].Scopes = []string{"another.scope"}
	if err := s.WritePerUserSecrets(bg, changed); err != nil {
		t.Fatalf("a save adding no agent = %v", err)
	}
	// Disabling is never refused.
	if err := s.WritePerUserSecrets(bg, config.PerUserSecretsConfig{}); err != nil {
		t.Fatalf("disabling = %v", err)
	}
	// Once the old worker is offline (stale), the save goes through.
	now := time.Unix(1_800_000_000, 0)
	s.registry.now = func() time.Time { return now }
	beat(s, "old-a", "agent-a", config.CapBlocklistV1)
	now = now.Add(staleAfter + time.Second)
	if err := s.WritePerUserSecrets(bg, puOn("agent-a")); err != nil {
		t.Fatalf("enable with only an offline old worker = %v", err)
	}
	if got := puLiveBlock(t, path); !got.Enabled || len(got.Mappings) != 1 {
		t.Errorf("config after the save = %+v", got)
	}
}

// TestPerUserWriteChecks: the writer refuses an enabled block the startup check
// refuses and one the loader rejects, and changes nothing.
func TestPerUserWriteChecks(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	src := &puBlock{checkErr: errors.New("perUserSecrets.enabled requires consent.store")}
	s := New(Config{
		PolicyPath:   path,
		PerUserLoad:  func() (config.PerUserSecretsConfig, error) { return loadPerUserSecrets(path) },
		PerUserCheck: src.check,
	})
	var inv *dashboard.InvalidPolicyError
	if err := s.WritePerUserSecrets(context.Background(), puOn()); !errors.As(err, &inv) {
		t.Fatalf("a block that fails the startup check = %v, want InvalidPolicyError", err)
	}
	src.setCheckErr(nil)
	bad := puOn()
	bad.Mappings[0].Domains = nil
	if err := s.WritePerUserSecrets(context.Background(), bad); err == nil {
		t.Fatal("a mapping without domains was saved")
	}
	if puLiveBlock(t, path).Enabled {
		t.Fatal("a refused save reached the config file")
	}
	unwired := New(Config{PolicyPath: path})
	if err := unwired.WritePerUserSecrets(context.Background(), puOn()); !errors.As(err, &inv) {
		t.Fatalf("enabling on a control plane without the feature wired = %v", err)
	}
}

const puRouteBody = `{"enabled":true,"workerCacheTTLSeconds":300,"mappings":[{"placeholder":"GOOGLE_USER_PLACEHOLDER","provider":"google","scopes":["s1"],"domains":["gmail.googleapis.com"],"in":["header"],"agents":["agent-a"]}]}`

// TestPerUserSecretsRoute: PUT /dashboard/api/per-user-secrets, over HTTP. The
// rollout guard answers 409 workers_lack_capability naming the workers; an admin
// with ?force=true succeeds and the admin audit row carries force and the worker
// ids; an editor is 403 role_required with and without force; a viewer, a
// missing session and a wrong method are refused; an unknown member is 400.
func TestPerUserSecretsRoute(t *testing.T) {
	e := newAuditEnv(t, auditEnvOpts{console: authzConsole(defaultRoles()), token: dashTestToken})
	path := e.srv.cfg.PolicyPath
	e.srv.cfg.PerUserLoad = func() (config.PerUserSecretsConfig, error) { return loadPerUserSecrets(path) }
	e.srv.cfg.PerUserCheck = func(config.PerUserSecretsConfig) error { return nil }
	admin, editor, viewer := e.session(t, groupAdmin), e.session(t, groupEditor), e.session(t, groupViewer)
	beat(e.srv, "old-a", "agent-a", config.CapBlocklistV1)

	rec := e.send(admin, "", http.MethodPut, perUserSecretsPath, puRouteBody)
	if b := decodeLack(t, rec.Body.String()); rec.Code != http.StatusConflict || b.Error != "workers_lack_capability" || strings.Join(b.Workers, ",") != "old-a" {
		t.Fatalf("enable with an old worker = %d %s, want 409 workers_lack_capability [old-a]", rec.Code, rec.Body.String())
	}
	if puLiveBlock(t, path).Enabled {
		t.Fatal("a refused save reached the config file")
	}
	for name, id := range map[string]string{"editor": editor, "viewer": viewer} {
		for _, q := range []string{"", "?force=true"} {
			if rec := e.send(id, "", http.MethodPut, perUserSecretsPath+q, puRouteBody); rec.Code != http.StatusForbidden {
				t.Errorf("%s PUT%s = %d %s, want 403", name, q, rec.Code, rec.Body.String())
			}
		}
	}
	if rec := e.send("", "", http.MethodPut, perUserSecretsPath, puRouteBody); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session = %d, want 401", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodPost, perUserSecretsPath, puRouteBody); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodPut, perUserSecretsPath, `{"enabled":true,"token":"x"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown member = %d %s, want 400", rec.Code, rec.Body.String())
	}

	rec = e.send(admin, "", http.MethodPut, perUserSecretsPath+"?force=true", puRouteBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("forced by an admin = %d %s", rec.Code, rec.Body.String())
	}
	if !puLiveBlock(t, path).Enabled {
		t.Fatal("the forced save did not reach the config file")
	}
	var row *adminaudit.Input
	for _, in := range e.rec.inputs() {
		if in.Action == "per_user_secrets.write" && in.Details[adminaudit.DetailForce] == "true" {
			in := in
			row = &in
		}
	}
	if row == nil || row.Details[adminaudit.DetailWorkersLacking] != "old-a" {
		t.Fatalf("no per_user_secrets.write audit row with force and the worker ids: %+v", e.rec.inputs())
	}
}

// TestPerUserSecretsRouteNoneMode: with console.auth none the route needs the
// admin bearer.
func TestPerUserSecretsRouteNoneMode(t *testing.T) {
	e := newAuditEnv(t, auditEnvOpts{token: dashTestToken, adminToken: "admin-token-for-per-user"})
	path := e.srv.cfg.PolicyPath
	e.srv.cfg.PerUserLoad = func() (config.PerUserSecretsConfig, error) { return loadPerUserSecrets(path) }
	e.srv.cfg.PerUserCheck = func(config.PerUserSecretsConfig) error { return nil }
	if rec := e.send("", "", http.MethodPut, perUserSecretsPath, puRouteBody); rec.Code != http.StatusUnauthorized {
		t.Errorf("no bearer = %d, want 401", rec.Code)
	}
	if rec := e.send("", "admin-token-for-per-user", http.MethodPut, perUserSecretsPath, puRouteBody); rec.Code != http.StatusOK {
		t.Errorf("admin bearer = %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// TestPerUserPruneUsesLongestTTL: prune keeps an entry for 2 x the longest
// allowed workerCacheTTL, not 2 x the configured one, so lowering the TTL cannot
// drop an epoch a worker still holding a token under the old TTL needs.
func TestPerUserPruneUsesLongestTTL(t *testing.T) {
	cfg := puOn()
	cfg.WorkerCacheTTL = config.MinPerUserWorkerCacheTTL
	h := newPerUserBundleHarness(t, &puBlock{cfg: cfg}, nil, nil)
	e := h.s.GrantEpochs()
	if _, err := e.Bump(context.Background(), puUserKey(t, "alice")); err != nil {
		t.Fatal(err)
	}
	h.clk.Advance(2*config.MinPerUserWorkerCacheTTL + time.Minute)
	if n, err := e.Prune(context.Background(), h.clk.Now()); err != nil || n != 0 {
		t.Fatalf("Prune after 2 x the configured TTL = %d, %v, want 0", n, err)
	}
	h.clk.Advance(2 * config.MaxPerUserWorkerCacheTTL)
	if n, err := e.Prune(context.Background(), h.clk.Now()); err != nil || n != 1 {
		t.Fatalf("Prune after 2 x the longest TTL = %d, %v, want 1", n, err)
	}
}

// TestPerUserSecretsStale: an enabled block that fails the startup check, or
// cannot be read, is reported on /healthz (degraded: perUserSecrets stale) and
// logged once per transition, not on every build; serving it again clears it.
func TestPerUserSecretsStale(t *testing.T) {
	src := &puBlock{cfg: puOn()}
	h := newPerUserBundleHarness(t, src, nil, nil)
	health := func() string {
		rec := httptest.NewRecorder()
		h.s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return rec.Body.String()
	}
	if got := health(); got != "ok\n" {
		t.Fatalf("healthz = %q, want ok", got)
	}
	src.setCheckErr(errors.New("consent.store is gone"))
	for i := 0; i < 3; i++ {
		h.ps.Refresh()
	}
	if got := health(); !strings.Contains(got, "degraded: perUserSecrets stale") {
		t.Fatalf("healthz = %q, want perUserSecrets stale", got)
	}
	if n := strings.Count(h.logs.String(), "perUserSecrets is stale"); n != 1 {
		t.Errorf("stale logged %d times over 3 builds, want once", n)
	}
	src.setCheckErr(nil)
	h.ps.Refresh()
	if got := health(); got != "ok\n" {
		t.Errorf("healthz after recovery = %q, want ok", got)
	}
	src.mu.Lock()
	src.loadErr = errors.New("read failed")
	src.mu.Unlock()
	h.ps.Refresh()
	if got := health(); !strings.Contains(got, "perUserSecrets stale") {
		t.Errorf("healthz with an unreadable block = %q", got)
	}
}

// TestPerUserFileEditWarnsLackingWorkers: a mapping that adds an agent through
// an edit of the served config (which no 409 can stop) logs one WARN naming the
// connected workers that lack usersecrets/v1, once per change.
func TestPerUserFileEditWarnsLackingWorkers(t *testing.T) {
	src := &puBlock{cfg: puOn("agent-a")}
	h := newPerUserBundleHarness(t, src, nil, nil)
	beat(h.s, "old-b", "agent-b", config.CapBlocklistV1)
	beat(h.s, "ok-b", "agent-b", config.CapUserSecretsV1)
	h.ps.Refresh()
	if strings.Contains(h.logs.String(), "per_user_secrets_workers_lack_capability") {
		t.Fatal("warned with no new agent")
	}
	src.set(puOn("agent-a", "agent-b"))
	h.ps.Refresh()
	h.ps.Refresh()
	logs := h.logs.String()
	if n := strings.Count(logs, "per_user_secrets_workers_lack_capability"); n != 1 || !strings.Contains(logs, `"workers":["old-b"]`) {
		t.Errorf("warnings = %d (want 1 naming old-b):\n%s", n, logs)
	}
}

// TestPerUserSecretsHashCoversEnabled: an enable/disable-only save changes the
// admin audit state hash.
func TestPerUserSecretsHashCoversEnabled(t *testing.T) {
	e := newAuditEnv(t, auditEnvOpts{token: dashTestToken})
	src := &puBlock{cfg: puOn()}
	e.srv.cfg.PerUserLoad = src.load
	on, err := e.srv.perUserSecretsHash(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	off := puOn()
	off.Enabled = false
	src.set(off)
	got, err := e.srv.perUserSecretsHash(context.Background())
	if err != nil || got == on {
		t.Fatalf("hash with the block disabled = %q (%v), same as enabled %q", got, err, on)
	}
}

// TestPerUserUnreadableWithFeatureOff: an unreadable served config with the
// feature off or never on leaves /healthz ok.
func TestPerUserUnreadableWithFeatureOff(t *testing.T) {
	src := &puBlock{loadErr: errors.New("read failed")}
	h := newPerUserBundleHarness(t, src, nil, nil)
	h.ps.Refresh()
	rec := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Body.String() != "ok\n" {
		t.Errorf("healthz = %q, want ok with the feature off", rec.Body.String())
	}
}
