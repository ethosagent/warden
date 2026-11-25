package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
)

// Signed bundles (W-P2-SBND-02). With --bundles=offer or require the control
// plane signs what it serves on GET /policy with its active purpose=bundle
// key and serves the envelope to workers that ask for it with the bundle
// Accept header. Everything here is behind the flag: with --bundles=off
// (the default) no publisher exists and /policy is the code it always was.
//
// The invariant the design rests on: a seq never covers two different
// contents. seq is the newest policy_publish_log row; every input of the
// signed content either moves the served policy ETag (policy, block list,
// credential, ... each append a row) or is tracked here and appends a row of
// its own first (the token JWKS, reason token_jwks; the token issuer, reason
// token_issuer). The publisher signs only
// when the newest row is the one that describes the content it is about to
// sign, and it refuses to re-sign a seq with different content.

// The --bundles modes.
const (
	BundlesOff     = "off"
	BundlesOffer   = "offer"
	BundlesRequire = "require"
)

const (
	// BundleMediaType is the Accept header value that asks for the envelope,
	// and the Content-Type the envelope is served with.
	BundleMediaType = "application/vnd.warden.bundle.v1+json"
	// DefaultBundleMaxAge is --bundle-max-age's default: how long a signed
	// bundle stays valid (expiresAt = issuedAt + max age).
	DefaultBundleMaxAge = 24 * time.Hour
	// MinBundleMaxAge is the shortest accepted --bundle-max-age.
	MinBundleMaxAge = time.Hour

	// sectionTokenJWKS is the payload section that carries the token JWKS.
	sectionTokenJWKS = "tokenJWKS"
	// publishActorBundle is the actor of rows the bundle publisher appends.
	publishActorBundle = "system:bundle"
	// bundleRetryAfter is the Retry-After of a 503 for a missing envelope.
	bundleRetryAfter = 5
	// stateCPID and stateJWKSSHA are the bundle_state names.
	stateCPID      = "cp_id"
	stateJWKSSHA   = "jwks_sha256"
	stateIssuerSHA = "token_issuer_sha256"
	// stateSigned is "<seq>:<content fingerprint>" of the newest envelope
	// signed. It outlives a restart, so a seq can never be signed twice with
	// different content, whatever changed while the control plane was down.
	stateSigned = "signed"

	// MaxBundleSeqFloor bounds --bundle-seq-floor far below the int64 range,
	// so a typo cannot exhaust the seq space.
	MaxBundleSeqFloor = 1 << 53
)

// BundlesConfig is the --bundles, --bundle-max-age and --bundle-seq-floor
// settings, resolved and validated by Run.
type BundlesConfig struct {
	// Mode is off (the zero value counts as off), offer or require.
	Mode string
	// MaxAge is how long a signed bundle is valid; 0 = DefaultBundleMaxAge.
	MaxAge time.Duration
	// SeqFloor appends one restore row at this seq at startup when the
	// publish log is below it (0 = never).
	SeqFloor int64
}

// On reports whether signed bundles are served at all.
func (c BundlesConfig) On() bool { return c.Mode == BundlesOffer || c.Mode == BundlesRequire }

func (c BundlesConfig) maxAge() time.Duration {
	if c.MaxAge <= 0 {
		return DefaultBundleMaxAge
	}
	return c.MaxAge
}

// resolveBundles validates the bundle flags against the rest of the startup
// configuration. Offer and require need a state dir, the versioned policy
// store and the signing keys; an error names every piece that is missing.
func resolveBundles(p Params, stateDir, policyStore string, kc config.KeysConfig) (BundlesConfig, error) {
	cfg := BundlesConfig{Mode: p.Bundles, MaxAge: p.BundleMaxAge, SeqFloor: p.BundleSeqFloor}
	switch cfg.Mode {
	case "":
		cfg.Mode = BundlesOff
	case BundlesOff, BundlesOffer, BundlesRequire:
	default:
		return BundlesConfig{}, fmt.Errorf("control-plane: --bundles must be off, offer or require, not %q", cfg.Mode)
	}
	if cfg.MaxAge != 0 && cfg.MaxAge < MinBundleMaxAge {
		return BundlesConfig{}, fmt.Errorf("control-plane: --bundle-max-age %s is below the minimum %s", cfg.MaxAge, MinBundleMaxAge)
	}
	if cfg.SeqFloor < 0 || cfg.SeqFloor > MaxBundleSeqFloor {
		return BundlesConfig{}, fmt.Errorf("control-plane: --bundle-seq-floor %d must be between 0 and %d", cfg.SeqFloor, int64(MaxBundleSeqFloor))
	}
	if !cfg.On() {
		return cfg, nil
	}
	var missing []string
	if stateDir == "" {
		missing = append(missing, "--state-dir")
	}
	if policyStore != PolicyStoreVersioned {
		missing = append(missing, "--policy-store=versioned")
	}
	if !kc.Enabled {
		missing = append(missing, "keys.enabled: true in --config (the purpose=bundle signing key)")
	}
	if len(missing) > 0 {
		return BundlesConfig{}, fmt.Errorf("control-plane: --bundles=%s needs %s", cfg.Mode, strings.Join(missing, ", "))
	}
	return cfg, nil
}

// BundleMigrations is the cpstate migration of the bundle publisher's two
// values: the control plane id and the token JWKS hash the publish log last
// covered. Registered in every mode, like the policy store's, so switching
// --bundles never trips the downgrade guard.
func BundleMigrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID:  "bundles/0001",
		SQL: `CREATE TABLE bundle_state (name TEXT PRIMARY KEY, value TEXT NOT NULL);`,
	}}
}

// bundleState reads and writes the bundle_state table.
type bundleState struct{ db *sql.DB }

func (s bundleState) get(ctx context.Context, name string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM bundle_state WHERE name = ?`, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("bundle state: read %s: %w", name, err)
	}
	return v, true, nil
}

func (s bundleState) put(ctx context.Context, name, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO bundle_state (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value`,
		name, value)
	if err != nil {
		return fmt.Errorf("bundle state: write %s: %w", name, err)
	}
	return nil
}

// cpID returns the control plane id, generating and storing it on first use.
// The insert-or-ignore makes two starts racing for the first id agree.
func (s bundleState) cpID(ctx context.Context) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("bundle state: generate cp id: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO bundle_state (name, value) VALUES (?, ?)`, stateCPID, "cp_"+hex.EncodeToString(raw[:])); err != nil {
		return "", fmt.Errorf("bundle state: store cp id: %w", err)
	}
	id, ok, err := s.get(ctx, stateCPID)
	if err != nil {
		return "", err
	}
	if !ok || id == "" {
		return "", errors.New("bundle state: cp id missing after insert")
	}
	return id, nil
}

// bundleKeys is the slice of *keys.KeySet the publisher needs: the signers
// and the public JWKS of a purpose, and change notifications. Signers is the
// active key first, then the staged next key during a staged bundle rotation:
// every envelope carries a signature of each, so a worker that pins either
// verifies it.
type bundleKeys interface {
	Signers(purpose string) ([]keys.Signer, error)
	JWKS(purpose string) keys.JWKS
	Subscribe(fn func(purpose string)) (unsubscribe func())
}

// signedBundle is one signed envelope with what the publisher and the long
// poll need to know about it.
type signedBundle struct {
	env       []byte
	etag      string // 16 hex of the envelope bytes
	seq       int64
	kids      []string // the signing kids: the active key, then any staged one
	issuedAt  time.Time
	expiresAt time.Time
	// fp fingerprints the signed content (policy, credential, sections), so a
	// re-sign of the same seq can prove it signs the same content.
	fp string
	// tokenKIDs are the kids of the tokenJWKS section this envelope signs: the
	// keys a worker holds once it applies it. The token mint guard reads them.
	tokenKIDs map[string]struct{}
}

// bundlePublisher builds and signs the envelope. Its mutable state is guarded
// by policyServer.refreshMu, the one lock every build runs under.
type bundlePublisher struct {
	cfg    BundlesConfig
	keys   bundleKeys
	state  bundleState
	now    func() time.Time
	logger *slog.Logger

	active bool
	cpID   string
	// jwks and issuer are the signed inputs that move no policy ETag, each
	// tracked so a change appends a row of its own before signing.
	jwks   trackedInput
	issuer trackedInput
	// tokenIssuer is tokenService.issuer, signed as the payload's tokenIssuer
	// ("" = the control plane mints no tokens). Guarded by refreshMu.
	tokenIssuer string
	// signedSeq and signedFP are the persisted newest signed (seq, content
	// fingerprint); signedSeq 0 = nothing signed yet.
	signedSeq int64
	signedFP  string
	cur       *signedBundle
	unsub     func()

	// degraded is set while the newest publish could not be signed or
	// published; /healthz reports it.
	degraded atomic.Bool
}

func newBundlePublisher(cfg BundlesConfig, k bundleKeys, db *sql.DB, now func() time.Time, logger *slog.Logger) *bundlePublisher {
	return &bundlePublisher{
		cfg: cfg, keys: k, state: bundleState{db: db}, now: now, logger: logger,
		jwks:   trackedInput{stateKey: stateJWKSSHA, reason: publishReasonTokenJWKS},
		issuer: trackedInput{stateKey: stateIssuerSHA, reason: publishReasonTokenIssuer, zeroBaseline: true},
	}
}

// trackedInput is one signed input that moves no policy ETag: the hash the
// publish log last covered, persisted so a restart notices a change made while
// the control plane was down.
type trackedInput struct {
	stateKey, reason string
	// sha is the covered hash; known is false until one was stored.
	sha   string
	known bool
	// zeroBaseline treats a never-stored hash as the hash of "nothing": the
	// first sight of a non-empty value then counts as a change. It is how a
	// control plane upgraded to a build that signs this input gets the row
	// that keeps one seq from covering two contents.
	zeroBaseline bool
}

// load reads the stored hash.
func (in *trackedInput) load(ctx context.Context, st bundleState) error {
	sha, ok, err := st.get(ctx, in.stateKey)
	if err != nil {
		return err
	}
	if ok {
		in.sha, in.known = sha, true
	}
	return nil
}

// hashOf is the covered form of a plain string value ("" stays "").
func hashOf(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// cover makes sure the publish log describes the current value cur: a change
// appends a marker row at head (reason in.reason), then the hash is stored. Row
// first, then the stored hash: a crash in between costs one extra row at the
// next start, never an uncovered change. A failed put is a sign failure:
// signing on would let a restart forget the change this row covered. The
// caller holds refreshMu.
func (ps *policyServer) cover(ctx context.Context, in *trackedInput, cur string, head int64, etag string) error {
	b := ps.bundles
	if (in.known || in.zeroBaseline) && cur != in.sha {
		if _, err := ps.versions.AppendMarker(ctx, head, etag, in.reason, publishActorBundle); err != nil {
			return fmt.Errorf("append %s row: %w", in.reason, err)
		}
		b.logger.Info("policy publish logged", "version", head, "etag", etag, "reason", in.reason)
	}
	if !in.known || cur != in.sha {
		if err := b.state.put(ctx, in.stateKey, cur); err != nil {
			return err
		}
		in.sha, in.known = cur, true
	}
	return nil
}

// setTokenIssuer installs tokenService.issuer as the payload's tokenIssuer and
// signs again when the publisher is already running. The issuer is a public
// URL; it is the only token-service value that enters a bundle.
func (ps *policyServer) setTokenIssuer(iss string) {
	if ps.bundles == nil {
		return
	}
	ps.refreshMu.Lock()
	changed := ps.bundles.tokenIssuer != iss
	ps.bundles.tokenIssuer = iss
	active := ps.bundles.active
	ps.refreshMu.Unlock()
	if changed && active {
		ps.refresh(false)
	}
}

// BundlesOn reports whether this server serves signed bundles.
func (ps *policyServer) bundlesOn() bool { return ps.bundles != nil }

// bundleDegraded reports whether the newest publish could not be signed.
func (ps *policyServer) bundleDegraded() bool {
	return ps.bundles != nil && ps.bundles.degraded.Load()
}

// startBundles brings the publisher up once the keys are loaded and the first
// versioned head exists: it loads (or creates) the control plane id and the
// JWKS baseline, appends the --bundle-seq-floor restore row, subscribes to
// key transitions and signs the first envelope. An error means the control
// plane must not start: it cannot honour the mode it was asked for.
func (ps *policyServer) startBundles(ctx context.Context) error {
	b := ps.bundles
	if b == nil {
		return nil
	}
	ps.refreshMu.Lock()
	defer ps.refreshMu.Unlock()
	if ps.versions == nil {
		return errors.New("control-plane: --bundles needs --policy-store=versioned")
	}
	if _, err := b.keys.Signers(keys.PurposeBundle); err != nil {
		return fmt.Errorf("control-plane: --bundles=%s needs a loadable purpose=bundle signing key: %w", b.cfg.Mode, err)
	}
	id, err := b.state.cpID(ctx)
	if err != nil {
		return fmt.Errorf("control-plane: %w", err)
	}
	b.cpID = id
	for _, in := range []*trackedInput{&b.jwks, &b.issuer} {
		if err := in.load(ctx, b.state); err != nil {
			return fmt.Errorf("control-plane: %w", err)
		}
	}
	if v, ok, err := b.state.get(ctx, stateSigned); err != nil {
		return fmt.Errorf("control-plane: %w", err)
	} else if ok {
		seq, fp, found := strings.Cut(v, ":")
		n, perr := strconv.ParseInt(seq, 10, 64)
		if !found || perr != nil || n < 1 || fp == "" {
			return errors.New("control-plane: bundle_state has an unreadable signed record; refusing to start")
		}
		b.signedSeq, b.signedFP = n, fp
	}
	if !ps.loaded {
		return errors.New("control-plane: --bundles needs a loaded policy")
	}
	if b.cfg.SeqFloor > 0 {
		if err := ps.applySeqFloor(ctx); err != nil {
			return err
		}
	}
	b.active = true
	b.unsub = b.keys.Subscribe(ps.onKeysChanged)
	ps.publishBundle(ctx, ps.lastWire, ps.lastETag, ps.lastHead, true)
	b.logger.Info("control plane bundles", "mode", b.cfg.Mode, "maxAge", b.cfg.maxAge().String(), "seqFloor", b.cfg.SeqFloor)
	return nil
}

// applySeqFloor appends the restore row when the log is below the floor. A
// floor that cannot be applied stops startup: pinned workers would reject
// every new bundle as a rollback.
func (ps *policyServer) applySeqFloor(ctx context.Context) error {
	b := ps.bundles
	if ps.lastHead == 0 {
		return fmt.Errorf("control-plane: --bundle-seq-floor %d cannot be applied: no policy head yet", b.cfg.SeqFloor)
	}
	appended, err := ps.versions.AppendRestore(ctx, b.cfg.SeqFloor, ps.lastHead, ps.lastETag, publishActorBundle)
	if err != nil {
		return fmt.Errorf("control-plane: --bundle-seq-floor %d cannot be applied: %s", b.cfg.SeqFloor, boundedErr(err))
	}
	if appended {
		b.logger.Info("bundle seq floor applied", "seq", b.cfg.SeqFloor, "reason", publishReasonRestore)
	}
	return nil
}

// stopBundles ends the key subscription.
func (ps *policyServer) stopBundles() {
	ps.refreshMu.Lock()
	defer ps.refreshMu.Unlock()
	if b := ps.bundles; b != nil && b.unsub != nil {
		b.unsub()
		b.unsub = nil
	}
}

// onKeysChanged is the KeySet.Subscribe callback. A token transition changes
// the JWKS section, which publishBundle turns into a token_jwks row before it
// signs; a bundle key transition only re-signs the same content, so the
// worker sees a refresh, not a new seq.
func (ps *policyServer) onKeysChanged(purpose string) {
	switch purpose {
	case keys.PurposeToken:
		ps.refresh(false)
	case keys.PurposeBundle:
		ps.refresh(true)
	}
}

// resignLoop re-signs the current content every max-age/4 with the same seq,
// so a worker's applied bundle never reaches expiresAt while the control
// plane is up. It runs on clk and returns when ctx ends.
func (ps *policyServer) resignLoop(ctx context.Context, clk clock.Clock) {
	b := ps.bundles
	if b == nil {
		return
	}
	defer ps.stopBundles()
	interval := b.cfg.maxAge() / 4
	for waitOn(ctx, clk, interval) {
		ps.refresh(true)
	}
}

// publishBundle signs the content (wire at head with served ETag etag) and
// hands the envelope to the watch. force re-signs even when the content and
// seq are unchanged. It never returns an error: on any failure the last
// envelope stays served and the publisher is marked degraded. The caller
// holds refreshMu.
func (ps *policyServer) publishBundle(ctx context.Context, wire policyWire, etag string, head int64, force bool) {
	b := ps.bundles
	if b == nil || !b.active || head == 0 {
		return
	}
	signers, err := b.keys.Signers(keys.PurposeBundle)
	if err != nil {
		b.fail(ctx, 0, "", err)
		return
	}
	kids := make([]string, len(signers))
	for i, sg := range signers {
		kids[i] = sg.KID()
	}
	kid := signers[0].KID() // the active key, for failure lines
	jwks, jsha, tokenKIDs, err := tokenJWKSSection(b.keys)
	if err != nil {
		b.fail(ctx, 0, kid, err)
		return
	}
	// The JWKS and the token issuer are signed content that moves no policy
	// ETag, so a change takes a row of its own first; otherwise one seq would
	// cover two contents.
	if err := ps.cover(ctx, &b.jwks, jsha, head, etag); err != nil {
		b.fail(ctx, 0, kid, err)
		return
	}
	if err := ps.cover(ctx, &b.issuer, hashOf(b.tokenIssuer), head, etag); err != nil {
		b.fail(ctx, 0, kid, err)
		return
	}
	last, ok, err := ps.versions.LatestPublish(ctx)
	if err != nil {
		b.fail(ctx, 0, kid, err)
		return
	}
	if !ok || last.Version != head || last.ETag != etag {
		// The newest row does not describe this content (a failed or racing
		// append): signing now could put two contents under one seq.
		b.logger.Warn("control plane: bundle not signed: the publish log is behind the served policy",
			"seq", last.Seq, "version", head)
		return
	}
	policy, creds, err := bundlePolicy(wire)
	if err != nil {
		b.fail(ctx, last.Seq, kid, err)
		return
	}
	fp := contentFingerprint(policy, creds, jwks, b.tokenIssuer)
	cur := b.cur
	switch {
	case b.signedSeq > last.Seq:
		b.logger.Error("control plane: the publish log is behind the newest signed bundle; refusing to sign (set --bundle-seq-floor)",
			"seq", last.Seq, "signedSeq", b.signedSeq)
		b.degraded.Store(true)
		return
	case b.signedSeq == last.Seq && b.signedFP != fp:
		b.logger.Error("control plane: bundle content changed under an unchanged seq; refusing to sign", "seq", last.Seq)
		b.degraded.Store(true)
		return
	case cur != nil && cur.seq > last.Seq:
		return // an older build lost a race; the newer envelope stays
	case cur != nil && cur.seq == last.Seq && !force:
		return
	}
	now := b.now().UTC()
	if cur != nil && cur.seq == last.Seq && !now.After(cur.issuedAt) {
		now = cur.issuedAt.Add(time.Millisecond) // a refresh must carry a newer issuedAt
	}
	bd := bundle.Bundle{
		Seq:           last.Seq,
		PolicyVersion: head,
		IssuedAt:      now,
		ExpiresAt:     now.Add(b.cfg.maxAge()),
		CPID:          b.cpID,
		Policy:        policy,
		TokenIssuer:   b.tokenIssuer,
	}
	// One section today. The ticket that adds a second one (for example the
	// registry section, W-P4-MREG-05) should turn jwks into a section list, so
	// each section is fingerprinted and each owns a publish-log reason.
	if jwks != nil {
		bd.Sections = map[string]json.RawMessage{sectionTokenJWKS: jwks}
	}
	env, err := bundle.Sign(ctx, bd, creds, signers...)
	if err != nil {
		if errors.Is(err, bundle.ErrTooLarge) {
			b.logger.Error("bundle too large; not published", "seq", last.Seq, "limit", bundle.MaxEnvelopeBytes)
			b.degraded.Store(true)
			return
		}
		b.fail(ctx, last.Seq, kid, err)
		return
	}
	sum := sha256.Sum256(env)
	sb := &signedBundle{
		env: env, etag: hex.EncodeToString(sum[:8]), seq: last.Seq, kids: kids,
		issuedAt: now, expiresAt: bd.ExpiresAt, fp: fp, tokenKIDs: tokenKIDs,
	}
	// Persist before publishing: an envelope nobody can prove was recorded is
	// never served.
	if err := b.state.put(ctx, stateSigned, strconv.FormatInt(sb.seq, 10)+":"+fp); err != nil {
		b.fail(ctx, last.Seq, kid, err)
		return
	}
	b.signedSeq, b.signedFP = sb.seq, fp
	b.cur = sb
	b.degraded.Store(false)
	ps.watch.setBundle(sb)
	b.logger.Info("bundle signed", "seq", sb.seq, "kids", sb.kids, "digest", payloadDigest(env), "bytes", len(env))
}

// fail records a signing failure: the last envelope keeps being served, the
// publisher reports degraded, and the log line carries the seq and kid only
// (never payload content or the credential).
func (b *bundlePublisher) fail(_ context.Context, seq int64, kid string, err error) {
	b.degraded.Store(true)
	b.logger.Error("bundle sign failed", "seq", seq, "kid", kid, "error", boundedErr(err))
}

// tokenJWKSSection returns the token JWKS as the tokenJWKS section (nil when
// no token key is published), the SHA-256 of it, hex, and the set of its kids.
func tokenJWKSSection(k bundleKeys) (json.RawMessage, string, map[string]struct{}, error) {
	set := k.JWKS(keys.PurposeToken)
	if len(set.Keys) == 0 {
		return nil, "", nil, nil
	}
	raw, err := json.Marshal(set)
	if err != nil {
		return nil, "", nil, fmt.Errorf("encode token jwks: %w", err)
	}
	kids := make(map[string]struct{}, len(set.Keys))
	for _, j := range set.Keys {
		kids[j.Kid] = struct{}{}
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), kids, nil
}

// servesBundleTokenKID is the bundle half of the token mint guard. With bundles
// off it is true: workers do not take token keys from a bundle, so there is
// nothing more to wait for. With bundles on it is true only when the envelope
// served now (the last one signed, which stays served while the publisher is
// degraded) carries kid in its tokenJWKS section, so a key is never used to
// mint before a pinned worker can hold it. No envelope yet is false.
func (ps *policyServer) servesBundleTokenKID(kid string) bool {
	if ps.bundles == nil {
		return true
	}
	sb, _ := ps.watch.bundleSnapshot()
	if sb == nil {
		return false
	}
	_, ok := sb.tokenKIDs[kid]
	return ok
}

// bundlePolicy splits the served wire into the signed policy bytes and the
// credential sidecar: the sanctioned AWS credential leaves settings.secrets
// and travels beside the signed payload, committed to by its hash.
func bundlePolicy(wire policyWire) (json.RawMessage, *bundle.Credentials, error) {
	var creds *bundle.Credentials
	if wire.Settings != nil && wire.Settings.Secrets != nil {
		sec := *wire.Settings.Secrets
		if sec.AccessKeyID != "" || sec.SecretAccessKey != "" {
			creds = &bundle.Credentials{AccessKeyID: sec.AccessKeyID, SecretAccessKey: sec.SecretAccessKey}
		}
		sec.AccessKeyID, sec.SecretAccessKey = "", ""
		settings := *wire.Settings
		settings.Secrets = &sec
		wire.Settings = &settings
	}
	raw, err := json.Marshal(projectScoped(wire))
	if err != nil {
		return nil, nil, fmt.Errorf("encode policy: %w", err)
	}
	return raw, creds, nil
}

// contentFingerprint is a hash over everything a seq's signed content is made
// of. The credential goes in by its own hash, so the fingerprint is safe to
// keep in memory.
func contentFingerprint(policy json.RawMessage, creds *bundle.Credentials, jwks json.RawMessage, tokenIssuer string) string {
	h := sha256.New()
	for _, part := range [][]byte{policy, jwks} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		_, _ = h.Write(n[:])
		_, _ = h.Write(part)
	}
	if creds != nil {
		cs := sha256.Sum256([]byte(creds.AccessKeyID + "\x00" + creds.SecretAccessKey))
		_, _ = h.Write(cs[:])
	}
	if tokenIssuer != "" {
		// Only when set, so a control plane without a token service keeps the
		// fingerprint it persisted before the issuer was signed.
		_, _ = h.Write([]byte("tokenIssuer\x00" + tokenIssuer))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// payloadDigest is the 16-hex SHA-256 prefix of the envelope's decoded
// payload: a fingerprint for the log that reveals nothing of the content.
func payloadDigest(env []byte) string {
	var e struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(env, &e) != nil {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(e.Payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// acceptsBundle reports whether the request's Accept header names the bundle
// media type with a non-zero quality.
func acceptsBundle(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept") {
		for _, item := range strings.Split(v, ",") {
			mt, params, _ := strings.Cut(item, ";")
			if !strings.EqualFold(strings.TrimSpace(mt), BundleMediaType) {
				continue
			}
			if q, ok := acceptQuality(params); ok && q <= 0 {
				continue
			}
			return true
		}
	}
	return false
}

// acceptQuality extracts a q= parameter from the parameter part of an Accept
// item.
func acceptQuality(params string) (float64, bool) {
	for _, p := range strings.Split(params, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
			q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return q, err == nil
		}
	}
	return 0, false
}

// writeBundleError writes the fixed JSON error of the bundle negotiation.
func writeBundleError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", strconv.Itoa(bundleRetryAfter))
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// initBundles builds the publisher when the config asks for bundles and its
// prerequisites are there (Run has already refused to start without them, so
// a gap here is a wiring mistake and is logged loudly). It runs in New before
// the first load, but the publisher stays inactive until startBundles.
func (s *Server) initBundles() {
	if !s.cfg.Bundles.On() {
		return
	}
	k := s.cfg.bundleKeys
	if k == nil && s.cfg.Keys != nil {
		k = s.cfg.Keys.KeySet()
	}
	if k == nil || s.cfg.State == nil || s.policy.versions == nil {
		s.cfg.Logger.Error("control plane: --bundles needs --state-dir, --policy-store=versioned and keys.enabled; bundles stay off",
			"mode", s.cfg.Bundles.Mode)
		return
	}
	s.policy.bundles = newBundlePublisher(s.cfg.Bundles, k, s.cfg.State.SQL(), s.cfg.Clock.Now, s.cfg.Logger)
}
