package identity

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/keys"
)

// MaxWardenTokenTTL is the longest exp-iat a Warden token may have. The token
// service mints far shorter ones; the cap bounds what a verifier will honour.
const MaxWardenTokenTTL = 15 * time.Minute

const (
	wardenCacheSize = 10_000
	// maxLoggedKID bounds the attacker-chosen kid a debug line may carry.
	maxLoggedKID = 64
)

// ErrStaleSnapshot is returned by SetSnapshot for a snapshot older than the
// one installed.
var ErrStaleSnapshot = errors.New("identity: stale warden snapshot")

// WardenAgent is one registered agent as the verified bundle serves it: whether
// it is active and the thumbprints of its current keys. Agent binding
// (W-P2-WBND-02) reads it from the same snapshot as the keys, so a key and the
// agent list it is checked against always come from one bundle.
type WardenAgent struct {
	// Active is true only for status "active"; anything else is disabled
	// (fail closed).
	Active bool
	// JKT is the set of RFC 7638 thumbprints of the agent's registered keys.
	JKT map[string]struct{}
}

// WardenBundle is the input of one snapshot: the facts of one verified bundle
// that Warden token verification and binding need. Generation is the bundle's
// seq.
type WardenBundle struct {
	Generation  int64
	TokenIssuer string
	JWKS        []keys.JWK
	Agents      map[string]WardenAgent
}

// WardenSnapshot is the immutable verification state built from one
// WardenBundle. It is the unit that is swapped atomically: keys, issuer and
// agents never mix across bundles.
type WardenSnapshot struct {
	generation int64
	issuer     string
	keys       map[string]keys.JWK
	agents     map[string]WardenAgent
}

// NewWardenSnapshot builds a snapshot from b. A JWK with no kid, a duplicate
// kid or a key that is not a usable public key is an error: the whole snapshot
// is refused rather than installing some of the keys.
func NewWardenSnapshot(b WardenBundle) (*WardenSnapshot, error) {
	s := &WardenSnapshot{
		generation: b.Generation, issuer: b.TokenIssuer,
		keys:   make(map[string]keys.JWK, len(b.JWKS)),
		agents: make(map[string]WardenAgent, len(b.Agents)),
	}
	for i, j := range b.JWKS {
		if j.Kid == "" {
			return nil, fmt.Errorf("identity: warden jwks: key %d has no kid", i)
		}
		if _, dup := s.keys[j.Kid]; dup {
			return nil, fmt.Errorf("identity: warden jwks: key %d repeats a kid", i)
		}
		if _, err := j.PublicKey(); err != nil {
			return nil, fmt.Errorf("identity: warden jwks: key %d: %w", i, err)
		}
		s.keys[j.Kid] = j
	}
	for id, a := range b.Agents {
		jkt := make(map[string]struct{}, len(a.JKT))
		for t := range a.JKT {
			jkt[t] = struct{}{}
		}
		s.agents[id] = WardenAgent{Active: a.Active, JKT: jkt}
	}
	return s, nil
}

// Generation is the snapshot's generation (the bundle seq).
func (s *WardenSnapshot) Generation() int64 {
	if s == nil {
		return 0
	}
	return s.generation
}

// Issuer is the token issuer the snapshot accepts; empty means the control
// plane mints no Warden tokens.
func (s *WardenSnapshot) Issuer() string {
	if s == nil {
		return ""
	}
	return s.issuer
}

// Available reports whether the snapshot can verify any token: it has an
// issuer and at least one key. Without that every Warden token is unverified
// with reason jwks_unavailable.
func (s *WardenSnapshot) Available() bool {
	return s != nil && s.issuer != "" && len(s.keys) > 0
}

// Agent returns the registered agent with id. It reads the snapshot only and
// never allocates.
func (s *WardenSnapshot) Agent(id string) (WardenAgent, bool) {
	if s == nil {
		return WardenAgent{}, false
	}
	a, ok := s.agents[id]
	return a, ok
}

// WardenConfig configures NewWardenVerifier.
type WardenConfig struct {
	// ClockSkew is the exp/nbf tolerance; 0 means DefaultClockSkew.
	ClockSkew time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// CacheSize bounds the result cache; 0 means the default.
	CacheSize int
	// Logger receives debug lines carrying only a kid and a token fingerprint.
	// nil logs nothing.
	Logger *slog.Logger
}

// WardenVerifier verifies the Warden tokens the control plane mints. Its keys,
// issuer and agents come only from a WardenSnapshot built from a verified
// bundle; it never fetches keys. Until a usable snapshot is installed every
// token is unverified (jwks_unavailable). It is safe for concurrent use.
type WardenVerifier struct {
	snap atomic.Pointer[WardenSnapshot]
	// epoch counts snapshot and skew changes. A Verify captures it before it
	// reads either, and its cache key carries it, so a result computed under
	// an older snapshot or skew is never found by a later Verify, however late
	// it is stored.
	epoch atomic.Uint64
	skew  atomic.Int64 // nanoseconds
	now   func() time.Time
	cache *wardenCache
	log   *slog.Logger
	// setMu serializes SetSnapshot so the generation check and the swap are
	// one step.
	setMu sync.Mutex
}

// NewWardenVerifier builds a verifier with no snapshot.
func NewWardenVerifier(cfg WardenConfig) (*WardenVerifier, error) {
	switch {
	case cfg.ClockSkew < 0 || cfg.ClockSkew > MaxClockSkew:
		return nil, errors.New("identity: warden verifier: clock skew must be between 0 and 5m")
	case cfg.ClockSkew == 0:
		cfg.ClockSkew = DefaultClockSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = wardenCacheSize
	}
	v := &WardenVerifier{now: cfg.Now, cache: newWardenCache(cfg.CacheSize), log: cfg.Logger}
	v.skew.Store(int64(cfg.ClockSkew))
	return v, nil
}

// SetClockSkew changes the exp/nbf tolerance (identity.clockSkewSeconds) with
// the same bounds as the constructor, 0 meaning the default. Results cached
// under the old tolerance are dropped. A change that is refused leaves the
// tolerance as it was.
func (v *WardenVerifier) SetClockSkew(d time.Duration) error {
	switch {
	case d < 0 || d > MaxClockSkew:
		return errors.New("identity: warden verifier: clock skew must be between 0 and 5m")
	case d == 0:
		d = DefaultClockSkew
	}
	if time.Duration(v.skew.Swap(int64(d))) != d {
		v.epoch.Add(1) // after the store: see Verify
		v.cache.reset()
	}
	return nil
}

// SetSnapshot installs s atomically. The generation must not go backwards
// (ErrStaleSnapshot). Results cached under an older generation can never be
// served again, because the cache key carries the generation; an equal
// generation replaces the snapshot and also drops the cache, since its
// content may differ. A nil s is refused.
func (v *WardenVerifier) SetSnapshot(s *WardenSnapshot) error {
	if s == nil {
		return errors.New("identity: warden snapshot is nil")
	}
	v.setMu.Lock()
	defer v.setMu.Unlock()
	if cur := v.snap.Load(); cur != nil {
		switch {
		case s.generation < cur.generation:
			return ErrStaleSnapshot
		case s.generation == cur.generation:
			v.cache.reset()
		}
	}
	v.snap.Store(s)
	v.epoch.Add(1) // after the store: a Verify that sees the new epoch sees the new snapshot
	return nil
}

// Snapshot returns the installed snapshot, nil before the first one. The
// binding check (W-P2-WBND-02) reads the agents from it.
func (v *WardenVerifier) Snapshot() *WardenSnapshot { return v.snap.Load() }

// ClockSkew returns the effective exp/nbf tolerance.
func (v *WardenVerifier) ClockSkew() time.Duration { return time.Duration(v.skew.Load()) }

// wardenPayload is the part of a Warden token's payload the verifier reads. It
// mirrors WardenClaims, but aud may be a string or a list and numbers are
// decoded strictly so a malformed value is malformed, not zero.
type wardenPayload struct {
	Ver             *int            `json:"ver"`
	Iss             string          `json:"iss"`
	Aud             json.RawMessage `json:"aud"`
	Sub             string          `json:"sub"`
	Email           string          `json:"email"`
	EmailVerified   bool            `json:"email_verified"`
	Groups          []string        `json:"groups"`
	GroupsTruncated bool            `json:"groups_truncated"`
	Act             *WardenActor    `json:"act"`
	SID             string          `json:"sid"`
	JTI             string          `json:"jti"`
	Iat             *int64          `json:"iat"`
	Nbf             *int64          `json:"nbf"`
	Exp             *int64          `json:"exp"`
	Scope           string          `json:"scope"`
	Cnf             *struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// Verify checks raw as a Warden token against the installed snapshot. Every
// result carries TokenType warden; the claims of a token that failed after its
// signature verified keep the authentic sub and email (the block-list check
// uses them: a match can only deny), and a token that failed earlier carries
// nothing but the type. The raw token goes nowhere but the checks.
func (v *WardenVerifier) Verify(_ context.Context, raw string, opts ...VerifyOption) (Claims, Status, Reason) {
	bare := Claims{TokenType: TokenWarden}
	if len(raw) > MaxTokenBytes {
		return bare, StatusInvalid, ReasonTooLarge
	}
	if raw == "" {
		return bare, StatusInvalid, ReasonMalformed
	}
	o := ApplyOptions(opts...)
	epoch := v.epoch.Load() // before the snapshot and the skew
	snap := v.snap.Load()
	if !snap.Available() {
		return bare, StatusUnverified, ReasonJWKSUnavailable
	}
	if o.NonceSet {
		// A Warden token has no nonce: it can never answer a console login.
		return bare, StatusInvalid, ReasonWrongNonce
	}
	now := v.now()
	skew := v.ClockSkew()
	sum := sha256.Sum256([]byte(raw))
	ck := wardenKey{gen: snap.generation, epoch: epoch, sum: sum}
	if c, ok := v.cache.get(ck, now); ok {
		return c, StatusValid, ""
	}

	hdr, payload, signingInput, sig, err := keys.ParseCompact(raw)
	if err != nil {
		if errors.Is(err, keys.ErrUnsupportedAlg) {
			return bare, StatusInvalid, ReasonAlgNotAllowed
		}
		return bare, StatusInvalid, ReasonMalformed
	}
	if hdr.Typ != WardenTokenTyp {
		return bare, StatusInvalid, ReasonMalformed
	}
	jwk, ok := snap.keys[hdr.Kid]
	if !ok {
		v.debug("warden token refused", ReasonUnknownKID, hdr.Kid, sum)
		return bare, StatusInvalid, ReasonUnknownKID
	}
	if err := keys.Verify(jwk, hdr.Alg, signingInput, sig); err != nil {
		r := ReasonBadSignature
		if errors.Is(err, keys.ErrAlgMismatch) || errors.Is(err, keys.ErrUnsupportedAlg) {
			r = ReasonAlgNotAllowed
		}
		v.debug("warden token refused", r, hdr.Kid, sum)
		return bare, StatusInvalid, r
	}

	// The signature verified: from here the claims are the control plane's.
	var p wardenPayload
	if json.Unmarshal(payload, &p) != nil {
		return bare, StatusInvalid, ReasonMalformed
	}
	uv := Claims{Sub: p.Sub, Email: p.Email, EmailVerified: p.EmailVerified, Issuer: p.Iss, KID: hdr.Kid, TokenType: TokenWarden}
	if p.Exp != nil {
		uv.Expiry = time.Unix(*p.Exp, 0)
	}
	fail := func(r Reason) (Claims, Status, Reason) {
		v.debug("warden token refused", r, hdr.Kid, sum)
		return uv, StatusInvalid, r
	}
	switch {
	case p.Iss != snap.issuer:
		return fail(ReasonWrongIss)
	case !audContains(p.Aud, WardenAudience):
		return fail(ReasonWrongAud)
	case p.Ver == nil || *p.Ver != WardenTokenVer, p.Exp == nil, p.Iat == nil, *p.Iat <= 0, *p.Exp <= *p.Iat:
		return fail(ReasonMalformed)
	case p.Sub == "", p.Act == nil, p.Act.Sub == "", p.SID == "", p.JTI == "", p.Cnf == nil, p.Cnf.JKT == "":
		return fail(ReasonMissingClaim)
	// Compared in seconds: iat > 0 and exp > iat above, so the subtraction
	// cannot wrap and no Duration is built from an attacker-sized number.
	case *p.Exp-*p.Iat > int64(MaxWardenTokenTTL/time.Second):
		return fail(ReasonTTLTooLong)
	case *p.Iat > now.Add(skew).Unix():
		return fail(ReasonMalformed) // issued in the future
	}
	exp := time.Unix(*p.Exp, 0)
	if now.After(exp.Add(skew)) {
		v.debug("warden token expired", "", hdr.Kid, sum)
		return uv, StatusExpired, ""
	}
	// The bounded Reason set has no not-yet-valid value; malformed is deliberate.
	if p.Nbf != nil && now.Add(skew).Before(time.Unix(*p.Nbf, 0)) {
		return fail(ReasonMalformed)
	}
	groups, trunc := NormalizeGroups(p.Groups)
	c := Claims{
		Sub: p.Sub, Email: p.Email, EmailVerified: p.EmailVerified && p.Email != "",
		Groups: groups, GroupsTruncated: p.GroupsTruncated || trunc,
		SID: p.SID, Issuer: p.Iss, IssuedAt: time.Unix(*p.Iat, 0), Expiry: exp,
		Act: p.Act.Sub, CnfJKT: p.Cnf.JKT, Scope: p.Scope, KID: hdr.Kid, TokenType: TokenWarden,
	}
	v.cache.put(ck, c, exp.Add(skew))
	return c, StatusValid, ""
}

// debug logs a refusal with the kid and an 8-hex fingerprint of the token,
// never the token or a claim value.
func (v *WardenVerifier) debug(msg string, r Reason, kid string, sum [32]byte) {
	if v.log == nil || !v.log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	if len(kid) > maxLoggedKID {
		kid = kid[:maxLoggedKID]
	}
	v.log.Debug(msg, "reason", string(r), "kid", kid, "fp", hex.EncodeToString(sum[:4]))
}

// audContains reports whether the aud claim (a string or a list of strings)
// holds want.
func audContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, a := range many {
		if a == want {
			return true
		}
	}
	return false
}

// wardenKey is the result cache key: the snapshot generation and the SHA-256
// of the token, so a swap makes every earlier entry unreachable.
type wardenKey struct {
	gen   int64
	epoch uint64
	sum   [32]byte
}

// wardenCache is a bounded LRU of valid results.
type wardenCache struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[wardenKey]*list.Element
}

type wardenEntry struct {
	key    wardenKey
	claims Claims
	until  time.Time
}

func newWardenCache(max int) *wardenCache {
	return &wardenCache{max: max, ll: list.New(), m: make(map[wardenKey]*list.Element)}
}

func (c *wardenCache) get(k wardenKey, now time.Time) (Claims, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[k]
	if !ok {
		return Claims{}, false
	}
	e := el.Value.(*wardenEntry)
	if !now.Before(e.until) {
		c.ll.Remove(el)
		delete(c.m, k)
		return Claims{}, false
	}
	c.ll.MoveToFront(el)
	return e.claims, true
}

func (c *wardenCache) put(k wardenKey, cl Claims, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		e := el.Value.(*wardenEntry)
		e.claims, e.until = cl, until
		c.ll.MoveToFront(el)
		return
	}
	c.m[k] = c.ll.PushFront(&wardenEntry{key: k, claims: cl, until: until})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*wardenEntry).key)
	}
}

func (c *wardenCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.m = make(map[wardenKey]*list.Element)
}
