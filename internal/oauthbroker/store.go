package oauthbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
)

// Errors every GrantStore returns, matched with errors.Is.
var (
	// ErrNotFound: no row with that id, state hash or (userKey, provider). A
	// consumed or expired attempt is also not found.
	ErrNotFound = errors.New("oauthbroker: not found")
	// ErrNotPending: CompletePending on a pending that is no longer open
	// (already granted, denied or expired, including expired but not yet swept).
	ErrNotPending = errors.New("oauthbroker: pending authorization is not open")
	// ErrTooMany: a per-user or global limit (Limits: by default
	// MaxOpenPendingsPerUser, MaxOpenAttemptsPerUser, MaxLiveAttempts) would be
	// exceeded.
	ErrTooMany = errors.New("oauthbroker: too many open authorizations")
	// ErrGrantState: ActivateGrant on a grant id that is not connecting, or
	// that a later BeginGrant or a RevokeGrant replaced.
	ErrGrantState = errors.New("oauthbroker: grant is not in the state this change needs")
	// ErrExists: CreateAttempt with a state hash that is already stored.
	ErrExists = errors.New("oauthbroker: already exists")
	// ErrInvalid wraps every input validation failure.
	ErrInvalid = errors.New("oauthbroker: invalid input")
)

// Limits and lifetimes the stores enforce.
const (
	// MaxOpenPendingsPerUser caps open (pending and unexpired) pending
	// authorizations per user_key.
	MaxOpenPendingsPerUser = 20
	// MaxOpenAttemptsPerUser caps unexpired connect attempts per user_key.
	MaxOpenAttemptsPerUser = 20
	// MaxLiveAttempts caps unexpired connect attempts across all users.
	MaxLiveAttempts = 10000
	// AttemptTTL is how long a browser attempt may take, from POST
	// /connect/start to the callback.
	AttemptTTL = 10 * time.Minute
	// ConnectingGrantTTL is how long a grant may stay connecting before Sweep
	// reports it to the reconciler (W-P3-BRKR-04).
	ConnectingGrantTTL = 10 * time.Minute
	// TerminalPendingRetention is how long a granted, denied or expired pending
	// is kept after completion before Sweep deletes it.
	TerminalPendingRetention = 7 * 24 * time.Hour
	// TouchInterval is the minimum gap between two last_used_at writes for one
	// (userKey, provider).
	TouchInterval = time.Minute
	// MaxStaleConnecting bounds the stale connecting grants one Sweep returns;
	// the rest come on the next pass.
	MaxStaleConnecting = 500
)

// Limits are the caps a store enforces. The zero value of a field means its
// default (the constants above); tests lower MaxLiveAttempts to exercise it
// without ten thousand rows.
type Limits struct {
	MaxOpenPendingsPerUser int
	MaxOpenAttemptsPerUser int
	MaxLiveAttempts        int
}

// WithDefaults returns l with every zero or negative field set to its default.
func (l Limits) WithDefaults() Limits {
	if l.MaxOpenPendingsPerUser <= 0 {
		l.MaxOpenPendingsPerUser = MaxOpenPendingsPerUser
	}
	if l.MaxOpenAttemptsPerUser <= 0 {
		l.MaxOpenAttemptsPerUser = MaxOpenAttemptsPerUser
	}
	if l.MaxLiveAttempts <= 0 {
		l.MaxLiveAttempts = MaxLiveAttempts
	}
	return l
}

// Field bounds CreatePending and CreateAttempt enforce. They keep one row
// small; real values are far shorter.
const (
	maxIDLen      = 512  // iss, sub, user_key, agent_id, provider, hashes
	maxScopes     = 64   // scopes per row
	maxScopeLen   = 256  // one scope string
	maxMessageLen = 1024 // the user-facing message
	maxRequestLen = 2048 // request_host, request_path, mcp_tool, request_method
	maxVerifier   = 128  // RFC 7636: a code_verifier is 43..128 characters
	minVerifier   = 43
)

// PendingStatus is where a pending authorization is in its life.
type PendingStatus string

// The pending statuses. Only StatusPending is open; the rest are terminal.
const (
	StatusPending PendingStatus = "pending"
	StatusGranted PendingStatus = "granted"
	StatusDenied  PendingStatus = "denied"
	StatusExpired PendingStatus = "expired"
)

// Terminal reports whether s is a final status.
func (s PendingStatus) Terminal() bool {
	return s == StatusGranted || s == StatusDenied || s == StatusExpired
}

// ReasonExpired is the reason Sweep records on a pending it expires.
const ReasonExpired = "expired"

// RequestInfo describes the agent request that led to a pending, when JIT
// (W-P3-JIT-01) created it. The portal landing page (W-P3-PORT-03) shows it.
// Every field is optional; Path never carries a query string.
type RequestInfo struct {
	Method  string
	Host    string
	Path    string
	MCPTool string
}

// Pending is one pending_authorizations row.
type Pending struct {
	// ID is 16 random bytes, base64url without padding; the store assigns it.
	ID string
	// Iss, Sub and UserKey identify the employee; UserKey is
	// secrets.UserKey(Iss, Sub).
	Iss     string
	Sub     string
	UserKey string
	// AgentID is the agent that needs the grant, or "" for a portal-started
	// pending.
	AgentID  string
	Provider string
	// Scopes is the canonical (sorted, de-duplicated) scope ceiling.
	Scopes  []string
	Message string
	Request RequestInfo
	Status  PendingStatus
	Reason  string
	// CreatedAt and ExpiresAt are set by the store; CompletedAt is zero while
	// the pending is open.
	CreatedAt   time.Time
	ExpiresAt   time.Time
	CompletedAt time.Time
}

// Attempt is one connect_attempts row: a single browser round trip to the
// provider. It is consumed once by ConsumeAttempt.
type Attempt struct {
	// StateHash is HashState(state), 64 lowercase hex characters. The OAuth
	// state itself is never stored.
	StateHash string
	// PendingID links the attempt to a pending, or "" for a portal connect.
	PendingID string
	Iss       string
	Sub       string
	UserKey   string
	Provider  string
	Scopes    []string
	// Verifier is the PKCE code_verifier. It never leaves the CP and is never
	// logged; String, GoString and LogValue omit it.
	Verifier string
	// BrowserHash is HashBrowserBinding(cookie value) of the
	// __Host-warden_connect cookie, 64 lowercase hex characters.
	BrowserHash string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// ShortHash returns at most the first 8 characters of a state hash, the most a
// log line may carry.
func ShortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// String prints the attempt without its verifier and with a shortened state
// hash.
func (a Attempt) String() string {
	return fmt.Sprintf("oauthbroker.Attempt{state:%s pending:%s provider:%s user_key:%s}",
		ShortHash(a.StateHash), a.PendingID, a.Provider, a.UserKey)
}

// GoString is String, so %#v cannot print the verifier either.
func (a Attempt) GoString() string { return a.String() }

// LogValue keeps the verifier and the full state hash out of slog output.
func (a Attempt) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("state", ShortHash(a.StateHash)),
		slog.String("pending_id", a.PendingID),
		slog.String("provider", a.Provider),
		slog.String("user_key", a.UserKey),
	)
}

// GrantState is where a grant is in its life.
type GrantState string

// The grant states. reconsent_required is set by the refresh engine
// (W-P3-PUS-03) when the provider rejects the refresh token.
const (
	GrantConnecting        GrantState = "connecting"
	GrantActive            GrantState = "active"
	GrantReconsentRequired GrantState = "reconsent_required"
	GrantRevoked           GrantState = "revoked"
)

// Account is the provider account a grant belongs to (W-P3-BRKR-08): the
// Google id_token sub or the GitHub user id, and the email or login shown in
// the portal. Both are optional.
type Account struct {
	ID    string
	Login string
}

// GrantRef names the grant BeginGrant creates or restarts.
type GrantRef struct {
	UserKey  string
	Iss      string
	Sub      string
	Provider string
}

// Grant is one oauth_grants row. There is one row per (UserKey, Provider).
type Grant struct {
	UserKey  string
	Iss      string
	Sub      string
	Provider string
	// GrantID is a fresh random id each BeginGrant; the TokenRecord in the
	// consent store carries the same id, so a stale writer can tell it lost.
	GrantID string
	// PrevGrantID is the active grant id that the current connecting attempt
	// replaced (a reconnect over a working grant), or "". ActivateGrant and
	// RevokeGrant clear it. The reconciler (W-P3-BRKR-04) uses it to restore
	// the earlier grant when a reconnect never completes.
	PrevGrantID string
	State       GrantState
	// Scopes is the canonical set the provider granted (set by ActivateGrant).
	Scopes  []string
	Account Account
	// GrantedAt is when the grant last became active (the row's creation time
	// until then). LastUsedAt and RevokedAt are zero when unset.
	GrantedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
	// LastRefreshAt and LastRefreshStatus record the last refresh attempt of
	// the grant's token (RefreshRecorder); zero/empty until one ran.
	LastRefreshAt     time.Time
	LastRefreshStatus string
}

// SweepResult is what one Sweep did.
type SweepResult struct {
	AttemptsDeleted int
	PendingsExpired int
	PendingsDeleted int
	// StaleConnecting lists grants that have been connecting for longer than
	// ConnectingGrantTTL (at most MaxStaleConnecting), for the reconciler.
	// Sweep does not change them.
	StaleConnecting []Grant
}

// GrantStore is the port over the broker's metadata. Implementations must pass
// oauthbrokertest.Run. Every method takes ctx; times come from the store's
// clock except Sweep's, which the caller passes.
type GrantStore interface {
	// CreatePending stores p as a new open pending that expires ttl from now.
	// The store assigns ID, Status, CreatedAt and ExpiresAt and canonicalizes
	// Scopes. ErrTooMany when the user already has MaxOpenPendingsPerUser open.
	CreatePending(ctx context.Context, p Pending, ttl time.Duration) (Pending, error)
	// GetPending returns the pending with that id. A pending whose expires_at
	// is not after now reads as StatusExpired even before a Sweep stores it.
	GetPending(ctx context.Context, id string) (Pending, error)
	// CompletePending moves an open pending to status (granted, denied or
	// expired) with reason, as a compare-and-set from pending: ErrNotPending
	// when it is already terminal or past expires_at, ErrNotFound when the id
	// is unknown. Subscribers are notified on success.
	CompletePending(ctx context.Context, id string, status PendingStatus, reason string) error
	// Subscribe returns a channel that receives the pending's final status and
	// is then closed, once CompletePending or Sweep ends it. A pending that is
	// already terminal (or unknown) gets an already-closed channel, holding the
	// status when there is one. cancel unregisters the waiter; it never closes
	// the channel. Notification is in memory, per process: a waiter must
	// re-read with GetPending after a wake and on its own timer.
	Subscribe(id string) (<-chan PendingStatus, func())

	// CreateAttempt stores a, which expires AttemptTTL from now. The store sets
	// CreatedAt and ExpiresAt and canonicalizes Scopes. ErrExists for a state
	// hash already stored; ErrTooMany past MaxOpenAttemptsPerUser or
	// MaxLiveAttempts.
	CreateAttempt(ctx context.Context, a Attempt) (Attempt, error)
	// ConsumeAttempt deletes and returns the attempt with that state hash in
	// one statement, so it succeeds once. ErrNotFound for an unknown,
	// consumed or expired attempt (an expired one is deleted too).
	ConsumeAttempt(ctx context.Context, stateHash string) (Attempt, error)

	// BeginGrant upserts the (UserKey, Provider) row as connecting with a new
	// GrantID, keeping its earlier scopes and account until ActivateGrant.
	// Over an active row it records the replaced id in PrevGrantID; over a
	// connecting row it keeps the PrevGrantID already recorded; over a
	// reconsent_required or revoked row PrevGrantID is "".
	BeginGrant(ctx context.Context, ref GrantRef) (Grant, error)
	// ActivateGrant sets the connecting grant with that id active with the
	// granted scopes and account. ErrGrantState when the row with that id is
	// not connecting; ErrNotFound when no row carries the id (never issued, or
	// replaced by a later BeginGrant).
	ActivateGrant(ctx context.Context, grantID string, scopes []string, account Account) (Grant, error)
	// MarkReconsentRequired moves the active (userKey, provider) grant to
	// reconsent_required, but only while the row still carries grantID, so a
	// refresh that overlaps a reconnect or a revoke changes nothing (the
	// W-P3-PUS-03 refresh engine calls it on invalid_grant). Calling it again
	// succeeds. ErrGrantState when the row moved on; ErrNotFound when there is
	// no row.
	MarkReconsentRequired(ctx context.Context, userKey, provider, grantID string) (Grant, error)
	// RevokeGrant marks the (userKey, provider) grant revoked and clears
	// PrevGrantID. With a non-empty grantID it is a compare-and-set: the row
	// must still carry that id (else ErrGrantState), so a reconciler working
	// from an old Sweep cannot revoke a newer grant after a reconnect; "" revokes
	// whatever grant the row holds (portal revoke, offboarding). It is
	// idempotent: revoking a revoked grant succeeds and keeps the first
	// RevokedAt. ErrNotFound when there is no row.
	RevokeGrant(ctx context.Context, userKey, provider, grantID string) (Grant, error)
	// RestoreGrant undoes a reconnect that never completed: when the
	// (userKey, provider) row is connecting with grant id connectingID and its
	// PrevGrantID is prevID, it becomes active again with grant id prevID and
	// the scopes and account the earlier activation set (CompareAndSet; the
	// W-P3-BRKR-04 reconciler calls it when the stored token still carries
	// prevID). ErrGrantState when the row is in another state or carries other
	// ids; ErrNotFound when there is no row.
	RestoreGrant(ctx context.Context, userKey, provider, connectingID, prevID string) (Grant, error)
	// GetGrant returns the (userKey, provider) grant in any state.
	GetGrant(ctx context.Context, userKey, provider string) (Grant, error)
	// ListGrants returns the user's grants ordered by provider; revoked ones
	// only with includeRevoked.
	ListGrants(ctx context.Context, userKey string, includeRevoked bool) ([]Grant, error)
	// TouchLastUsed records that an active grant was used at at. It writes at
	// most once per TouchInterval per (userKey, provider) and only moves
	// last_used_at forward; a call that does not write returns nil.
	TouchLastUsed(ctx context.Context, userKey, provider string, at time.Time) error

	// Sweep deletes expired attempts, marks open pendings past expires_at
	// expired (notifying their subscribers), deletes terminal pendings
	// completed more than TerminalPendingRetention before now, and returns the
	// grants connecting for longer than ConnectingGrantTTL.
	Sweep(ctx context.Context, now time.Time) (SweepResult, error)
}

// HashState returns the hex SHA-256 of an OAuth state value, the only form a
// store keeps (Attempt.StateHash).
func HashState(state string) string { return sha256Hex(state) }

// HashBrowserBinding returns the hex SHA-256 of the __Host-warden_connect
// cookie value (Attempt.BrowserHash).
func HashBrowserBinding(cookie string) string { return sha256Hex(cookie) }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// CanonicalScopes returns scopes sorted and de-duplicated, without empty
// strings. The result is never nil.
func CanonicalScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s != "" {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ValidatePending checks the caller-supplied fields of a CreatePending input.
func ValidatePending(p Pending, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("%w: pending ttl must be positive", ErrInvalid)
	}
	if err := required(map[string]string{"iss": p.Iss, "sub": p.Sub, "user_key": p.UserKey, "provider": p.Provider}); err != nil {
		return err
	}
	if err := bounded(maxIDLen, map[string]string{"iss": p.Iss, "sub": p.Sub, "user_key": p.UserKey, "provider": p.Provider, "agent_id": p.AgentID}); err != nil {
		return err
	}
	if err := bounded(maxMessageLen, map[string]string{"message": p.Message}); err != nil {
		return err
	}
	if err := bounded(maxRequestLen, map[string]string{
		"request_method": p.Request.Method, "request_host": p.Request.Host,
		"request_path": p.Request.Path, "mcp_tool": p.Request.MCPTool,
	}); err != nil {
		return err
	}
	if strings.Contains(p.Request.Path, "?") {
		return fmt.Errorf("%w: request_path must not carry a query string", ErrInvalid)
	}
	return validScopes(p.Scopes)
}

// ValidateAttempt checks the caller-supplied fields of a CreateAttempt input.
func ValidateAttempt(a Attempt) error {
	if err := required(map[string]string{"iss": a.Iss, "sub": a.Sub, "user_key": a.UserKey, "provider": a.Provider}); err != nil {
		return err
	}
	if err := bounded(maxIDLen, map[string]string{"iss": a.Iss, "sub": a.Sub, "user_key": a.UserKey, "provider": a.Provider, "pending_id": a.PendingID}); err != nil {
		return err
	}
	if !isHexHash(a.StateHash) {
		return fmt.Errorf("%w: state_hash must be 64 lowercase hex characters (HashState)", ErrInvalid)
	}
	if !isHexHash(a.BrowserHash) {
		return fmt.Errorf("%w: browser_hash must be 64 lowercase hex characters (HashBrowserBinding)", ErrInvalid)
	}
	if n := len(a.Verifier); n < minVerifier || n > maxVerifier {
		return fmt.Errorf("%w: verifier must be %d..%d characters", ErrInvalid, minVerifier, maxVerifier)
	}
	return validScopes(a.Scopes)
}

// ValidateGrantRef checks a BeginGrant input.
func ValidateGrantRef(r GrantRef) error {
	f := map[string]string{"iss": r.Iss, "sub": r.Sub, "user_key": r.UserKey, "provider": r.Provider}
	if err := required(f); err != nil {
		return err
	}
	return bounded(maxIDLen, f)
}

// ValidateAccount checks an ActivateGrant account and scopes.
func ValidateAccount(scopes []string, a Account) error {
	if err := bounded(maxIDLen, map[string]string{"provider_account_id": a.ID, "provider_account_login": a.Login}); err != nil {
		return err
	}
	return validScopes(scopes)
}

func required(fields map[string]string) error {
	for _, k := range sortedKeys(fields) {
		if fields[k] == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalid, k)
		}
	}
	return nil
}

func bounded(n int, fields map[string]string) error {
	for _, k := range sortedKeys(fields) {
		if len(fields[k]) > n {
			return fmt.Errorf("%w: %s is longer than %d bytes", ErrInvalid, k, n)
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func validScopes(scopes []string) error {
	if len(scopes) > maxScopes {
		return fmt.Errorf("%w: more than %d scopes", ErrInvalid, maxScopes)
	}
	for _, s := range scopes {
		if len(s) > maxScopeLen || strings.ContainsAny(s, " ,\t\r\n") {
			return fmt.Errorf("%w: scope %.32q is too long or holds a separator", ErrInvalid, s)
		}
	}
	return nil
}

func isHexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
