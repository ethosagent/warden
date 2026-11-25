package tokensvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
)

// Limits and defaults of the exchange.
const (
	// DefaultTTL is the default lifetime of an issued token; MinTTL and
	// MaxTTL bound the configured value.
	DefaultTTL = 15 * time.Minute
	MinTTL     = time.Minute
	MaxTTL     = 15 * time.Minute
	// DefaultSessionIdle and DefaultSessionAbsolute bound a token session.
	DefaultSessionIdle     = 12 * time.Hour
	DefaultSessionAbsolute = 7 * 24 * time.Hour
	// MaxTokenSize caps the encoded issued token, which keeps it under the
	// worker's 16 KiB cap.
	MaxTokenSize = 12 << 10

	maxScopes     = 16
	randomIDBytes = 16 // 128 bits
	// BearerTokenType is the token_type of the response.
	BearerTokenType = "Bearer"
)

var scopeRE = regexp.MustCompile(`^[a-z0-9:._-]{1,64}$`)

// BlockChecker reports whether a user is on the block list. The control plane
// implements it over its block store (internal/controlplane); tokensvc never
// imports the control plane. An error means the answer is unknown and the
// exchange is refused: a failed read never allows.
type BlockChecker interface {
	// IsBlocked reports whether sub (exact) or email (matched lowercase;
	// the caller passes "" unless the IdP verified it) is blocked.
	IsBlocked(ctx context.Context, sub, email string) (bool, error)
}

// ClientAuthenticator authenticates the agent. *AssertionVerifier is the
// implementation.
type ClientAuthenticator interface {
	VerifyClientAssertionFor(ctx context.Context, raw, formClientID string) (Client, error)
}

// Signers hands out the active signing key of a purpose. *keys.KeySet is the
// implementation. The service asks only for keys.PurposeToken.
type Signers interface {
	Active(purpose string) (keys.Signer, error)
}

// Config configures a Service. Issuer, Clients, Agents, Blocks, Signers,
// Sessions, Resolvers, Now and Rand are required; New refuses anything less.
type Config struct {
	// Issuer is the iss of every issued token, from operator configuration
	// and never from a request. See ValidateIssuer.
	Issuer string
	// TTL is the longest lifetime of an issued token (default DefaultTTL,
	// MinTTL..MaxTTL).
	TTL time.Duration
	// SessionIdle and SessionAbsolute default to DefaultSessionIdle and
	// DefaultSessionAbsolute.
	SessionIdle, SessionAbsolute time.Duration

	Clients   ClientAuthenticator
	Agents    agentreg.Store
	Blocks    BlockChecker
	Signers   Signers
	Sessions  SessionStore
	Resolvers map[string]SubjectResolver
	// Now is the clock. Rand is the randomness source for jti and sid ids;
	// production passes crypto/rand.Reader.
	Now  func() time.Time
	Rand io.Reader
}

// Service exchanges a subject token and an agent assertion for a Warden token.
// It is safe for concurrent use.
type Service struct {
	cfg Config
}

// New validates cfg and returns the service.
func New(cfg Config) (*Service, error) {
	if err := ValidateIssuer(cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.TTL < MinTTL || cfg.TTL > MaxTTL {
		return nil, fmt.Errorf("tokensvc: ttl %s outside %s..%s", cfg.TTL, MinTTL, MaxTTL)
	}
	if cfg.SessionIdle == 0 {
		cfg.SessionIdle = DefaultSessionIdle
	}
	if cfg.SessionAbsolute == 0 {
		cfg.SessionAbsolute = DefaultSessionAbsolute
	}
	if cfg.SessionIdle < 0 || cfg.SessionAbsolute < 0 {
		return nil, errors.New("tokensvc: negative session lifetime")
	}
	switch {
	case cfg.Clients == nil, cfg.Agents == nil, cfg.Blocks == nil, cfg.Signers == nil,
		cfg.Sessions == nil, cfg.Now == nil, cfg.Rand == nil:
		return nil, errors.New("tokensvc: Clients, Agents, Blocks, Signers, Sessions, Now and Rand are required")
	case len(cfg.Resolvers) == 0:
		return nil, errors.New("tokensvc: at least one subject resolver is required")
	}
	for typ, r := range cfg.Resolvers {
		if typ == "" || r == nil {
			return nil, errors.New("tokensvc: invalid subject resolver entry")
		}
	}
	rs := make(map[string]SubjectResolver, len(cfg.Resolvers))
	for k, v := range cfg.Resolvers {
		rs[k] = v
	}
	cfg.Resolvers = rs
	return &Service{cfg: cfg}, nil
}

// ValidateIssuer checks the token service's own issuer URL: absolute https
// with a host, no userinfo, query, fragment or trailing slash. http is
// accepted only for a loopback host (local development).
func ValidateIssuer(s string) error {
	bad := func(why string) error {
		return fmt.Errorf("tokensvc: issuer must be an absolute https URL without query, fragment or trailing slash: %s", why)
	}
	if s == "" {
		return bad("empty")
	}
	if strings.ContainsAny(s, "?#") || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return bad("query, fragment or stray characters")
	}
	if strings.HasSuffix(s, "/") {
		return bad("trailing slash")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Hostname() == "" {
		return bad("not an absolute URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(u.Hostname()) {
			return bad("http is allowed only for a loopback host")
		}
	default:
		return bad("scheme")
	}
	return nil
}

func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}

// ExchangeRequest is one token exchange request, already parsed from the form.
type ExchangeRequest struct {
	ClientAssertion string
	// ClientID is the optional form client_id; when set it must equal the
	// assertion's iss.
	ClientID           string
	SubjectToken       string
	SubjectTokenType   string
	Scope              string
	Audience           string
	RequestedTokenType string
}

// Issued is a successful exchange. AccessToken is a bearer credential: Issued
// formats without it, so logging an Issued never leaks it.
type Issued struct {
	AccessToken     string
	IssuedTokenType string
	TokenType       string
	// ExpiresIn is exp - iat in seconds.
	ExpiresIn int64
	// Scope is the issued scope, space-delimited; empty when none.
	Scope string

	// The fields below are for recording; none is a credential.
	Sub   string
	Agent string
	SID   string
	JTI   string
	KID   string
	Exp   time.Time
}

// String implements fmt.Stringer without the token.
func (i Issued) String() string {
	return fmt.Sprintf("tokensvc.Issued{agent=%s sid=%s kid=%s exp=%s}", i.Agent, i.SID, i.KID, i.Exp.UTC().Format(time.RFC3339))
}

// GoString implements fmt.GoStringer without the token.
func (i Issued) GoString() string { return i.String() }

// LogValue implements slog.LogValuer without the token or the subject.
func (i Issued) LogValue() slog.Value {
	return slog.GroupValue(slog.String("agent", i.Agent), slog.String("sid", i.SID),
		slog.String("jti", i.JTI), slog.String("kid", i.KID), slog.Time("exp", i.Exp))
}

// Exchange runs one token exchange. Every failure is a *Error with a closed
// Code and Reason; once the agent has authenticated, the Error carries its id.
//
// The order is: request shape, agent assertion, subject token, agent re-read,
// block list, groups, scope, session, mint. Any store or key failure fails
// closed; no token is produced on an error.
func (s *Service) Exchange(ctx context.Context, req ExchangeRequest) (*Issued, error) {
	if req.Audience != "" && req.Audience != identity.WardenAudience {
		return nil, &Error{Code: CodeInvalidTarget, Reason: ReasonInvalidTarget}
	}
	switch req.RequestedTokenType {
	case "", TokenTypeJWT, TokenTypeAccessToken:
	default:
		return nil, &Error{Code: CodeInvalidRequest, Reason: ReasonUnsupportedTokenType}
	}
	resolver, ok := s.cfg.Resolvers[req.SubjectTokenType]
	if !ok {
		return nil, &Error{Code: CodeInvalidRequest, Reason: ReasonUnsupportedTokenType}
	}

	client, err := s.cfg.Clients.VerifyClientAssertionFor(ctx, req.ClientAssertion, req.ClientID)
	if err != nil {
		return nil, err
	}
	deny := func(code OAuthCode, r Reason) (*Issued, error) {
		return nil, &Error{Code: code, Reason: r, AgentID: client.AgentID}
	}

	subj, err := resolver.Resolve(ctx, req.SubjectToken)
	if err != nil {
		var te *Error
		if errors.As(err, &te) {
			return nil, &Error{Code: te.Code, Reason: te.Reason, AgentID: client.AgentID}
		}
		return deny(CodeTemporarilyUnavailable, ReasonVerifierMisconfigured)
	}
	if subj.Subject == nil {
		return deny(CodeInvalidGrant, ReasonSubjectInvalid)
	}
	user := subj.Subject

	// The agent may have been disabled or re-keyed while the IdP answered.
	agent, err := s.cfg.Agents.Get(ctx, client.AgentID)
	switch {
	case errors.Is(err, agentreg.ErrNotFound):
		return deny(CodeInvalidClient, ReasonAgentUnknown)
	case err != nil:
		return deny(CodeTemporarilyUnavailable, ReasonAgentStoreUnavailable)
	case agent.Status != agentreg.StatusActive:
		return deny(CodeInvalidClient, ReasonAgentDisabled)
	case !hasKey(agent, client.JKT):
		return deny(CodeInvalidClient, ReasonUnknownKID)
	}

	blockEmail := ""
	if user.EmailVerified {
		blockEmail = user.Email
	}
	blocked, err := s.cfg.Blocks.IsBlocked(ctx, user.Sub, blockEmail)
	if err != nil {
		return deny(CodeTemporarilyUnavailable, ReasonBlockStoreUnavailable)
	}
	if blocked {
		return deny(CodeInvalidGrant, ReasonUserBlocked)
	}

	if identity.CompilePrincipals(agent.AllowedGroups, nil).Match(user) != identity.Member {
		return deny(CodeUnauthorizedClient, ReasonGroupNotAllowed)
	}

	scope, ok := issuedScope(req.Scope, agent.AllowedScopes)
	if !ok {
		return deny(CodeInvalidScope, ReasonScopeNotAllowed)
	}

	now := s.cfg.Now()
	iat := now.Truncate(time.Second)
	exp := iat.Add(s.cfg.TTL)
	if subjExp := subj.Expiry.Truncate(time.Second); subjExp.Before(exp) {
		exp = subjExp
	}
	if !exp.After(iat) {
		return deny(CodeInvalidGrant, ReasonSubjectExpired)
	}

	signer, err := s.cfg.Signers.Active(keys.PurposeToken)
	if err != nil {
		return deny(CodeTemporarilyUnavailable, ReasonSignerUnavailable)
	}

	newSID, err := s.randomID(SessionPrefix)
	if err != nil {
		return deny(CodeTemporarilyUnavailable, ReasonSignerUnavailable)
	}
	jti, err := s.randomID("")
	if err != nil {
		return deny(CodeTemporarilyUnavailable, ReasonSignerUnavailable)
	}
	claims := identity.WardenClaims{
		Ver: identity.WardenTokenVer, Iss: s.cfg.Issuer, Aud: identity.WardenAudience,
		Sub: user.Sub, IdPIss: subj.IdPIss,
		Groups: user.Groups, GroupsTruncated: user.GroupsTruncated,
		Act: identity.WardenActor{Sub: client.AgentID},
		SID: newSID, IdPSID: subj.IdPSID, JTI: jti,
		Iat: iat.Unix(), Nbf: iat.Unix(), Exp: exp.Unix(),
		Scope: scope,
		Cnf:   identity.WardenConfirmation{JKT: client.JKT},
	}
	if user.EmailVerified && user.Email != "" {
		claims.Email, claims.EmailVerified = user.Email, true
	}
	header := keys.Header{Alg: signer.Alg(), Kid: signer.KID(), Typ: identity.WardenTokenTyp}
	// Refuse an oversized token before the session is created or extended.
	// The estimate uses the fresh sid, which has the same length as any sid
	// this service issues; the exact size is checked again after signing.
	if estimateSize(header, claims) > MaxTokenSize {
		return deny(CodeInvalidRequest, ReasonTokenTooLarge)
	}

	sid, err := s.cfg.Sessions.Touch(ctx,
		SessionKey{IdPIss: subj.IdPIss, Sub: user.Sub, AgentID: client.AgentID},
		subj.IssuedAt, now, SessionPolicy{Idle: s.cfg.SessionIdle, Absolute: s.cfg.SessionAbsolute}, newSID)
	switch {
	case errors.Is(err, ErrSessionRevoked):
		return deny(CodeInvalidGrant, ReasonSessionRevoked)
	case err != nil:
		return deny(CodeTemporarilyUnavailable, ReasonSessionStoreUnavailable)
	}
	claims.SID = sid
	token, err := keys.SignCompact(ctx, signer, header, claims)
	if err != nil {
		return deny(CodeTemporarilyUnavailable, ReasonSignerUnavailable)
	}
	if len(token) > MaxTokenSize {
		return deny(CodeInvalidRequest, ReasonTokenTooLarge)
	}
	return &Issued{
		AccessToken: token, IssuedTokenType: TokenTypeJWT, TokenType: BearerTokenType,
		ExpiresIn: exp.Unix() - iat.Unix(), Scope: scope,
		Sub: user.Sub, Agent: client.AgentID, SID: sid, JTI: jti, KID: signer.KID(), Exp: exp,
	}, nil
}

// estimateSize returns the length of the compact JWS SignCompact would make
// for header and claims, assuming a 64-byte signature (EdDSA and ES256).
func estimateSize(h keys.Header, c identity.WardenClaims) int {
	hb, err1 := json.Marshal(h)
	cb, err2 := json.Marshal(c)
	if err1 != nil || err2 != nil {
		return MaxTokenSize + 1
	}
	enc := base64.RawURLEncoding
	return enc.EncodedLen(len(hb)) + 1 + enc.EncodedLen(len(cb)) + 1 + enc.EncodedLen(64)
}

// hasKey reports whether the agent still has a key with thumbprint jkt.
func hasKey(a agentreg.Agent, jkt string) bool {
	for _, k := range a.Keys {
		if k.JKT == jkt {
			return true
		}
	}
	return false
}

// issuedScope returns the scope to issue: the requested scope when every
// token matches the grammar and is allowed, all of allowed when nothing was
// requested. The result is sorted and de-duplicated.
func issuedScope(requested string, allowed []string) (string, bool) {
	if requested == "" {
		out := append([]string(nil), allowed...)
		sort.Strings(out)
		return strings.Join(dedup(out), " "), true
	}
	toks := strings.Split(requested, " ")
	if len(toks) > maxScopes {
		return "", false
	}
	permitted := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		permitted[a] = struct{}{}
	}
	for _, t := range toks {
		if !scopeRE.MatchString(t) {
			return "", false
		}
		if _, ok := permitted[t]; !ok {
			return "", false
		}
	}
	sort.Strings(toks)
	return strings.Join(dedup(toks), " "), true
}

// dedup removes adjacent duplicates from a sorted list.
func dedup(in []string) []string {
	out := in[:0:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// randomID returns prefix plus 128 random bits, base64url without padding.
func (s *Service) randomID(prefix string) (string, error) {
	var b [randomIDBytes]byte
	if _, err := io.ReadFull(s.cfg.Rand, b[:]); err != nil {
		return "", fmt.Errorf("tokensvc: random: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}
