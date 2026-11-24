package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/tokensvc"
)

// The RFC 8693 token endpoint (W-P2-TOKX-03). POST /oauth2/token and the RFC
// 8414 discovery document are mounted on the control plane's mux directly,
// only when the token service was built (tokenService.enabled): outside
// withSession, CSRF, the authz table's role check, the admin audit middleware
// and worker auth, because the caller authenticates with a private_key_jwt
// client assertion and nothing else. A session cookie, a wwt_ worker token or a
// wak_ API key is never client authentication here: any Authorization header
// is refused, and cookies are never read.
//
// The handler only parses and maps. Every decision, and every error code and
// reason, comes from tokensvc.Service.Exchange.

// tokenReadTimeout bounds reading the request body. A variable so a test can
// shorten it.
var tokenReadTimeout = 10 * time.Second

const (
	// tokenPath is the token endpoint; tokensvc.TokenPath is the same path
	// appended to the issuer for the assertion audience.
	tokenPath = "/oauth2/token"
	// asMetadataPath is the RFC 8414 authorization server metadata location.
	asMetadataPath = "/.well-known/oauth-authorization-server"

	// maxTokenFormBytes caps the request body. A P1 subject token can be 16
	// KiB and the assertion 8 KiB, so 32 KiB leaves room for the rest.
	maxTokenFormBytes = 32 << 10
	// tokenRetryAfterSeconds is the Retry-After of a 503: long enough for a
	// failing store or IdP to recover, short enough that a harness retries.
	tokenRetryAfterSeconds = 5

	// asMetadataMaxAge is how long a client may cache the discovery document.
	asMetadataMaxAge = 5 * 60

	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	clientAssertionJWT     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// Request-shape reasons of the handler itself. Like the tokensvc reasons they
// are fixed words: nothing the caller sent is ever echoed.
const (
	reqMethodNotAllowed = "method_not_allowed"
	reqContentType      = "unsupported_content_type"
	reqQueryParameters  = "query_parameters_not_allowed"
	reqAuthorization    = "authorization_header_not_allowed"
	reqBodyTooLarge     = "body_too_large"
	reqMalformedBody    = "malformed_body"
	reqDuplicateParam   = "duplicate_parameter"
	reqUnsupportedParam = "unsupported_parameter"
	reqMissingParameter = "missing_parameter"
	reqUnsupportedGrant = "unsupported_grant_type"
	reqClientAuthFailed = "client_authentication_failed"
	reqServiceUnavail   = "service_unavailable"
	reqRateLimited      = "rate_limited"
)

// tokenWarnMaxKeys bounds the unauthenticated-failure log limiter.
const tokenWarnMaxKeys = 4096

// TokenExchanger is what the endpoint needs from the token service;
// *tokensvc.Service is the implementation and tests pass a fake.
type TokenExchanger interface {
	Exchange(ctx context.Context, req tokensvc.ExchangeRequest) (*tokensvc.Issued, error)
}

// tokenFormParams is the set of parameters the endpoint reads. Every other
// parameter is ignored (RFC 6749 section 3.2), except actor_token and
// resource, which the endpoint refuses.
var tokenFormParams = map[string]bool{
	"grant_type": true, "subject_token": true, "subject_token_type": true,
	"client_assertion_type": true, "client_assertion": true, "client_id": true,
	"audience": true, "requested_token_type": true, "scope": true,
	"actor_token": true, "actor_token_type": true, "resource": true,
}

// handleToken serves POST /oauth2/token.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	setTokenHeaders(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOAuthError(w, http.StatusMethodNotAllowed, tokensvc.CodeInvalidRequest, reqMethodNotAllowed)
		return
	}
	// The server has only a header timeout, so bound the body read here: a
	// trickled body must not hold a goroutine. Unsupported writers (a test
	// recorder) just skip it. This comes before the in-flight slot is taken, so
	// a slot is never held longer than the deadline by a stalled body.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(tokenReadTimeout))
	// The two limits that need nothing from the request but its peer address
	// run before anything is parsed: a flood spends no more than a map lookup.
	release, ok := s.admitToken(w, r)
	if !ok {
		return
	}
	defer release()
	form, status, code, reason := readTokenForm(w, r)
	if reason == "" {
		// The body is read: clear the deadline, or net/http's background read
		// times out later and cancels r.Context() in the middle of the
		// exchange (a slow IdP fetch), which would answer a misleading 503 and
		// could burn the assertion's jti. On a refusal it stays, so the server
		// does not wait on the rest of a stalled body.
		_ = rc.SetReadDeadline(time.Time{})
	}
	if reason != "" {
		s.tokenRefused(r, code, reason)
		writeOAuthError(w, status, code, reason)
		return
	}

	// Client authentication presence comes before the other parameters, so a
	// caller without an assertion (a browser with a session cookie, a worker
	// with a bearer) learns only that it is not authenticated.
	if form["client_assertion_type"] != clientAssertionJWT || form["client_assertion"] == "" {
		s.tokenRefused(r, tokensvc.CodeInvalidClient, reqClientAuthFailed)
		writeOAuthError(w, http.StatusUnauthorized, tokensvc.CodeInvalidClient, reqClientAuthFailed)
		return
	}
	if form["subject_token"] == "" || form["subject_token_type"] == "" {
		s.tokenRefused(r, tokensvc.CodeInvalidRequest, reqMissingParameter)
		writeOAuthError(w, http.StatusBadRequest, tokensvc.CodeInvalidRequest, reqMissingParameter)
		return
	}

	issued, err := s.cfg.Tokens.Exchange(r.Context(), tokensvc.ExchangeRequest{
		ClientAssertion:    form["client_assertion"],
		ClientID:           form["client_id"],
		SubjectToken:       form["subject_token"],
		SubjectTokenType:   form["subject_token_type"],
		Scope:              form["scope"],
		Audience:           form["audience"],
		RequestedTokenType: form["requested_token_type"],
	})
	if err != nil {
		var te *tokensvc.Error
		if !errors.As(err, &te) {
			// Not a tokensvc failure: an unexpected error is a refusal, never
			// a token, and its text stays in the log.
			s.cfg.Logger.Error("token_exchange_error", "error_type", errorKind(err))
			w.Header().Set("Retry-After", strconv.Itoa(tokenRetryAfterSeconds))
			writeOAuthError(w, http.StatusServiceUnavailable, tokensvc.CodeTemporarilyUnavailable, reqServiceUnavail)
			return
		}
		s.tokenDenied(r, te.Code, string(te.Reason), te.AgentID)
		if !te.Verified {
			// Counted by the service; no row, so a rate-limited log line is
			// the only trace of a caller that did not authenticate.
			s.warnUnauthenticated(r, string(te.Reason))
		}
		status, desc := tokenErrorResponse(te)
		switch status {
		case http.StatusServiceUnavailable:
			w.Header().Set("Retry-After", strconv.Itoa(tokenRetryAfterSeconds))
		case http.StatusTooManyRequests:
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(te.RetryAfter)))
		}
		writeOAuthError(w, status, te.Code, desc)
		return
	}
	resp := map[string]any{
		"access_token":      issued.AccessToken,
		"issued_token_type": issued.IssuedTokenType,
		"token_type":        issued.TokenType,
		"expires_in":        issued.ExpiresIn,
	}
	if issued.Scope != "" {
		resp["scope"] = issued.Scope
	}
	writeTokenJSON(w, http.StatusOK, resp)
}

// readTokenForm applies the request-shape rules and returns the parameters.
// On a refusal it returns the status, code and a fixed reason.
func readTokenForm(w http.ResponseWriter, r *http.Request) (form map[string]string, status int, code tokensvc.OAuthCode, reason string) {
	bad := func(reason string) (map[string]string, int, tokensvc.OAuthCode, string) {
		return nil, http.StatusBadRequest, tokensvc.CodeInvalidRequest, reason
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return bad(reqQueryParameters)
	}
	// Any Authorization header, whatever its scheme or value: the endpoint has
	// no bearer or basic client authentication.
	if len(r.Header.Values("Authorization")) > 0 {
		return bad(reqAuthorization)
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" {
		return bad(reqContentType)
	}
	if r.ContentLength > maxTokenFormBytes {
		return bad(reqBodyTooLarge)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTokenFormBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return bad(reqBodyTooLarge)
		}
		return bad(reqMalformedBody)
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return bad(reqMalformedBody)
	}
	form = make(map[string]string, len(values))
	for k, v := range values {
		if len(v) > 1 {
			return bad(reqDuplicateParam)
		}
		if tokenFormParams[k] {
			form[k] = v[0]
		}
	}
	// The grant type comes first: a caller on the wrong grant learns that
	// before anything else about the request.
	if form["grant_type"] != grantTypeTokenExchange {
		return nil, http.StatusBadRequest, tokensvc.CodeUnsupportedGrantType, reqUnsupportedGrant
	}
	if _, ok := form["actor_token"]; ok {
		return bad(reqUnsupportedParam)
	}
	if _, ok := form["actor_token_type"]; ok {
		return bad(reqUnsupportedParam)
	}
	if _, ok := form["resource"]; ok {
		return bad(reqUnsupportedParam)
	}
	return form, 0, "", ""
}

// tokenErrorResponse maps a tokensvc.Error to its HTTP status and the
// error_description. The description is the closed Reason, except for
// invalid_client: an unknown agent, an unknown kid, a bad signature and a
// disabled agent must be indistinguishable, so they all answer the same fixed
// word.
func tokenErrorResponse(te *tokensvc.Error) (int, string) {
	switch te.Code {
	case tokensvc.CodeInvalidClient:
		return http.StatusUnauthorized, reqClientAuthFailed
	case tokensvc.CodeInvalidRequest, tokensvc.CodeInvalidGrant, tokensvc.CodeUnauthorizedClient,
		tokensvc.CodeInvalidScope, tokensvc.CodeInvalidTarget, tokensvc.CodeUnsupportedGrantType:
		return http.StatusBadRequest, string(te.Reason)
	case tokensvc.CodeTemporarilyUnavailable:
		return http.StatusServiceUnavailable, string(te.Reason)
	case tokensvc.CodeRateLimited:
		return http.StatusTooManyRequests, string(te.Reason)
	default:
		// A code this table does not know is a refusal, never a success.
		return http.StatusServiceUnavailable, reqServiceUnavail
	}
}

// tokenDenied logs a refusal. It carries the code, the closed reason and the
// agent id when the assertion authenticated; never a token, assertion, subject
// or request value. Issuance records are written by the service (W-P2-TOKX-04).
func (s *Server) tokenDenied(r *http.Request, code tokensvc.OAuthCode, reason, agent string) {
	level := slog.LevelDebug
	if code == tokensvc.CodeTemporarilyUnavailable {
		level = slog.LevelWarn
	}
	// The id is the caller's claim until the assertion verified: an
	// invalid_client, or a failure of the stores the verification itself uses,
	// leaves it unproven, and a made-up id must not look like a real agent.
	key := "agent"
	switch {
	case code == tokensvc.CodeInvalidClient,
		reason == string(tokensvc.ReasonAgentStoreUnavailable),
		reason == string(tokensvc.ReasonReplayStoreUnavailable),
		reason == string(tokensvc.ReasonVerifierMisconfigured):
		key = "claimed_agent"
	}
	s.cfg.Logger.Log(r.Context(), level, "token_exchange_denied", "code", string(code), "reason", reason, key, agent)
}

// errorKind names an error's dynamic type without its text, which may carry
// store or driver detail.
func errorKind(err error) string { return fmt.Sprintf("%T", err) }

// setTokenHeaders marks every response of the endpoint uncacheable (RFC 6749
// section 5.1) and JSON.
func setTokenHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

// writeOAuthError writes an RFC 6749 section 5.2 error response.
func writeOAuthError(w http.ResponseWriter, status int, code tokensvc.OAuthCode, description string) {
	writeTokenJSON(w, status, map[string]string{"error": string(code), "error_description": description})
}

func writeTokenJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleASMetadata serves GET /.well-known/oauth-authorization-server (RFC
// 8414) so harnesses do not hard-code the token endpoint. Every URL derives
// from the configured issuer, never from the request's Host. The document is
// served at the bare well-known path only: RFC 8414 section 3 inserts the path
// of an issuer that has one after the well-known segment, which is not mounted,
// so tokenService.issuer must have no path component for discovery to work
// (token exchange itself is unaffected).
func (s *Server) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeAuthzJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	iss := s.cfg.TokenIssuer
	doc := map[string]any{
		"issuer":                                iss,
		"token_endpoint":                        iss + tokensvc.TokenPath,
		"jwks_uri":                              iss + jwksPath,
		"grant_types_supported":                 []string{grantTypeTokenExchange},
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"EdDSA", "ES256"},
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(asMetadataMaxAge))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(doc)
	}
}

// tokenEdgeState is the endpoint's runtime state, built once by Handler.
type tokenEdgeState struct {
	sem     chan struct{}
	trusted []netip.Prefix
	warn    *addrLimiter
}

func (s *Server) newTokenEdgeState() *tokenEdgeState {
	st := &tokenEdgeState{
		trusted: trustedPrefixes(s.cfg.Console.TrustedProxies),
		warn:    newAddrLimiter(s.cfg.Clock, time.Minute, tokenWarnMaxKeys),
	}
	if n := s.cfg.TokenEdge.MaxInFlight; n > 0 {
		st.sem = make(chan struct{}, n)
	}
	return st
}

// admitToken applies the per-client-IP limit and the in-flight cap. It
// returns false after writing the 429; otherwise release must be called when
// the request is done.
func (s *Server) admitToken(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	edge := s.tokenEdge
	if edge == nil {
		return func() {}, true
	}
	if lim := s.cfg.TokenEdge.IP; lim != nil {
		if allowed, wait := lim.Allow(tokenClientKey(r, edge.trusted), s.cfg.Clock.Now()); !allowed {
			s.tokenThrottled(w, r, wait)
			return nil, false
		}
	}
	if edge.sem == nil {
		return func() {}, true
	}
	select {
	case edge.sem <- struct{}{}:
		return func() { <-edge.sem }, true
	default:
		s.tokenThrottled(w, r, time.Second)
		return nil, false
	}
}

// tokenThrottled answers 429 rate_limited with a whole-second Retry-After
// (RFC 6585 section 4). The request body is not read.
func (s *Server) tokenThrottled(w http.ResponseWriter, r *http.Request, wait time.Duration) {
	s.cfg.TokenEdge.Metrics.Denied(tokensvc.ReasonRateLimited)
	s.warnUnauthenticated(r, reqRateLimited)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
	writeOAuthError(w, http.StatusTooManyRequests, tokensvc.CodeRateLimited, reqRateLimited)
}

// retryAfterSeconds rounds a wait up to whole seconds, at least one.
func retryAfterSeconds(d time.Duration) int {
	secs := int((d + time.Second - 1) / time.Second)
	if secs < 1 {
		return 1
	}
	return secs
}

// tokenRefused handles a refusal the handler itself makes (request shape,
// missing client authentication): the debug line, the counter under the closed
// reason enum, and the rate-limited warning. The caller is unauthenticated, so
// there is no row and no agent id.
func (s *Server) tokenRefused(r *http.Request, code tokensvc.OAuthCode, reason string) {
	s.tokenDenied(r, code, reason, "")
	s.cfg.TokenEdge.Metrics.Denied(handlerReason(reason))
	s.warnUnauthenticated(r, reason)
}

// handlerReason maps the handler's request-shape words onto the closed
// tokensvc.Reason enum, which is the only label set of the denied counter.
func handlerReason(reason string) tokensvc.Reason {
	if reason == reqBodyTooLarge {
		return tokensvc.ReasonTooLarge
	}
	return tokensvc.ReasonMalformed
}

// warnUnauthenticated logs a refusal of a caller that did not authenticate, at
// most once per reason and client IP per minute. It carries the closed reason
// and the client IP, nothing the caller sent.
func (s *Server) warnUnauthenticated(r *http.Request, reason string) {
	edge := s.tokenEdge
	if edge == nil {
		return
	}
	ip := tokenClientKey(r, edge.trusted)
	if !edge.warn.allow(reason + "|" + ip) {
		return
	}
	s.cfg.Logger.Warn("token_exchange_unauthenticated", "reason", reason, "client_ip", ip)
}

// tokenClientKey is the rate-limit key of the request's client: the peer
// address, unless the peer is a trusted proxy, in which case the nearest
// X-Forwarded-For hop that is not itself a trusted proxy (walking from the
// right, where the trusted proxies append). X-Forwarded-For from any other
// peer is ignored, and so is everything left of the first untrusted hop,
// which the client controls. An IPv6 address is keyed by its /64, so a client
// cannot mint keys by rotating the host part. An unparsable peer shares one
// key.
func tokenClientKey(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return "-"
	}
	peer = peer.Unmap()
	if !inPrefixes(trusted, peer) {
		return addrKey(peer)
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !inPrefixes(trusted, a) {
			return addrKey(a)
		}
	}
	return addrKey(peer)
}

// addrKey is the textual key of an address: IPv4 as is, IPv6 as its /64.
func addrKey(a netip.Addr) string {
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}
