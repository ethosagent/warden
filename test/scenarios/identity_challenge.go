package scenarios

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The identity challenge scenarios (#558): a worker in challenge mode refuses a
// CONNECT with no valid identity with a 407 that carries a sign-in URL, before
// the block list, the policy and any dial. The in-process OIDC issuer fake
// answers the device authorization; nothing here polls it (the client's half is
// proven in internal/identityclient and the L2 stack).
//
// Neither a token, a device_code nor a user_code may appear in a log line, an
// event or a metric label: every scenario ends with that sweep.

const (
	signInStartedMetric = "warden.identity.signin.started.total"
	challengeTarget     = identityHost + ":443"
)

// challengeOpts boots challenge mode against the issuer fake, plus extra options.
func challengeOpts(extra ...harness.Option) []harness.Option {
	return append([]harness.Option{harness.WithIdentity(config.IdentityModeChallenge)}, extra...)
}

// challengeReply is one CONNECT answer, parsed.
type challengeReply struct {
	status int
	header http.Header
	raw    string
	body   struct {
		Error       string `json:"error"`
		Reason      string `json:"reason"`
		SignInError string `json:"sign_in_error"`
		SignIn      *struct {
			Issuer                  string `json:"issuer"`
			VerificationURI         string `json:"verification_uri"`
			VerificationURIComplete string `json:"verification_uri_complete"`
			UserCode                string `json:"user_code"`
			DeviceCode              string `json:"device_code"`
			TokenEndpoint           string `json:"token_endpoint"`
			ClientID                string `json:"client_id"`
			Interval                int    `json:"interval"`
			ExpiresIn               int    `json:"expires_in"`
		} `json:"sign_in"`
	}
}

// rawConnect sends one CONNECT to the worker with auth ("" = none) and reads
// the whole reply to EOF. It returns errors, so goroutines can use it.
func rawConnect(addr, hostPort, auth string) (challengeReply, error) {
	var r challengeReply
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return r, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostPort, hostPort)
	if auth != "" {
		req += "Proxy-Authorization: " + auth + "\r\n"
	}
	if _, err := fmt.Fprint(conn, req+"\r\n"); err != nil {
		return r, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return r, err
	}
	defer func() { _ = resp.Body.Close() }()
	r.status, r.header = resp.StatusCode, resp.Header
	if resp.StatusCode/100 == 2 {
		return r, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return r, err
	}
	r.raw = string(b)
	_ = json.Unmarshal(b, &r.body)
	return r, nil
}

func connectChallenge(t *testing.T, h *harness.H, auth string) challengeReply {
	t.Helper()
	r, err := rawConnect(h.ProxyAddr(), challengeTarget, auth)
	if err != nil {
		t.Fatalf("CONNECT %s: %v", challengeTarget, err)
	}
	return r
}

// assertChallenge checks the 407's shape: status, headers (no 401, no
// WWW-Authenticate), error and reason.
func assertChallenge(t *testing.T, what string, r challengeReply, reason string) {
	t.Helper()
	if r.status != http.StatusProxyAuthRequired {
		t.Fatalf("%s: status %d, want 407 (body %q)", what, r.status, r.raw)
	}
	for name, want := range map[string]string{
		"Proxy-Authenticate": `Basic realm="warden"`,
		"Content-Type":       "application/json",
		"Cache-Control":      "no-store",
	} {
		if got := r.header.Get(name); got != want {
			t.Errorf("%s: %s = %q, want %q", what, name, got, want)
		}
	}
	if v := r.header.Get("WWW-Authenticate"); v != "" {
		t.Errorf("%s: WWW-Authenticate %q must never be written", what, v)
	}
	if r.body.Error != "identity_required" || r.body.Reason != reason {
		t.Errorf("%s: error %q reason %q, want identity_required / %s", what, r.body.Error, r.body.Reason, reason)
	}
}

// assertOffer checks the sign_in object against the issuer fake: every URL on
// its origin, the client and the endpoint named, codes present.
func assertOffer(t *testing.T, h *harness.H, what string, r challengeReply) {
	t.Helper()
	si := r.body.SignIn
	if si == nil {
		t.Fatalf("%s: no sign_in in %q", what, r.raw)
	}
	iss := h.Issuer().Issuer()
	if si.Issuer != iss || si.TokenEndpoint != iss+"/token" || si.ClientID != "warden-cli" {
		t.Errorf("%s: sign_in issuer/token_endpoint/client_id = %q / %q / %q", what, si.Issuer, si.TokenEndpoint, si.ClientID)
	}
	if !strings.HasPrefix(si.VerificationURI, iss+"/") || !strings.HasPrefix(si.VerificationURIComplete, iss+"/") ||
		!strings.Contains(si.VerificationURIComplete, "user_code=") {
		t.Errorf("%s: verification URIs %q / %q are not on the issuer origin", what, si.VerificationURI, si.VerificationURIComplete)
	}
	if si.UserCode == "" || si.DeviceCode == "" || si.Interval <= 0 || si.ExpiresIn <= 0 {
		t.Errorf("%s: sign_in is missing a code, interval or expires_in", what)
	}
}

// identityRequiredEvents returns the deny events with reason identity_required.
func identityRequiredEvents(h *harness.H) []analytics.Event {
	var out []analytics.Event
	for _, e := range h.Events() {
		if e.Decision == "deny" && e.Reason == "identity_required" {
			out = append(out, e)
		}
	}
	return out
}

// signInCounts reads warden.identity.signin.started.total by outcome. It is nil
// on a target with no metrics.
func signInCounts(h *harness.H) map[string]float64 {
	if !h.MetricsAvailable() {
		return nil
	}
	out := map[string]float64{}
	for k, v := range h.Metrics() {
		if !strings.HasPrefix(k, signInStartedMetric+"{") {
			continue
		}
		rest := strings.TrimSuffix(strings.TrimPrefix(k, signInStartedMetric+"{"), "}")
		_, outcome, _ := strings.Cut(rest, "outcome=")
		out[outcome] = v
	}
	return out
}

func assertSignInCounts(t *testing.T, h *harness.H, want map[string]float64) {
	t.Helper()
	got := signInCounts(h)
	if got == nil {
		t.Log("this target exports no metrics; skipping the warden.identity.signin.started.total assertion")
		return
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s{outcome=%s} = %v, want %v", signInStartedMetric, k, got[k], w)
		}
	}
	for k, g := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected %s{outcome=%s} = %v", signInStartedMetric, k, g)
		}
	}
}

// assertNoSignInSecrets fails when a token, a device_code or a user_code appears
// in the logs, the events, the receipts or a metric label. The failure names the
// surface, never the value.
func assertNoSignInSecrets(t *testing.T, h *harness.H, secrets ...string) {
	t.Helper()
	var needles []string
	for _, s := range secrets {
		if s != "" {
			needles = append(needles, s)
		}
	}
	needles = append(needles, leakNeedles(secrets)...)
	surfaces := map[string]string{"logs": h.Logs()}
	evJSON, _ := json.Marshal(h.Events())
	surfaces["events"] = string(evJSON)
	rcJSON, _ := json.Marshal(h.Receipts())
	surfaces["receipts"] = string(rcJSON)
	if h.MetricsAvailable() {
		var keys []string
		for k := range h.Metrics() {
			keys = append(keys, k)
		}
		surfaces["metrics"] = strings.Join(keys, "\n")
	}
	for name, body := range surfaces {
		for _, n := range needles {
			if strings.Contains(body, n) {
				t.Errorf("a token, device_code or user_code appears in the %s", name)
				break
			}
		}
	}
}

// offerSecrets are the credentials of one offer, for the leak sweep.
func offerSecrets(rs ...challengeReply) []string {
	var out []string
	for _, r := range rs {
		if r.body.SignIn != nil {
			out = append(out, r.body.SignIn.DeviceCode, r.body.SignIn.UserCode)
		}
	}
	return out
}

// challengeNoToken: a CONNECT with no token gets the 407 and a sign-in URL on
// the issuer's origin; no dial happens and one deny event says identity_required.
func challengeNoToken(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	r := connectChallenge(t, h, "")
	assertChallenge(t, "no token", r, "none")
	assertOffer(t, h, "no token", r)

	reqs := h.Issuer().DeviceRequests()
	if len(reqs) != 1 || reqs[0].ClientID != "warden-cli" || !strings.Contains(reqs[0].Scope, "audience:server:client_id:warden") ||
		!strings.Contains(reqs[0].Scope, "offline_access") {
		t.Errorf("device authorizations = %+v, want one for warden-cli with the default scopes", reqs)
	}
	h.Eventually("the 407 to be recorded as one deny event", func() bool { return len(identityRequiredEvents(h)) == 1 })
	evs := identityRequiredEvents(h)
	if len(evs) != 1 || evs[0].Domain != identityHost || evs[0].IdentityStatus != "none" || evs[0].UserSub != "" {
		t.Errorf("deny events = %+v, want one identity_required for %s with status none", evs, identityHost)
	}
	if n := len(up.Requests()); n != 0 {
		t.Errorf("the upstream saw %d requests; the 407 must come before any dial", n)
	}
	for _, e := range h.Events() {
		if e.Decision == "allow" {
			t.Errorf("unexpected allow event %+v", e)
		}
	}
	assertSignInCounts(t, h, map[string]float64{"started": 1})
	assertNoSignInSecrets(t, h, offerSecrets(r)...)
}

// challengeValidToken: a valid token is allowed and attributed, and starts no
// sign-in.
func challengeValidToken(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	c := idToken{name: "valid", tok: h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng")),
		status: "valid", sub: "alice", email: "alice@example.com", groups: []string{"eng"}}
	if got := idTransports[0].get(t, h, c, "/valid"); got != http.StatusOK {
		t.Fatalf("valid token: status %d, want the upstream's 200", got)
	}
	assertIdentityEvent(t, "valid", only(t, h.Events(), "https://"+identityHost+"/valid"), c, "allow")
	if n := len(h.Issuer().DeviceRequests()); n != 0 {
		t.Errorf("%d device authorizations for a valid token, want 0", n)
	}
	assertUpstreamClean(t, up, 1)
	assertNoSignInSecrets(t, h, c.tok)
}

// challengeExpiredToken: an expired token is refused like no token, with
// reason expired and a fresh sign-in; the event keeps the status.
func challengeExpiredToken(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	tok := h.MintUserToken(fakes.Valid("erin", "erin@example.com"), fakes.Expired())
	r := connectChallenge(t, h, basicAuth("session", tok))
	assertChallenge(t, "expired", r, "expired")
	assertOffer(t, h, "expired", r)
	h.Eventually("the 407 to be recorded", func() bool { return len(identityRequiredEvents(h)) == 1 })
	e := identityRequiredEvents(h)[0]
	if e.IdentityStatus != "expired" || e.UserSub != "" || e.UserEmail != "" {
		t.Errorf("event status %q sub %q email %q, want expired and no user fields", e.IdentityStatus, e.UserSub, e.UserEmail)
	}
	if n := len(up.Requests()); n != 0 {
		t.Errorf("the upstream saw %d requests", n)
	}
	assertNoSignInSecrets(t, h, append(offerSecrets(r), tok)...)
}

// challengeInvalidToken: a token with the wrong audience gets reason invalid.
func challengeInvalidToken(t *testing.T, h *harness.H) {
	tok := h.MintUserToken(fakes.Valid("walt", "walt@example.com"), fakes.WrongAudience())
	r := connectChallenge(t, h, basicAuth("session", tok))
	assertChallenge(t, "invalid", r, "invalid")
	assertOffer(t, h, "invalid", r)
	// A malformed credential is refused the same way, and its text is not echoed.
	m := connectChallenge(t, h, "Basic !!!not-base64!!!")
	assertChallenge(t, "malformed", m, "invalid")
	if strings.Contains(m.raw, "not-base64") {
		t.Errorf("the 407 echoes the credential")
	}
	assertNoSignInSecrets(t, h, append(offerSecrets(r, m), tok)...)
}

// challengeUnverified: with the issuer down and the key cache cold a token
// cannot be checked. Challenge mode fails closed (407, reason unverified); the
// same setup in attribute mode still allows. The issuer is down for the device
// start too, so there is no sign_in and the error says why.
func challengeUnverified(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	iss := h.Issuer()
	iss.Stop()
	tok := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	r := connectChallenge(t, h, basicAuth("session", tok))
	assertChallenge(t, "unverified", r, "unverified")
	if r.body.SignIn != nil || r.body.SignInError != "issuer_unreachable" {
		t.Errorf("unverified with the issuer down: sign_in %v, sign_in_error %q, want none / issuer_unreachable", r.body.SignIn, r.body.SignInError)
	}
	h.Eventually("the 407 to be recorded", func() bool { return len(identityRequiredEvents(h)) == 1 })
	if e := identityRequiredEvents(h)[0]; e.IdentityStatus != "unverified" || e.IdentityReason != "jwks_unavailable" {
		t.Errorf("event status %q reason %q, want unverified / jwks_unavailable", e.IdentityStatus, e.IdentityReason)
	}
	if n := len(up.Requests()); n != 0 {
		t.Errorf("the upstream saw %d requests; unverified must fail closed", n)
	}

	// Same setup, attribute mode: the request is allowed (fail open).
	if err := editIdentity(t, h, func(s *config.IdentitySettings) { s.DefaultMode = config.IdentityModeAttribute }); err != nil {
		t.Fatalf("switch to attribute: %v", err)
	}
	c := idToken{name: "unverified", tok: tok, status: "unverified", reason: "jwks_unavailable"}
	n := 0
	h.Eventually("attribute mode to let the unverified token through", func() bool {
		n++
		return idTransports[0].get(t, h, c, fmt.Sprintf("/attr_%d", n)) == http.StatusOK
	})
	assertNoSignInSecrets(t, h, tok)
}

// challengeIssuerDown: the issuer is up for discovery but the device endpoint
// fails. The 407 stays, with no sign_in and sign_in_error issuer_unreachable;
// the failure is not cached, so the next request signs in once it recovers.
func challengeIssuerDown(t *testing.T, h *harness.H) {
	iss := h.Issuer()
	iss.SetDeviceStatus(http.StatusInternalServerError)
	r := connectChallenge(t, h, "")
	assertChallenge(t, "device endpoint down", r, "none")
	if r.body.SignIn != nil || r.body.SignInError != "issuer_unreachable" {
		t.Fatalf("sign_in %v, sign_in_error %q, want none / issuer_unreachable", r.body.SignIn, r.body.SignInError)
	}
	if strings.Contains(r.raw, "sign_in\":") {
		t.Errorf("body %q has a sign_in object", r.raw)
	}
	iss.SetDeviceStatus(0)
	ok := connectChallenge(t, h, "")
	assertChallenge(t, "recovered", ok, "none")
	assertOffer(t, h, "recovered", ok)
	assertSignInCounts(t, h, map[string]float64{"issuer_unreachable": 1, "started": 1})
	assertNoSignInSecrets(t, h, offerSecrets(ok)...)
}

// challengeSingleflight: 50 parallel CONNECTs from one agent share one device
// authorization at the issuer and are all handed the same offer.
func challengeSingleflight(t *testing.T, h *harness.H) {
	const n = 50
	replies := make([]challengeReply, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	addr := h.ProxyAddr()
	for i := range replies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replies[i], errs[i] = rawConnect(addr, challengeTarget, "")
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("CONNECT %d: %v", i, err)
		}
		assertChallenge(t, fmt.Sprintf("CONNECT %d", i), replies[i], "none")
		if replies[i].body.SignIn == nil || replies[i].body.SignIn.DeviceCode != replies[0].body.SignIn.DeviceCode {
			t.Fatalf("CONNECT %d did not get the shared offer", i)
		}
	}
	if got := len(h.Issuer().DeviceRequests()); got != 1 {
		t.Errorf("%d device_authorization calls for %d parallel CONNECTs, want exactly 1", got, n)
	}
	assertSignInCounts(t, h, map[string]float64{"started": 1, "reused": n - 1})
	assertNoSignInSecrets(t, h, offerSecrets(replies[0])...)
}

// challengeRateLimit: the worker allows one device authorization a minute. The
// offer is reused while it lives; once it has lapsed a new start is over the
// bound and the 407 says rate_limited, with no sign_in.
func challengeRateLimit(t *testing.T, h *harness.H) {
	h.Issuer().SetDeviceExpiresIn(2) // reuse window of one second
	first := connectChallenge(t, h, "")
	assertChallenge(t, "first", first, "none")
	assertOffer(t, h, "first", first)
	var limited challengeReply
	h.Eventually("a new start to be refused as rate_limited", func() bool {
		limited = connectChallenge(t, h, "")
		return limited.body.SignInError == "rate_limited"
	})
	assertChallenge(t, "rate limited", limited, "none")
	if limited.body.SignIn != nil {
		t.Errorf("a rate-limited 407 carries a sign_in object")
	}
	if got := len(h.Issuer().DeviceRequests()); got != 1 {
		t.Errorf("%d device authorizations, want 1: the bound must stop the second", got)
	}
	got := signInCounts(h)
	if got != nil && (got["started"] != 1 || got["rate_limited"] < 1) {
		t.Errorf("signin counters = %v, want started 1 and rate_limited >= 1", got)
	}
	assertNoSignInSecrets(t, h, offerSecrets(first)...)
}

// challengeForeignURL: an issuer that returns a verification URI on another
// origin is not believed: the URLs are dropped and the 407 says so.
func challengeForeignURL(t *testing.T, h *harness.H) {
	h.Issuer().SetDeviceVerificationBase("https://evil.example.org")
	r := connectChallenge(t, h, "")
	assertChallenge(t, "foreign url", r, "none")
	if r.body.SignIn != nil || r.body.SignInError != "issuer_unreachable" {
		t.Errorf("sign_in %v, sign_in_error %q, want none / issuer_unreachable", r.body.SignIn, r.body.SignInError)
	}
	if strings.Contains(r.raw, "evil.example.org") || strings.Contains(r.raw, "device-code") || strings.Contains(r.raw, "ABCD-") {
		t.Errorf("the 407 passes through what the foreign issuer returned: %q", r.raw)
	}
	assertSignInCounts(t, h, map[string]float64{"issuer_unreachable": 1})
	assertNoSignInSecrets(t, h, "device-code-1", "ABCD-0001")
}

// challengeSignedInNext: once a request carries a valid token the agent's
// pending sign-in is dropped, so the next challenge starts a new one (the
// client signed out and must sign in again).
func challengeSignedInNext(t *testing.T, h *harness.H) {
	first := connectChallenge(t, h, "")
	assertOffer(t, h, "first", first)
	tok := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	if st, _, _ := h.ConnectReplyFull(challengeTarget, basicAuth("session", tok)); st != http.StatusOK {
		t.Fatalf("valid token: CONNECT status %d, want 200", st)
	}
	second := connectChallenge(t, h, "")
	assertOffer(t, h, "second", second)
	if second.body.SignIn.DeviceCode == first.body.SignIn.DeviceCode || second.body.SignIn.UserCode == first.body.SignIn.UserCode {
		t.Errorf("the offer after a sign-in is the old one; want a new device authorization")
	}
	if got := len(h.Issuer().DeviceRequests()); got != 2 {
		t.Errorf("%d device authorizations, want 2", got)
	}
	assertNoSignInSecrets(t, h, append(offerSecrets(first, second), tok)...)
}

// attributeUnchanged: attribute mode is byte-for-byte what it was before
// challenge existed. A CONNECT with no token, an expired token or a bad one is
// tunnelled with the plain 200 line, a policy deny is the plain 403 line, and no
// device authorization, sign-in metric or challenge field exists.
func attributeUnchanged(t *testing.T, h *harness.H) {
	up := h.Upstream(identityHost)
	expired := h.MintUserToken(fakes.Valid("erin", "erin@example.com"), fakes.Expired())
	for name, auth := range map[string]string{
		"no token": "", "expired": basicAuth("session", expired), "malformed": "Basic !!!",
	} {
		if got := rawConnectBytes(t, h, challengeTarget, auth); got != "HTTP/1.1 200 Connection Established\r\n\r\n" {
			t.Errorf("%s: CONNECT reply %q, want the plain 200 line", name, got)
		}
	}
	if got := rawConnectBytes(t, h, identityDenyHost+":443", ""); got != "HTTP/1.1 403 Forbidden\r\n\r\n" {
		t.Errorf("policy deny: reply %q, want the plain 403 line", got)
	}
	c := idToken{name: "none", status: "none"}
	if got := idTransports[0].get(t, h, c, "/plain"); got != http.StatusOK {
		t.Fatalf("no token: status %d, want 200", got)
	}
	assertIdentityEvent(t, "no token", only(t, h.Events(), "https://"+identityHost+"/plain"), c, "allow")
	for _, e := range h.Events() {
		if e.Reason == "identity_required" || e.Reason == "identity_expired" || e.Reason == "identity_conflict" {
			t.Errorf("attribute mode recorded a challenge reason: %+v", e)
		}
	}
	if n := len(h.Issuer().DeviceRequests()); n != 0 {
		t.Errorf("%d device authorizations in attribute mode, want 0", n)
	}
	if got := signInCounts(h); len(got) != 0 {
		t.Errorf("sign-in counters in attribute mode: %v", got)
	}
	assertNoIdentityHeaders(t, up)
	assertNoSignInSecrets(t, h, expired)
}

// rawConnectBytes returns the exact bytes the worker writes in reply to one
// CONNECT, up to the close or the first idle moment (a tunnel stays open).
func rawConnectBytes(t *testing.T, h *harness.H, hostPort, auth string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the worker proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostPort, hostPort)
	if auth != "" {
		req += "Proxy-Authorization: " + auth + "\r\n"
	}
	if _, err := fmt.Fprint(conn, req+"\r\n"); err != nil {
		t.Fatalf("send CONNECT: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	b, _ := io.ReadAll(conn)
	return string(b)
}

// challengeFleetFlag: workers of this build advertise identity/challenge-v1, so
// with challenge mode served the fleet view flags only the legacy worker (a
// heartbeat without caps), the one that would silently keep allowing, and clears
// the flag once the control plane serves another mode.
func challengeFleetFlag(t *testing.T, h *harness.H) {
	const legacy = "legacy-old-worker"
	flags := func() (map[string]bool, bool) {
		// Workers heartbeat on the harness's fake clock: one beat per advance.
		h.Clock().Advance(time.Second)
		if r := h.CP().DoWorker(http.MethodPost, "/control/heartbeat", h.CP().Token(), legacy, `{"policyETag":"x"}`); r.Status != http.StatusNoContent {
			t.Fatalf("legacy heartbeat = %d", r.Status)
		}
		ws, err := h.CP().Workers()
		if err != nil {
			return nil, false
		}
		out := map[string]bool{}
		for _, w := range ws {
			if w.ProxyID != legacy && !slices.Contains(w.Caps, config.CapIdentityChallengeV1) {
				return nil, false // the real worker has not heartbeated yet
			}
			out[w.ProxyID] = w.NoIdentityChallenge
		}
		_, ok := out[legacy]
		return out, ok && len(out) > 1
	}
	h.Eventually("only the legacy worker is flagged noIdentityChallenge", func() bool {
		got, ok := flags()
		if !ok {
			return false
		}
		for id, flagged := range got {
			if flagged != (id == legacy) {
				return false
			}
		}
		return true
	})
	if err := editIdentity(t, h, func(s *config.IdentitySettings) { s.DefaultMode = config.IdentityModeAttribute }); err != nil {
		t.Fatalf("switch to attribute: %v", err)
	}
	h.Eventually("the flag clears when challenge is no longer served", func() bool {
		got, ok := flags()
		if !ok {
			return false
		}
		for _, flagged := range got {
			if flagged {
				return false
			}
		}
		return true
	})
}

// challengeHotReload: the control plane accepts challenge mode and the signIn
// block through its settings API and the worker applies them live. A worker in
// attribute mode tunnels an anonymous CONNECT; after the edit the same CONNECT
// gets the 407 and a sign-in offer, with no restart.
func challengeHotReload(t *testing.T, h *harness.H) {
	h.Upstream(identityHost)
	if r := rawConnectBytes(t, h, challengeTarget, ""); !strings.HasPrefix(r, "HTTP/1.1 200 ") {
		t.Fatalf("attribute mode: reply %q, want the plain 200", r)
	}
	err := editIdentity(t, h, func(s *config.IdentitySettings) {
		s.DefaultMode = config.IdentityModeChallenge
		s.SignIn = &config.SignInSettings{ClientID: "warden-cli", MaxPending: 4, StartsPerMinute: 10, Scopes: []string{"openid", "email"}}
	})
	if err != nil {
		t.Fatalf("the control plane refused challenge mode: %v", err)
	}
	var r challengeReply
	h.Eventually("the worker to apply challenge mode", func() bool {
		var err error
		r, err = rawConnect(h.ProxyAddr(), challengeTarget, "")
		return err == nil && r.status == http.StatusProxyAuthRequired
	})
	assertChallenge(t, "after the edit", r, "none")
	assertOffer(t, h, "after the edit", r)
	if reqs := h.Issuer().DeviceRequests(); len(reqs) != 1 || reqs[0].Scope != "openid email" {
		t.Errorf("device authorizations = %+v, want one with the configured scopes", reqs)
	}
	var cur struct {
		Settings *config.SettingsWire `json:"settings"`
	}
	if err := h.CP().GetJSON("/dashboard/api/settings", &cur); err != nil {
		t.Fatal(err)
	}
	if id := cur.Settings.Identity; id == nil || id.DefaultMode != config.IdentityModeChallenge || id.SignIn == nil || id.SignIn.MaxPending != 4 {
		t.Errorf("the control plane does not serve what was saved: %+v", id)
	}
	assertNoSignInSecrets(t, h, offerSecrets(r)...)
}
