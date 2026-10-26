//go:build e2e

package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness/compose"
)

// Runtime proofs for the Dex recipe (W-P1-DEX-06). The static tests prove the
// files are well-formed; these prove the recipe works with Dex and OpenLDAP
// running. Dex is reached exactly as a developer reaches it: the published
// port, no dialer override, no hosts entry. No test prints a token, password,
// client secret, device code or refresh token; a failure names claims and
// shows decoded non-secret claims only.

const (
	dexInternalURL = "http://dex:5556/dex" // the origin a container dials
	dexTokenTTL    = 3600                  // seconds: expiry.idTokens 1h in config.dev.yaml
	wantAudience   = "warden"
	deviceScope    = "openid groups offline_access audience:server:client_id:warden"
)

// claims is a decoded ID token payload. Only non-secret claims are read from it.
type claims map[string]any

// idClaims decodes the payload segment of a JWT without verifying it.
func idClaims(t testing.TB, token string) claims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("identity: ID token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("identity: ID token payload is not base64url: %v", err)
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("identity: ID token payload is not JSON: %v", err)
	}
	return c
}

// strList reads a claim that is a string or a list of strings.
func (c claims) strList(name string) []string {
	switch v := c[name].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, e := range list {
		if e == want {
			return true
		}
	}
	return false
}

// claimWant is what a seeded user's ID token must carry.
type claimWant struct {
	groups      []string // must all be present
	noWardenGrp bool     // no group may start with "warden-"
}

// checkClaims returns one problem per violated expectation. Problems name the
// claim and the non-secret value, never the token. Pure, so the mutation
// cases are unit-tested without Docker (TestDexClaimChecksReject).
func checkClaims(c claims, w claimWant) []string {
	var bad []string
	if !contains(c.strList("aud"), wantAudience) {
		bad = append(bad, fmt.Sprintf("aud = %v, want it to contain %q", c.strList("aud"), wantAudience))
	}
	if azp, _ := c["azp"].(string); azp != harnessClientID {
		bad = append(bad, fmt.Sprintf("azp = %q, want %q", azp, harnessClientID))
	}
	if iss, _ := c["iss"].(string); iss != dexURL {
		bad = append(bad, fmt.Sprintf("iss = %q, want exactly %q", iss, dexURL))
	}
	exp, expOK := c["exp"].(float64)
	iat, iatOK := c["iat"].(float64)
	if !expOK || !iatOK || int64(exp)-int64(iat) != dexTokenTTL {
		bad = append(bad, fmt.Sprintf("exp-iat = %v (exp %v, iat %v), want %d", exp-iat, exp, iat, dexTokenTTL))
	}
	groups := c.strList("groups")
	for _, g := range w.groups {
		if !contains(groups, g) {
			bad = append(bad, fmt.Sprintf("groups = %v, want it to contain %q", groups, g))
		}
	}
	if w.noWardenGrp {
		for _, g := range groups {
			if strings.HasPrefix(g, "warden-") {
				bad = append(bad, fmt.Sprintf("groups = %v, want no warden-* group", groups))
				break
			}
		}
	}
	return bad
}

var (
	aliceWant = claimWant{groups: []string{"warden-admins", "eng"}}
	daveWant  = claimWant{groups: []string{"eng"}, noWardenGrp: true}
)

// goodClaims is a token payload that satisfies aliceWant.
func goodClaims() claims {
	return claims{
		"aud":    []any{harnessClientID, wantAudience},
		"azp":    harnessClientID,
		"iss":    dexURL,
		"exp":    float64(1_700_003_600),
		"iat":    float64(1_700_000_000),
		"groups": []any{"warden-admins", "eng"},
	}
}

// TestDexClaimChecksReject is the red-first proof for TestDexTokenClaims, with
// no Docker: each drift the ticket names (idTokens expiry, audience, alice
// losing warden-admins) and the issuer and azp make checkClaims report a
// problem, and a good payload reports none.
func TestDexClaimChecksReject(t *testing.T) {
	if bad := checkClaims(goodClaims(), aliceWant); len(bad) != 0 {
		t.Fatalf("a good payload was rejected: %v", bad)
	}
	mutations := map[string]func(c claims){
		"idTokens changed to 2h":      func(c claims) { c["exp"] = float64(1_700_007_200) },
		"aud lost warden":             func(c claims) { c["aud"] = []any{harnessClientID} },
		"alice lost warden-admins":    func(c claims) { c["groups"] = []any{"eng"} },
		"azp is not the harness":      func(c claims) { c["azp"] = "warden-cli" },
		"issuer is the internal name": func(c claims) { c["iss"] = dexInternalURL },
	}
	for name, mutate := range mutations {
		c := goodClaims()
		mutate(c)
		if bad := checkClaims(c, aliceWant); len(bad) == 0 {
			t.Errorf("%s: checkClaims accepted the payload", name)
		}
	}
	// dave must carry no warden-* group.
	c := goodClaims()
	c["groups"] = []any{"eng", "warden-admins"}
	if bad := checkClaims(c, daveWant); len(bad) == 0 {
		t.Errorf("dave with warden-admins was accepted")
	}
}

// serviceContainer finds the running container of a compose service of the
// stack. It uses the compose labels, so it needs neither the compose file list
// nor the secrets those files interpolate.
func serviceContainer(t testing.TB, service string) string {
	t.Helper()
	res := compose.Run(".", compose.ComposeDeadline, "docker", "ps", "-q",
		"--filter", "label=com.docker.compose.project="+compose.Project,
		"--filter", "label=com.docker.compose.service="+service)
	ids := strings.Fields(res.Stdout)
	if res.Exit != 0 || len(ids) != 1 {
		t.Fatalf("identity: want exactly one running %s container, got %d (exit %d): %s", service, len(ids), res.Exit, firstLine(res.Stderr))
	}
	return ids[0]
}

// getDiscovery GETs a discovery document and returns its fields.
type discovery struct {
	Issuer                      string `json:"issuer"`
	JWKSURI                     string `json:"jwks_uri"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

func parseDiscovery(t testing.TB, where string, body []byte) discovery {
	t.Helper()
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("identity: %s discovery is not JSON: %v", where, err)
	}
	return d
}

func TestDexIssuerConsistent(t *testing.T) {
	requireStack(t)

	resp, err := hostClient.Get(dexURL + discoveryPath)
	if err != nil {
		t.Fatalf("GET %s%s: %v", dexURL, discoveryPath, redactURLError(err))
	}
	hostBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("host discovery status = %d, want 200", resp.StatusCode)
	}
	host := parseDiscovery(t, "host", hostBody)

	// From inside the network, a container dials the internal origin dex:5556
	// explicitly. The CP image is alpine without curl; busybox wget makes the
	// same GET.
	cid := serviceContainer(t, compose.SvcCP)
	res := compose.Run(".", compose.ComposeDeadline, "docker", "exec", cid, "wget", "-q", "-O-", dexInternalURL+discoveryPath)
	if res.Exit != 0 {
		t.Fatalf("wget %s%s inside %s: exit %d: %s", dexInternalURL, discoveryPath, compose.SvcCP, res.Exit, firstLine(res.Stderr))
	}
	inner := parseDiscovery(t, "container", []byte(res.Stdout))

	for where, d := range map[string]discovery{"host": host, "container": inner} {
		if d.Issuer != dexURL {
			t.Errorf("%s: issuer = %q, want exactly %q", where, d.Issuer, dexURL)
		}
		if d.DeviceAuthorizationEndpoint == "" {
			t.Errorf("%s: discovery has no device_authorization_endpoint", where)
		}
	}
	if host.Issuer != inner.Issuer {
		t.Errorf("issuer differs by origin: host %q, container %q", host.Issuer, inner.Issuer)
	}
}

// runTokenScript runs scripts/dex-token.sh with the .env.example values and no
// DEX_URL, so the script's default issuer is what is exercised.
func runTokenScript(t testing.TB, user, password string, extra ...string) (stdout, stderr string, exit int) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatalf("BLOCKED: scripts/dex-token.sh needs jq on PATH")
		}
		t.Skip("BLOCKED (skipped, not passed): scripts/dex-token.sh needs jq on PATH; this test did NOT run")
	}
	root, err := compose.RepoRoot()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "DEX_URL" || k == "DEX_TEST_PASSWORD" || k == "HARNESS_DEX_CLIENT_SECRET" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"DEX_TEST_PASSWORD="+password,
		"HARNESS_DEX_CLIENT_SECRET="+devEnv(t, "HARNESS_DEX_CLIENT_SECRET"))
	res := compose.RunEnv(root, env, compose.ComposeDeadline, filepath.Join(root, "scripts", "dex-token.sh"), append([]string{user}, extra...)...)
	return res.Stdout, res.Stderr, res.Exit
}

func TestDexTokenClaims(t *testing.T) {
	requireStack(t)
	password := devEnv(t, "DEX_TEST_PASSWORD")

	cases := []struct {
		user string
		want claimWant
	}{{"alice", aliceWant}, {"dave", daveWant}}
	for _, tc := range cases {
		t.Run(tc.user+" via scripts/dex-token.sh", func(t *testing.T) {
			stdout, stderr, exit := runTokenScript(t, tc.user, password)
			if exit != 0 {
				t.Fatalf("dex-token.sh %s exited %d: %s", tc.user, exit, firstLine(stderr))
			}
			// Default output is the decoded claims; the script prints no token.
			var shown claims
			if err := json.Unmarshal([]byte(stdout), &shown); err != nil {
				t.Fatalf("dex-token.sh output is not JSON claims: %v", err)
			}
			if strings.Contains(stdout, "eyJ") {
				t.Errorf("dex-token.sh printed something JWT-shaped without --raw")
			}
			// The script prints sub/email/groups/aud/azp/exp/iat (no iss), and
			// has already enforced aud, azp and exp-iat itself.
			if !contains(shown.strList("aud"), wantAudience) {
				t.Errorf("script aud = %v, want it to contain %q", shown.strList("aud"), wantAudience)
			}
			if azp, _ := shown["azp"].(string); azp != harnessClientID {
				t.Errorf("script azp = %q, want %q", azp, harnessClientID)
			}
			checkGroups(t, shown.strList("groups"), tc.want)
			// --raw prints only the token, so the claims the printed form
			// omits (iss, and exp-iat in full) are checked on the same path.
			rawOut, rawErr, rawExit := runTokenScript(t, tc.user, password, "--raw")
			if rawExit != 0 {
				t.Fatalf("dex-token.sh %s --raw exited %d: %s", tc.user, rawExit, firstLine(rawErr))
			}
			for _, p := range checkClaims(idClaims(t, strings.TrimSpace(rawOut)), tc.want) {
				t.Errorf("%s (script --raw): %s", tc.user, p)
			}
		})
		t.Run(tc.user+" via the Go helper", func(t *testing.T) {
			c := idClaims(t, dexToken(t, tc.user))
			for _, p := range checkClaims(c, tc.want) {
				t.Errorf("%s: %s", tc.user, p)
			}
		})
	}

	t.Run("wrong password fails without echoing it", func(t *testing.T) {
		const wrong = "definitely-not-the-password-7731"
		stdout, stderr, exit := runTokenScript(t, "alice", wrong)
		if exit == 0 {
			t.Fatalf("dex-token.sh accepted a wrong password")
		}
		if strings.Contains(stdout+stderr, wrong) || strings.Contains(stdout+stderr, password) {
			t.Errorf("the failure output echoes a password")
		}
		if strings.Contains(stdout+stderr, devEnv(t, "HARNESS_DEX_CLIENT_SECRET")) {
			t.Errorf("the failure output echoes the client secret")
		}
		if strings.TrimSpace(stderr) == "" {
			t.Errorf("a failed run printed no error")
		}
	})
}

// checkGroups applies only the group part of a claimWant.
func checkGroups(t testing.TB, groups []string, w claimWant) {
	t.Helper()
	c := claims{"groups": toAny(groups)}
	for _, p := range checkClaims(c, w) {
		if strings.HasPrefix(p, "groups") {
			t.Error(p)
		}
	}
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func TestDexDeviceFlow(t *testing.T) {
	requireStack(t)

	form := url.Values{"client_id": {"warden-cli"}, "scope": {deviceScope}}
	resp, err := hostClient.PostForm(dexURL+"/device/code", form)
	if err != nil {
		t.Fatalf("POST device/code: %v", redactURLError(err))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device/code status = %d, want 200", resp.StatusCode)
	}
	var dev struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
	}
	if err := json.Unmarshal(body, &dev); err != nil {
		t.Fatalf("device/code response is not JSON: %v", err)
	}
	for name, v := range map[string]string{"device_code": dev.DeviceCode, "user_code": dev.UserCode, "verification_uri": dev.VerificationURI} {
		if v == "" {
			t.Errorf("device/code response has no %s", name)
		}
	}

	// Nobody has approved the code, so the polling endpoint must say so.
	poll := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {dev.DeviceCode},
		"client_id":   {"warden-cli"},
	}
	presp, err := hostClient.PostForm(dexURL+"/token", poll)
	if err != nil {
		t.Fatalf("poll token endpoint: %v", redactURLError(err))
	}
	pbody, _ := io.ReadAll(io.LimitReader(presp.Body, 1<<20))
	presp.Body.Close()
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(pbody, &out); err != nil {
		t.Fatalf("poll response (status %d) is not JSON", presp.StatusCode)
	}
	if out.Error != "authorization_pending" {
		t.Errorf("poll: status %d, error %q, want authorization_pending", presp.StatusCode, out.Error)
	}
}

// jwks is the subset of a JSON Web Key Set the signature check needs.
type jwks struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// verifyRS256 checks the JWT's signature against the key set with the standard
// library only. It returns the kid it verified with.
func verifyRS256(token string, set jwks) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token has %d segments", len(parts))
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return "", fmt.Errorf("alg = %q, want RS256", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	for _, k := range set.Keys {
		if k.Kid != hdr.Kid || k.Kty != "RSA" {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			return "", fmt.Errorf("key %q has a malformed modulus or exponent", k.Kid)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return "", fmt.Errorf("signature does not verify with key %q", k.Kid)
		}
		return k.Kid, nil
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	sort.Strings(kids)
	return "", fmt.Errorf("no key with kid %q in the published set %v", hdr.Kid, kids)
}

// signRS256 builds a JWT signed with key, for the verifier tests.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid, payload string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc([]byte(`{"alg":"RS256","kid":"`+kid+`"}`)) + "." + enc([]byte(payload))
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

func publicSet(kid string, key *rsa.PrivateKey) jwks {
	var set jwks
	set.Keys = append(set.Keys, struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}{
		Kid: kid, Kty: "RSA", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	})
	return set
}

// TestDexVerifyRS256 pins the verifier with no Docker, so the restart proof
// cannot go vacuous: a good token verifies; a tampered payload, a signature by
// another key, alg none, an unknown kid and a malformed token all fail.
func TestDexVerifyRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := publicSet("k1", key)
	good := signRS256(t, key, "k1", `{"sub":"x"}`)
	if kid, err := verifyRS256(good, set); err != nil || kid != "k1" {
		t.Fatalf("a correctly signed token: kid %q, err %v", kid, err)
	}

	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"y"}`)) + "." + parts[2]
	noneHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`))
	rejects := map[string]string{
		"tampered payload":     tampered,
		"signed by a stranger": signRS256(t, other, "k1", `{"sub":"x"}`),
		"unknown kid":          signRS256(t, key, "k2", `{"sub":"x"}`),
		"alg none":             noneHdr + "." + parts[1] + "." + parts[2],
		"two segments":         "a.b",
	}
	for name, tok := range rejects {
		if _, err := verifyRS256(tok, set); err == nil {
			t.Errorf("%s: the token verified", name)
		}
	}
}

func TestDexRestartSurvival(t *testing.T) {
	requireStack(t)

	g := dexGrant(t, "alice")
	if g.RefreshToken == "" {
		t.Fatal("the password grant returned no refresh token (offline_access)")
	}
	before := idClaims(t, g.IDToken)

	cid := serviceContainer(t, "dex")
	if res := compose.Run(".", compose.ComposeDeadline, "docker", "restart", cid); res.Exit != 0 {
		t.Fatalf("docker restart dex: exit %d: %s", res.Exit, firstLine(res.Stderr))
	}
	err := compose.PollUntil(compose.StackDeadline, func() (bool, string) {
		res := compose.Run(".", compose.ProbeDeadline, "docker", "inspect", "-f", "{{.State.Health.Status}}", cid)
		if st := strings.TrimSpace(res.Stdout); st != "healthy" {
			return false, "dex health = " + st
		}
		if code, _, err := compose.PlainGet(dexURL + discoveryPath); err != nil || code != http.StatusOK {
			return false, fmt.Sprintf("dex discovery: status %d err %v", code, err)
		}
		return true, ""
	})
	if err != nil {
		t.Fatalf("dex did not come back healthy after restart: %v", err)
	}

	// The earlier ID token verifies against the keys Dex publishes NOW.
	resp, err := hostClient.Get(dexURL + "/keys")
	if err != nil {
		t.Fatalf("GET jwks: %v", redactURLError(err))
	}
	var set jwks
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks: status %d, decode err %v", resp.StatusCode, err)
	}
	kid, err := verifyRS256(g.IDToken, set)
	if err != nil {
		t.Fatalf("the pre-restart ID token no longer verifies: %v", err)
	}
	t.Logf("pre-restart ID token (sub %v) verifies with published key %s", before["sub"], kid)

	// The refresh token survives and mints a new ID token.
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {g.RefreshToken}}
	req, err := http.NewRequest(http.MethodPost, dexURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build refresh request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(harnessClientID, devEnv(t, "HARNESS_DEX_CLIENT_SECRET"))
	rresp, err := hostClient.Do(req)
	if err != nil {
		t.Fatalf("refresh request: %v", redactURLError(err))
	}
	rbody, _ := io.ReadAll(io.LimitReader(rresp.Body, 1<<20))
	rresp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(rbody, &out); err != nil {
		t.Fatalf("refresh response (status %d) is not JSON", rresp.StatusCode)
	}
	if rresp.StatusCode != http.StatusOK || out.IDToken == "" {
		t.Fatalf("refresh after restart: status %d, error %q", rresp.StatusCode, out.Error)
	}
	after := idClaims(t, out.IDToken)
	if after["sub"] != before["sub"] || after["iss"] != dexURL {
		t.Errorf("refreshed token: sub changed or iss = %v, want same sub and %q", after["iss"], dexURL)
	}
	if _, err := verifyRS256(out.IDToken, set); err != nil {
		t.Errorf("the refreshed ID token does not verify: %v", err)
	}
}
