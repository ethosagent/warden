package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/internal/keys"
)

// agentCP is a fake token endpoint (TLS) that issues a Warden-shaped token or
// a scripted RFC 6749 error.
type agentCP struct {
	srv    *httptest.Server
	caFile string
	status atomic.Int64 // 0 = issue a token
	code   atomic.Value // string
	calls  atomic.Int64
	last   atomic.Value // url.Values form
}

const wardenSecretMarker = "warden-token-body"

func newAgentCP(t *testing.T) *agentCP {
	t.Helper()
	cp := &agentCP{}
	cp.code.Store("")
	cp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cp.calls.Add(1)
		cp.last.Store(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		if st := int(cp.status.Load()); st != 0 {
			w.WriteHeader(st)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": cp.code.Load().(string), "error_description": "CP-DESC-MARKER"})
			return
		}
		exp := time.Now().Add(15 * time.Minute).Unix()
		claims, _ := json.Marshal(map[string]any{
			"sub": "user-1", "scope": "read", "exp": exp, "act": map[string]string{"sub": "agent-1"},
			"cnf": map[string]string{"jkt": "thumb-1"}, "marker": wardenSecretMarker,
		})
		tok := "eyJhbGciOiJFZERTQSJ9." + base64.RawURLEncoding.EncodeToString(claims) + ".c2ln"
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 900, "scope": "read"})
	}))
	t.Cleanup(cp.srv.Close)
	cp.caFile = filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.srv.Certificate().Raw})
	if err := os.WriteFile(cp.caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(cp.srv.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
	return cp
}

func (cp *agentCP) endpoint() string { return cp.srv.URL + "/oauth2/token" }

// agentRig enrolls an agent and prepares a 0600 subject token file.
type agentRigCmd struct {
	*rig
	cp          *agentCP
	keyFile     string
	subjectFile string
	subject     string
}

func newAgentCmdRig(t *testing.T) *agentRigCmd {
	t.Helper()
	cp := newAgentCP(t)
	r := newRig(t, "")
	dir := t.TempDir()
	a := &agentRigCmd{rig: r, cp: cp, keyFile: filepath.Join(dir, "agents", "agent-1.key"),
		subjectFile: filepath.Join(dir, "subject"), subject: "SUBJECT-ID-TOKEN-SECRET"}
	if err := os.WriteFile(a.subjectFile, []byte(a.subject+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.env[identityclient.EnvAgentID] = "agent-1"
	r.env[identityclient.EnvTokenEndpoint] = cp.endpoint()
	r.env[identityclient.EnvCPCA] = cp.caFile
	return a
}

func (a *agentRigCmd) enroll(t *testing.T, extra ...string) (string, string, error) {
	t.Helper()
	return a.run(append([]string{"identity", "enroll", "--key-file", a.keyFile}, extra...)...)
}

func TestIdentityEnrollAndTokenNoLeak(t *testing.T) {
	a := newAgentCmdRig(t)
	stdout, stderr, err := a.enroll(t)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// stdout is the public JWK and nothing else.
	jwk, err := keys.ParseJWK([]byte(stdout))
	if err != nil || jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" || strings.Contains(stdout, `"d"`) {
		t.Fatalf("enroll stdout = %q (%v), want the public JWK", stdout, err)
	}
	if thumb, _ := keys.Thumbprint(jwk); jwk.Kid != thumb {
		t.Fatalf("kid %q is not the RFC 7638 thumbprint %q", jwk.Kid, thumb)
	}
	pemKey, err := os.ReadFile(a.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	seed := string(pemKey)
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(seed), "-----BEGIN PRIVATE KEY-----"), "-----END PRIVATE KEY-----"))
	body = strings.ReplaceAll(body, "\n", "")
	if body == "" || strings.Contains(stdout+stderr, body) || strings.Contains(stdout+stderr, "PRIVATE KEY") {
		t.Fatal("enroll printed key material")
	}
	if _, _, err := a.enroll(t); err == nil {
		t.Fatal("a second enroll without --force succeeded")
	}
	if _, _, err := a.enroll(t, "--force"); err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	if _, _, err := a.run("identity", "enroll", "--agent-id", "bad id", "--key-file", a.keyFile+"2"); err == nil {
		t.Fatal("an invalid agent id was enrolled")
	}
	pemKey, _ = os.ReadFile(a.keyFile)
	body = strings.ReplaceAll(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(string(pemKey)), "-----BEGIN PRIVATE KEY-----"), "-----END PRIVATE KEY-----")), "\n", "")

	args := []string{"--verbose", "--agent-key-file", a.keyFile, "--subject-token-file", a.subjectFile}
	tokOut, tokErr, err := a.run(append([]string{"identity", "token"}, args...)...)
	if err != nil {
		t.Fatalf("token: %v (%s)", err, tokErr)
	}
	token := strings.TrimSpace(tokOut)
	if !strings.HasPrefix(token, "eyJ") || a.cp.calls.Load() != 1 {
		t.Fatalf("token stdout = %q calls %d", tokOut, a.cp.calls.Load())
	}
	stOut, stErr, err := a.run(append([]string{"identity", "status"}, args...)...)
	if err != nil {
		t.Fatalf("status: %v (%s)", err, stErr)
	}
	for _, want := range []string{"sub: user-1", "act.sub: agent-1", "cnf.jkt: thumb-1", "scope: read", "exp: "} {
		if !strings.Contains(stOut, want) {
			t.Errorf("status lacks %q:\n%s", want, stOut)
		}
	}
	assertion := a.cp.last.Load().(interface{ Get(string) string }).Get("client_assertion")
	if assertion == "" {
		t.Fatal("the control plane saw no assertion")
	}
	// The Ed25519 seed in every form it could surface: raw, the JWK "d" member
	// (base64url), standard base64 and hex.
	block, _ := pem.Decode(pemKey)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rawSeed := parsed.(ed25519.PrivateKey).Seed()
	secrets := map[string]string{
		"subject": a.subject, "assertion": assertion, "token": token, "pem body": body, "marker": wardenSecretMarker,
		"seed raw": string(rawSeed), "seed base64url": base64.RawURLEncoding.EncodeToString(rawSeed),
		"seed base64": base64.StdEncoding.EncodeToString(rawSeed), "seed hex": hex.EncodeToString(rawSeed),
	}
	outputs := map[string]string{"token stderr": tokErr, "status stdout": stOut, "status stderr": stErr, "enroll": stdout + stderr}
	for name, out := range outputs {
		for what, secret := range secrets {
			if secret != "" && strings.Contains(out, secret) {
				t.Errorf("%s holds the whole %s (%d bytes of it)", name, what, len(secret))
			}
			// Sliding window: no 16-character piece of a secret may appear.
			for _, w := range secretWindows(what, secret, 16) {
				if strings.Contains(out, w) {
					t.Errorf("%s holds a 16-character piece of the %s", name, what)
					break
				}
			}
		}
	}
	if !strings.Contains(tokErr, "agent_id=agent-1") {
		t.Errorf("verbose log lacks the agent id:\n%s", tokErr)
	}
	// A fingerprint is the only derivative of a token that may be logged.
	if !strings.Contains(tokErr, "token_fp="+identityclient.Fingerprint(token)) {
		t.Errorf("verbose log lacks the token fingerprint:\n%s", tokErr)
	}
}

func TestIdentityExitCodesAgent(t *testing.T) {
	run := func(a *agentRigCmd) (string, error) {
		t.Helper()
		stdout, _, err := a.run("identity", "token", "--agent-key-file", a.keyFile, "--subject-token-file", a.subjectFile)
		return stdout, err
	}
	t.Run("a refused exchange exits 4", func(t *testing.T) {
		a := newAgentCmdRig(t)
		if _, _, err := a.enroll(t); err != nil {
			t.Fatal(err)
		}
		for status, code := range map[int]string{401: "invalid_client", 400: "invalid_grant"} {
			a.cp.status.Store(int64(status))
			a.cp.code.Store(code)
			a.cp.calls.Store(0)
			stdout, err := run(a)
			var d identityclient.ErrExchangeDenied
			if !errors.As(err, &d) || d.Code != code || exitCode(err) != 4 || stdout != "" {
				t.Errorf("%s: code %d err %v stdout %q", code, exitCode(err), err, stdout)
			}
			if a.cp.calls.Load() != 1 {
				t.Errorf("%s was tried %d times", code, a.cp.calls.Load())
			}
			if strings.Contains(err.Error(), "CP-DESC-MARKER") {
				t.Errorf("the error echoes the response body: %v", err)
			}
		}
	})
	t.Run("an unreachable control plane exits 3", func(t *testing.T) {
		a := newAgentCmdRig(t)
		if _, _, err := a.enroll(t); err != nil {
			t.Fatal(err)
		}
		a.cp.srv.Close()
		if _, err := run(a); !errors.Is(err, identityclient.ErrCPUnreachable) || exitCode(err) != 3 {
			t.Errorf("code %d err %v, want 3", exitCode(err), err)
		}
	})
	t.Run("login required stays 2", func(t *testing.T) {
		p := newIdP(t)
		a := newAgentCmdRig(t)
		a.env[identityclient.EnvIssuer] = p.srv.URL
		a.env[identityclient.EnvCacheDir] = a.cacheDir
		if _, _, err := a.enroll(t); err != nil {
			t.Fatal(err)
		}
		_, _, err := a.run("identity", "token", "--agent-key-file", a.keyFile)
		if !errors.Is(err, identityclient.ErrLoginRequired) || exitCode(err) != 2 {
			t.Errorf("code %d err %v, want 2", exitCode(err), err)
		}
	})
	t.Run("missing configuration exits 1", func(t *testing.T) {
		a := newAgentCmdRig(t)
		delete(a.env, identityclient.EnvTokenEndpoint)
		if _, _, err := a.run("identity", "token", "--subject-token-file", a.subjectFile); err == nil || exitCode(err) != 1 {
			t.Errorf("no token endpoint: code %d err %v", exitCode(err), err)
		}
	})
	t.Run("a group-readable key is refused naming the path", func(t *testing.T) {
		a := newAgentCmdRig(t)
		if _, _, err := a.enroll(t); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(a.keyFile, 0o640); err != nil {
			t.Fatal(err)
		}
		_, err := run(a)
		if err == nil || !strings.Contains(err.Error(), a.keyFile) || a.cp.calls.Load() != 0 {
			t.Errorf("err %v calls %d", err, a.cp.calls.Load())
		}
	})
}

// secretWindows returns every n-character substring of secret. The constant
// parts shared by every key or JWT (the PKCS#8 header, the JWT header) are
// skipped, because they identify a format, not a secret.
func secretWindows(what, secret string, n int) []string {
	switch what {
	case "pem body":
		if len(secret) > 24 {
			secret = secret[24:] // the fixed PKCS#8 prefix of an Ed25519 key
		}
	case "assertion", "token":
		if i := strings.Index(secret, "."); i >= 0 {
			secret = secret[i+1:] // the JWT header
		}
	}
	var ws []string
	for i := 0; i+n <= len(secret); i++ {
		ws = append(ws, secret[i:i+n])
	}
	return ws
}
