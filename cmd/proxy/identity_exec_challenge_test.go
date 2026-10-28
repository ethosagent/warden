package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// challengeWorker is a worker in identity challenge mode: a CONNECT with no
// Proxy-Authorization gets a 407 and a sign-in offer for issuer, one with a
// credential gets 200.
type challengeWorker struct {
	ln     net.Listener
	issuer string
	mu     sync.Mutex
	heads  []string
}

func newChallengeWorker(t *testing.T, issuer string) *challengeWorker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &challengeWorker{ln: ln, issuer: issuer}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go w.serve(c)
		}
	}()
	return w
}

func (w *challengeWorker) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	var head strings.Builder
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(l)
		if l == "\r\n" {
			break
		}
	}
	w.mu.Lock()
	w.heads = append(w.heads, head.String())
	w.mu.Unlock()
	if strings.Contains(head.String(), "Proxy-Authorization:") {
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		return
	}
	body := fmt.Sprintf(`{"error":"identity_required","reason":"none","sign_in":{"issuer":%q,"verification_uri":%q,`+
		`"verification_uri_complete":%q,"user_code":%q,"device_code":%q,"token_endpoint":%q,"client_id":"warden-cli","interval":1,"expires_in":600}}`,
		w.issuer, w.issuer+"/activate", w.issuer+"/activate?user_code="+testUserCode, testUserCode, testDeviceCode, w.issuer+"/token")
	_, _ = fmt.Fprintf(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"warden\"\r\n"+
		"Content-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

func (w *challengeWorker) authorized() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, h := range w.heads {
		if strings.Contains(h, "Proxy-Authorization:") {
			n++
		}
	}
	return n
}

// TestIdentityExecChallenge: `exec --challenge --signin-notify` starts with no
// login, prints the sign-in line on stderr, runs the hook with the URL and code
// (and no token), signs in through the issuer and the child's retry succeeds.
func TestIdentityExecChallenge(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := newIdP(t)
	w := newChallengeWorker(t, p.srv.URL)
	r := newRig(t, p.srv.URL)
	hookOut := filepath.Join(t.TempDir(), "hook.out")
	hook := `printf '%s|%s|%s' "$WARDEN_SIGNIN_URL" "$WARDEN_SIGNIN_CODE" "${WARDEN_IDENTITY_ISSUER-unset}" > ` + hookOut

	res := r.runExec("connect-retry", nil, "--worker", w.ln.Addr().String(), "--signin-notify", hook, "--", self, "-test.run=NONE")
	if res.err != nil {
		t.Fatalf("exec: %v\n%s", res.err, res.stderr)
	}
	wantURL := p.srv.URL + "/activate?user_code=" + testUserCode
	if !strings.Contains(res.stderr, "warden: sign in at "+wantURL+" (code "+testUserCode+")") {
		t.Errorf("stderr lacks the sign-in line:\n%s", res.stderr)
	}
	if n := strings.Count(res.stderr, "warden: sign in at"); n != 1 {
		t.Errorf("the sign-in line was printed %d times, want 1", n)
	}
	if !strings.Contains(res.stdout, "STATUS HTTP/1.1 407") || !strings.Contains(res.stdout, "STATUS HTTP/1.1 200") {
		t.Errorf("the child did not see a 407 then a 200:\n%s", res.stdout)
	}
	if w.authorized() < 1 {
		t.Error("no CONNECT carried the token after the sign-in")
	}
	got, err := os.ReadFile(hookOut)
	if err != nil || string(got) != wantURL+"|"+testUserCode+"|unset" {
		t.Errorf("hook output %q (%v), want the URL, the code and no WARDEN_IDENTITY_* setting", got, err)
	}
	e, lerr := r.cacheEntry()
	if lerr != nil {
		t.Fatalf("no login was stored: %v", lerr)
	}
	for _, secret := range []string{e.IDToken, e.RefreshToken, testDeviceCode, testRefresh, testAccess} {
		for name, text := range map[string]string{"stdout": res.stdout, "stderr": res.stderr, "hook output": string(got)} {
			if strings.Contains(text, secret) {
				t.Errorf("a token or device code reached %s: %.10s", name, secret)
			}
		}
	}
}

// TestIdentityExecChallengeNeedsTheFlag: without --challenge an exec with no
// login keeps exiting 2 and never asks the worker anonymously.
func TestIdentityExecChallengeNeedsTheFlag(t *testing.T) {
	p := newIdP(t)
	w := newChallengeWorker(t, p.srv.URL)
	r := newRig(t, p.srv.URL)
	res := r.runExec("env", nil, "--worker", w.ln.Addr().String(), "--", "true")
	if exitCode(res.err) != 2 {
		t.Fatalf("exit = %d (%v), want 2", exitCode(res.err), res.err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.heads) != 0 {
		t.Errorf("the worker was dialled %d times", len(w.heads))
	}
}
