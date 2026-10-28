package identityclient_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
)

// challengeWorker plays a worker in identity challenge mode: a CONNECT with a
// Proxy-Authorization gets 200 (and an echo), one without gets the 407 with the
// sign-in offer built by offer.
type challengeWorker struct {
	ln    net.Listener
	offer func() string // the JSON body of the 407

	mu    sync.Mutex
	heads []string
}

func newChallengeWorker(t *testing.T, offer func() string) *challengeWorker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &challengeWorker{ln: ln, offer: offer}
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
	if !strings.Contains(head.String(), "Proxy-Authorization:") {
		body := w.offer()
		_, _ = fmt.Fprintf(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"warden\"\r\n"+
			"Content-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		return
	}
	_, _ = io.WriteString(c, ok200)
	_, _ = io.Copy(c, br)
}

func (w *challengeWorker) Heads() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.heads...)
}

// offerJSON is a worker 407 body naming issuer and client.
func offerJSON(issuer, clientID, device string) string {
	return fmt.Sprintf(`{"error":"identity_required","reason":"none","sign_in":{"issuer":%q,"verification_uri":%q,`+
		`"verification_uri_complete":%q,"user_code":%q,"device_code":%q,"token_endpoint":%q,"client_id":%q,"interval":1,"expires_in":600}}`,
		issuer, issuer+"/activate", issuer+"/activate?user_code="+userCode, userCode, device, issuer+"/token", clientID)
}

type challengeRig struct {
	rig    *rig
	worker *challengeWorker
	addr   string
	notes  *notifications
	logs   *safeBuf
	chal   *identityclient.Challenger
}

// safeBuf is a log sink a test can read while a background poll still writes.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type notifications struct {
	mu sync.Mutex
	n  [][2]string
}

func (n *notifications) add(url, code string) {
	n.mu.Lock()
	n.n = append(n.n, [2]string{url, code})
	n.mu.Unlock()
}

func (n *notifications) all() [][2]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([][2]string(nil), n.n...)
}

// startChallengeForwarder runs a Forwarder with the challenge on, in front of a
// challengeWorker whose offer is offer(rig).
func startChallengeForwarder(t *testing.T, r *rig, offer func() string) *challengeRig {
	t.Helper()
	w := newChallengeWorker(t, offer)
	cr := &challengeRig{rig: r, worker: w, notes: &notifications{}, logs: &safeBuf{}}
	log := slog.New(slog.NewTextHandler(cr.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cr.chal = &identityclient.Challenger{Client: r.cl, Notify: cr.notes.add, Log: log}
	fwd := &identityclient.Forwarder{
		WorkerAddr: w.ln.Addr().String(), ClientCredential: fwdCred, Challenge: cr.chal, Log: log,
		Token: func(ctx context.Context) (string, error) {
			res, err := r.cl.Token(ctx)
			return res.IDToken, err
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cr.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fwd.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	return cr
}

// connect sends one CONNECT through the forwarder and returns the head and body.
func (c *challengeRig) connect(t *testing.T) (head string, body []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", c.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, connectReq("api.example.com:443", goodAuth())); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	head = readHead(t, br)
	if statusOf(head) == 200 {
		return head, nil
	}
	body, _ = io.ReadAll(br)
	return head, body
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestForwarderChallenge: with no login the forwarder dials the worker without
// credentials, shows the sign-in URL once, relays a 407 without the device code,
// polls the issuer, stores the token, and the next CONNECT carries it.
func TestForwarderChallenge(t *testing.T) {
	r := newRig(t)
	cr := startChallengeForwarder(t, r, func() string { return offerJSON(r.idp.URL(), identityclient.DefaultClientID, deviceCode) })

	head, body := cr.connect(t)
	if statusOf(head) != 407 || !strings.Contains(head, "Connection: close") || !strings.Contains(head, "Proxy-Authenticate: Basic") {
		t.Fatalf("first CONNECT: head %q, want a 407 that closes", head)
	}
	// The worker was dialled with no Proxy-Authorization at all.
	heads := cr.worker.Heads()
	if len(heads) != 1 || strings.Contains(heads[0], "Proxy-Authorization") {
		t.Fatalf("worker heads = %q, want one CONNECT without credentials", heads)
	}
	// The agent's body: the contract fields, no device code anywhere.
	if strings.Contains(string(body), deviceCode) || strings.Contains(string(body), "device_code") {
		t.Fatalf("the relayed body carries the device code: %s", body)
	}
	var got struct {
		Error, Reason string
		SignIn        map[string]any `json:"sign_in"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	if got.Error != "identity_required" || got.Reason != "none" ||
		got.SignIn["user_code"] != userCode || got.SignIn["verification_uri_complete"] != r.idp.URL()+"/activate?user_code="+userCode ||
		got.SignIn["verification_uri"] != r.idp.URL()+"/activate" || got.SignIn["expires_in"] != float64(600) {
		t.Fatalf("relayed body = %s", body)
	}
	if n := cr.notes.all(); len(n) != 1 || n[0][0] != r.idp.URL()+"/activate?user_code="+userCode || n[0][1] != userCode {
		t.Fatalf("notifications = %v, want one with the complete URL and the code", n)
	}

	// The poll stores the token (the fake issuer approves at once).
	waitFor(t, "the login to be stored", func() bool { _, err := r.cl.Status(); return err == nil })
	head, _ = cr.connect(t)
	if statusOf(head) != 200 {
		t.Fatalf("CONNECT after sign-in: head %q, want 200", head)
	}
	heads = cr.worker.Heads()
	tok, err := r.cl.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+tok.IDToken)) + "\r\n"
	if len(heads) != 2 || !strings.Contains(heads[1], want) {
		t.Fatalf("the CONNECT after sign-in does not carry the token: %q", heads)
	}
	// Nothing the forwarder logs holds a code or a token.
	if s := contains(cr.logs.String(), deviceCode, userCode, tok.IDToken); s != "" {
		t.Errorf("the forwarder log holds a credential")
	}
	if st, _ := os.Stat(r.cl.Store().Path()); st == nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the cache file is not mode 0600")
	}
}

// TestForwarderChallengeOnePoll: challenged CONNECTs that arrive while a poll
// runs share it: one notification, one poll.
func TestForwarderChallengeOnePoll(t *testing.T) {
	r := newRig(t)
	gate := make(chan struct{})
	var sleepCalls atomic.Int64
	r.cl.Sleep = func(ctx context.Context, d time.Duration) error {
		sleepCalls.Add(1)
		select {
		case <-gate:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	cr := startChallengeForwarder(t, r, func() string { return offerJSON(r.idp.URL(), identityclient.DefaultClientID, deviceCode) })
	for range 5 {
		head, body := cr.connect(t)
		if statusOf(head) != 407 || strings.Contains(string(body), "device_code") {
			t.Fatalf("head %q body %s", head, body)
		}
	}
	if n := cr.notes.all(); len(n) != 1 {
		t.Fatalf("%d notifications for one login, want 1", len(n))
	}
	waitFor(t, "the poll to start waiting", func() bool { return sleepCalls.Load() >= 1 })
	if n := sleepCalls.Load(); n != 1 {
		t.Errorf("%d concurrent polls, want 1", n)
	}
	close(gate)
	waitFor(t, "the login to be stored", func() bool { _, err := r.cl.Status(); return err == nil })
	// A 407 that raced the finished login and still names its code starts nothing.
	if head, _ := cr.connect(t); statusOf(head) != 200 {
		t.Fatalf("after sign-in: %q", head)
	}
}

// TestForwarderIgnoresForeignIssuer: an offer for another issuer or another
// client is not shown and not polled; the agent gets the 407 with no sign_in.
func TestForwarderIgnoresForeignIssuer(t *testing.T) {
	for name, offer := range map[string]func(r *rig) string{
		"issuer": func(r *rig) string {
			return offerJSON("http://evil.example.test/dex", identityclient.DefaultClientID, deviceCode)
		},
		"client id": func(r *rig) string { return offerJSON(r.idp.URL(), "someone-elses-client", deviceCode) },
		"no device code": func(r *rig) string {
			return offerJSON(r.idp.URL(), identityclient.DefaultClientID, "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			var sleeps atomic.Int64
			r.cl.Sleep = func(ctx context.Context, d time.Duration) error { sleeps.Add(1); return ctx.Err() }
			cr := startChallengeForwarder(t, r, func() string { return offer(r) })
			head, body := cr.connect(t)
			if statusOf(head) != 407 {
				t.Fatalf("head %q, want 407", head)
			}
			if strings.Contains(string(body), "sign_in\"") || strings.Contains(string(body), deviceCode) || strings.Contains(string(body), "evil") {
				t.Errorf("the relayed body keeps the untrusted offer: %s", body)
			}
			time.Sleep(50 * time.Millisecond)
			if n := cr.notes.all(); len(n) != 0 {
				t.Errorf("the user was told to sign in at %v", n)
			}
			if sleeps.Load() != 0 || r.idp.deviceCalls.Load() != 0 {
				t.Errorf("the client polled for a foreign offer")
			}
			if _, err := r.cl.Status(); !errors.Is(err, identityclient.ErrLoginRequired) {
				t.Errorf("a login was stored: %v", err)
			}
		})
	}
}

// TestForwarderChallengeOff: without a Challenger no login still means 503 and
// no dial: a worker that does not enforce identity is never asked anonymously.
func TestForwarderChallengeOff(t *testing.T) {
	r := startForwarder(t, ok200, func(context.Context) (string, error) { return "", identityclient.ErrLoginRequired })
	_, _, head := r.send(t, connectReq("api.example.com:443", goodAuth()))
	if statusOf(head) != 503 || r.worker.dials.Load() != 0 {
		t.Fatalf("head %q dials %d, want 503 and no dial", head, r.worker.dials.Load())
	}
}

// TestForwarderRefreshFailureThenChallenge: a refresh token the issuer rejects
// deletes the cache and the next CONNECT gets a fresh challenge.
func TestForwarderRefreshFailureThenChallenge(t *testing.T) {
	r := newRig(t)
	r.login(t)
	r.idp.mu.Lock()
	r.idp.refresh = "revoked-elsewhere"
	r.idp.mu.Unlock()
	r.clock.Advance(tokenTTL)
	cr := startChallengeForwarder(t, r, func() string { return offerJSON(r.idp.URL(), identityclient.DefaultClientID, deviceCode) })
	head, _ := cr.connect(t)
	if statusOf(head) != 407 {
		t.Fatalf("head %q, want the challenge after the refresh failed", head)
	}
	if _, err := os.Stat(r.cl.Store().Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dead cache entry is still there: %v", err)
	}
	if n := cr.notes.all(); len(n) != 1 {
		t.Errorf("%d notifications, want 1", len(n))
	}
}

// TestForwarderRelaysOtherProxyAuth407: a 407 that is not a Warden challenge is
// relayed as the worker wrote it (nothing is invented), and one that even
// mentions a device code is replaced, never passed on.
func TestForwarderRelaysOtherProxyAuth407(t *testing.T) {
	for name, tc := range map[string]struct {
		body       string
		wantBody   string
		wantNoCode bool
	}{
		"foreign body":        {body: `{"error":"something_else","detail":"proxy says no"}`, wantBody: `{"error":"something_else","detail":"proxy says no"}`},
		"empty body":          {body: ``, wantBody: ``},
		"half a challenge":    {body: `{"error":"identity_required","sign_in":{"device_code":"` + deviceCode + `"`, wantNoCode: true},
		"not json with codes": {body: `device_code=` + deviceCode, wantNoCode: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			cr := startChallengeForwarder(t, r, func() string { return tc.body })
			head, body := cr.connect(t)
			if statusOf(head) != 407 {
				t.Fatalf("head %q, want 407", head)
			}
			if tc.wantNoCode {
				if strings.Contains(string(body), deviceCode) || strings.Contains(string(body), "device_code") {
					t.Errorf("the device code was relayed: %s", body)
				}
			} else if string(body) != tc.wantBody {
				t.Errorf("body %q, want the worker's %q", body, tc.wantBody)
			}
			if n := cr.notes.all(); len(n) != 0 {
				t.Errorf("the user was told to sign in at %v", n)
			}
		})
	}
}
