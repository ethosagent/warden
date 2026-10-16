package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// TestServe_DenyHostWithTrailingDots pins #397 end to end: a denylist entry
// must deny its host no matter how many trailing dots the CONNECT authority
// carried. The judge is configured AND allow-happy, so a deny that slipped to
// NoMatch would be visible as a judge decision instead of the 403 — an explicit
// denylist hit is never judge-eligible. A CONNECT authority that is only dots
// must fail closed the same way.
func TestServe_DenyHostWithTrailingDots(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	judge := &fakeJudge{verdict: Verdict{Decision: "allow", Reason: "judge allows everything"}}
	p, store := startJudgeProxy(t,
		[]config.AllowlistEntry{{Domain: "allowed.example.com", Port: 443}},
		[]config.DenylistEntry{{Domain: "bad.corp.test"}},
		caCertPEM, caKeyPEM, judge,
	)

	for _, target := range []string{"bad.corp.test...:443", "...:443"} {
		conn, err := net.Dial("tcp", p.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		br := bufio.NewReader(conn)
		resp, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("CONNECT %s: %v", target, err)
		}
		if !strings.Contains(resp, "403") {
			t.Fatalf("CONNECT %s: expected 403, got %q", target, resp)
		}
		// Wait for connection close so handleConn has completed and stored the
		// analytics event.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadAll(br)
		_ = conn.Close()

		events := store.snapshot()
		if len(events) == 0 {
			t.Fatalf("CONNECT %s: expected a deny event", target)
		}
		last := events[len(events)-1]
		if last.Decision != "deny" {
			t.Fatalf("CONNECT %s: decision = %q, want deny", target, last.Decision)
		}
		if last.Protocol != "tcp" {
			t.Fatalf("CONNECT %s: protocol = %q, want tcp", target, last.Protocol)
		}
	}

	if n := judge.callCount(); n != 0 {
		t.Errorf("judge consulted %d times for a denylisted host, want 0", n)
	}
}

// TestTLS_HostRecheckAgreesWithAdmissionOnTrailingDots proves admission and the
// per-request Host recheck normalise the same way (#397): a tunnel admitted for
// a dotted CONNECT authority accepts a request whose Host header spells the
// same host differently (case / trailing dots). The dotted form was denied at
// CONNECT before the fix, and the recheck dropped the session on the dotted
// Host header.
func TestTLS_HostRecheckAgreesWithAdmissionOnTrailingDots(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	p, _ := startTestProxyWithSecrets(t, []string{"github.com"}, caCertPEM, caKeyPEM, map[string]string{}, nil)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "github.com...", caCertPEM)

	fmt.Fprint(tlsClient, "GET /v1/chat HTTP/1.1\r\nHost: github.com.\r\n\r\n")
	buf := make([]byte, 256)
	_ = tlsClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(tlsClient, buf[:8])
	if err != nil {
		t.Fatalf("expected the tunnel to carry the response (Host recheck must agree with admission), got n=%d err=%v", n, err)
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.method != "GET" || !strings.HasPrefix(rb.path, "/v1/chat") {
		t.Fatalf("backend saw method=%q path=%q, want GET /v1/chat", rb.method, rb.path)
	}
}

// TestReadRequest_HostRecheckNormalisesHost pins the recheck comparison unit:
// both sides go through the shared policy normalisation, so case and any
// number of trailing dots never disagree, while a different host — or a
// dots-only Host header — still ends the session (fail closed).
func TestReadRequest_HostRecheckNormalisesHost(t *testing.T) {
	p := &Proxy{}
	cases := []struct {
		domain, host string
		wantEnd      bool
	}{
		{"github.com", "github.com", false},
		{"github.com", "GITHUB.com.", false},
		{"github.com", "github.com...", false},
		{"GITHUB.com....", "github.com", false}, // admission saw the dotted form
		{"github.com...", "GitHub.COM.", false},
		{"github.com", "evil.test", true},
		{"github.com", "github.com.evil.test", true},
		{"github.com", "...", true}, // dots-only Host header: fail closed
		{"github.com", "", true},
	}
	for _, c := range cases {
		s := &requestScope{domain: c.domain, req: &http.Request{Host: c.host}}
		if got := p.readRequest(s); got != c.wantEnd {
			t.Errorf("readRequest(domain=%q, Host=%q) = %v, want %v", c.domain, c.host, got, c.wantEnd)
		}
	}
}
