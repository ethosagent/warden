package dnstest

import (
	"context"
	"net"
	"testing"
	"time"
)

// stubResolver returns a *net.Resolver pointed at the stub server, the same
// shape of resolver the proxy's NewUpstreamResolver builds.
func stubResolver(s *Server) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, s.Addr())
		},
	}
}

// TestStubAnswersA resolves a configured name through a real *net.Resolver and
// expects the stub's pinned A record — plus proof the query reached the stub.
func TestStubAnswersA(t *testing.T) {
	s := New(t, map[string]string{"stub.example.test": "93.184.216.34"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := stubResolver(s).LookupIPAddr(ctx, "stub.example.test")
	if err != nil {
		t.Fatalf("LookupIPAddr: %v", err)
	}
	if len(addrs) != 1 || addrs[0].IP.String() != "93.184.216.34" {
		t.Fatalf("resolved %v, want [93.184.216.34]", addrs)
	}
	if s.Queries.Load() == 0 {
		t.Fatal("stub received no queries; resolution bypassed it")
	}
}

// TestStubNXDOMAIN answers an unknown name with NXDOMAIN, so a lookup fails
// instead of hanging.
func TestStubNXDOMAIN(t *testing.T) {
	s := New(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := stubResolver(s).LookupIPAddr(ctx, "missing.example.test"); err == nil {
		t.Fatal("expected NXDOMAIN error for an unknown name")
	}
}

// TestStubDropsMalformed feeds the stub a non-DNS datagram; it must not crash
// (the serve loop keeps answering real queries afterwards).
func TestStubDropsMalformed(t *testing.T) {
	s := New(t, map[string]string{"stub.example.test": "127.0.0.1"})
	addr, err := net.ResolveUDPAddr("udp", s.Addr())
	if err != nil {
		t.Fatalf("resolve stub addr: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial stub: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("not a dns packet")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := stubResolver(s).LookupIPAddr(ctx, "stub.example.test"); err != nil {
		t.Fatalf("lookup after garbage packet: %v", err)
	}
}
