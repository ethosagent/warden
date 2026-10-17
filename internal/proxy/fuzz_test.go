package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// scriptedConn is a net.Conn whose input is a fixed byte string followed by EOF
// and whose output is captured. handleConn runs against it synchronously, so a
// fuzz iteration needs no sockets and no goroutines.
type scriptedConn struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func (c *scriptedConn) Read(b []byte) (int, error)       { return c.in.Read(b) }
func (c *scriptedConn) Write(b []byte) (int, error)      { return c.out.Write(b) }
func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return fuzzAddr{} }
func (c *scriptedConn) RemoteAddr() net.Addr             { return fuzzAddr{} }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzAddr struct{}

func (fuzzAddr) Network() string { return "fuzz" }
func (fuzzAddr) String() string  { return "fuzz" }

// connectFuzzPolicy mixes exact, wildcard, port-pinned and denylisted entries.
func connectFuzzPolicy() config.Policy {
	return config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "allowed.test", Port: 443},
			{Domain: "*.wild.test", Port: 443},
			{Domain: "pinned.test", Port: 8443},
		},
		Denylist: []config.DenylistEntry{
			{Domain: "denied.test", Port: 443},
			{Domain: "*.evil.test", Port: 443},
		},
	}
}

// connectRun feeds raw to handleConn and returns what the proxy wrote plus every
// address it tried to dial. Dials fail: the point is the decision, not the relay.
func connectRun(p *Proxy, raw []byte, dialed *[]string) string {
	*dialed = nil
	p.dialFunc = func(_, addr string) (net.Conn, error) {
		*dialed = append(*dialed, addr)
		return nil, fmt.Errorf("fuzz: no dial")
	}
	c := &scriptedConn{in: bytes.NewReader(raw)}
	p.handleConn(c)
	return c.out.String()
}

func newConnectFuzzProxy(tb testing.TB) (*Proxy, *policy.Evaluator) {
	tb.Helper()
	ev := policy.NewEvaluator(connectFuzzPolicy())
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     ev,
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  &cappedStore{},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return p, ev
}

// checkConnectDecision is the oracle shared by the fuzz target and the pinned
// regression test. Whatever the bytes, the proxy must never open a tunnel (200)
// or dial for a destination the policy does not allow, and it must dial exactly
// what it evaluated.
func checkConnectDecision(p *Proxy, ev *policy.Evaluator, raw []byte) error {
	var dialed []string
	resp := connectRun(p, raw, &dialed)
	tunnel := strings.Contains(resp, "200 Connection Established")
	if !tunnel && len(dialed) > 0 {
		return fmt.Errorf("dialed %v without opening a tunnel", dialed)
	}
	if tunnel && !strings.HasPrefix(string(raw), "CONNECT ") {
		return fmt.Errorf("200 for a request that is not a CONNECT")
	}
	for _, addr := range dialed {
		host, port, err := SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("dialed unparseable address %q", addr)
		}
		if d := ev.Evaluate(host, port, policy.SchemeHTTPS); d != policy.Allow {
			return fmt.Errorf("dialed %q but policy says %v", addr, d)
		}
	}
	if tunnel {
		// The target on the request line is what must have been evaluated.
		fields := strings.Fields(strings.SplitN(string(raw), "\n", 2)[0])
		if len(fields) < 2 {
			return fmt.Errorf("200 for a request line with no target")
		}
		host, port, err := SplitHostPort(fields[1])
		if err != nil {
			return fmt.Errorf("200 for unparseable target %q", fields[1])
		}
		if d := ev.Evaluate(host, port, policy.SchemeHTTPS); d != policy.Allow {
			return fmt.Errorf("200 for %q but policy says %v", fields[1], d)
		}
	}
	return nil
}

// FuzzConnectRequest drives the CONNECT line and header parsing in handleConn
// with arbitrary bytes. Properties: no panic, and no tunnel or dial for a
// destination the policy denies, whatever the framing.
func FuzzConnectRequest(f *testing.F) {
	for _, s := range connectSeeds {
		f.Add([]byte(s.raw))
	}
	p, ev := newConnectFuzzProxy(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if err := checkConnectDecision(p, ev, raw); err != nil {
			t.Fatalf("%v\ninput: %q", err, raw)
		}
	})
}

// connectSeeds are the starting points the fuzzer mutates: well-formed requests,
// the malformed shapes handleConn must drop, and the CONNECT tricks from the
// red-team playbook (.agents/playbooks/red-team.md §2.2). The same inputs are
// committed under testdata/fuzz/FuzzConnectRequest so plain `go test` replays
// them, and TestConnectRequest_KnownBad pins the verdict for each.
type connectSeed struct {
	raw    string
	tunnel bool // the verdict: a tunnel opens only for these
}

var connectSeeds = []connectSeed{
	{raw: "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n", tunnel: true},
	{raw: "CONNECT a.wild.test:443 HTTP/1.1\r\n\r\n", tunnel: true},
	{raw: "CONNECT allowed.test:443 HTTP/1.1\nHost: x\n\n", tunnel: true},
	{raw: "CONNECT allowed.test:443\r\n\r\n"},
	{raw: "CONNECT allowed.test HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT :443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test:https HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test:0 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test:99999 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test:-443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test:443:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT ALLOWED.Test.:443 HTTP/1.1\r\n\r\n", tunnel: true},
	{raw: "CONNECT allowed.test..:443 HTTP/1.1\r\n\r\n", tunnel: true},
	{raw: "CONNECT denied.test:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT DENIED.test.:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT x.evil.test:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT wild.test:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT pinned.test:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT google.com@127.0.0.1:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test@127.0.0.1:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT 2130706433:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT 0177.0.0.1:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT 0x7f000001:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT [::1]:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT [::ffff:127.0.0.1]:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT metadata.google.internal:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test%2e:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test\x00.evil:443 HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT\tallowed.test:443\tHTTP/1.1\r\n\r\n"},
	{raw: "CONNECT  allowed.test:443  HTTP/1.1\r\n\r\n", tunnel: true},
	{raw: "CONNECT allowed.test:443 evil.test:443 HTTP/1.1\r\n\r\n", tunnel: true},
	{raw: "CONNECT evil.test:443 allowed.test:443 HTTP/1.1\r\n\r\n"},
	{raw: "connect allowed.test:443 HTTP/1.1\r\n\r\n"},
	{raw: "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n"},
	{raw: "POST / HTTP/1.1\r\n\r\n"},
	{raw: "CONNECT allowed.test:443 HTTP/1.1\r\nHost: evil.test\r\nContent-Length: 5\r\nContent-Length: 15\r\n\r\n", tunnel: true},
	{raw: "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443"},
	{raw: "CONNECT " + strings.Repeat("a", 4096) + ".test:443 HTTP/1.1\r\n\r\n"},
	{raw: ""},
	{raw: "\r\n\r\n"},
	{raw: "CONNECT "},
}

// TestConnectRequest_KnownBad pins the verdict for each seed: it passes the
// oracle, and only the seeds marked tunnel open one.
func TestConnectRequest_KnownBad(t *testing.T) {
	p, ev := newConnectFuzzProxy(t)
	for _, s := range connectSeeds {
		if err := checkConnectDecision(p, ev, []byte(s.raw)); err != nil {
			t.Errorf("%v\ninput: %q", err, s.raw)
			continue
		}
		var dialed []string
		resp := connectRun(p, []byte(s.raw), &dialed)
		if got := strings.Contains(resp, "200 Connection Established"); got != s.tunnel {
			t.Errorf("input %q: tunnel opened = %v, want %v (response %q)", s.raw, got, s.tunnel, resp)
		}
	}
}

// cappedStore is an analytics sink that keeps only the last cappedStoreMax
// events, so a long fuzz run does not grow memory without bound.
const cappedStoreMax = 64

type cappedStore struct {
	mu     sync.Mutex
	events [cappedStoreMax]analytics.Event
	n      int
}

func (s *cappedStore) StoreEvent(e analytics.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[s.n%cappedStoreMax] = e
	s.n++
	return nil
}

func (s *cappedStore) GetEvents(analytics.EventFilter) ([]analytics.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n < cappedStoreMax {
		return append([]analytics.Event(nil), s.events[:s.n]...), nil
	}
	return append([]analytics.Event(nil), s.events[:]...), nil
}

// sniHelloSeeds are the starting points the fuzzer mutates: well-formed hellos
// (whole, fragmented, extended), the missing-SNI shapes, and the bytes that must
// never become a gateable name — garbage, the plaintext h2 preface, truncations,
// and hostile server_names (control bytes, IP literals, over-limit labels).
var sniHelloSeeds = []string{
	string(tlsRecord(0x16, helloWithSNI("backend.test"))),
	string(append(tlsRecord(0x16, helloWithSNI("backend.test")), "\x16\x03\x01\x00\x05more"...)),
	string(tlsRecord(0x16, helloWithSNI("Backend.Test."))),
	string(splitRecord(helloWithSNI("backend.test"), 9)),
	string(tlsRecord(0x16, helloWithSNI(""))),
	// server_name extension with an empty list: no plaintext name (the ECH case).
	string(tlsRecord(0x16, helloWithSNI("", []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00}))),
	string(tlsRecord(0x16, helloWithSNI("x\r\ny.backend.test"))),
	string(tlsRecord(0x16, helloWithSNI("a\x00.backend.test"))),
	string(tlsRecord(0x16, helloWithSNI("a b.test"))),
	string(tlsRecord(0x16, helloWithSNI("192.0.2.10"))),
	string(tlsRecord(0x16, helloWithSNI(strings.Repeat("x", 9000)))),
	"NOT-TLS",
	"GET / HTTP/1.1\r\n\r\n",
	h2ClientPreface,
	h2ClientPreface[:len(h2ClientPreface)-5],
	string(tlsRecord(0x16, helloWithSNI("backend.test"))[:len(tlsRecord(0x16, helloWithSNI("backend.test")))-10]),
	string([]byte{0x16, 0x03}),
	string(tlsRecord(0x16, handshakeMsg(0x01, helloBody(nil, 3, 0x00, 0x13, 0x01)))),
	string(tlsRecord(0x16, nil)),
}

// FuzzSniffClientHello drives the ClientHello parser with arbitrary bytes.
// Properties: no panic; a parse error never carries a name; the recorded wire
// never exceeds the input or the hello budget; and whatever name comes out is
// either admitted by the LDH grammar as a normalised DNS name or rendered by
// safeSNI as a bounded, escaped string a deny event can carry.
func FuzzSniffClientHello(f *testing.F) {
	for _, s := range sniHelloSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		sni, wire, err := sniffClientHello(bufio.NewReader(bytes.NewReader(raw)), maxClientHelloBytes)
		if err != nil {
			if sni != "" {
				t.Fatalf("sniff error %v alongside a name %q", err, sni)
			}
			return
		}
		if len(wire) > len(raw) || len(wire) > maxClientHelloBytes {
			t.Fatalf("replay wire is %d bytes (input %d, budget %d)", len(wire), len(raw), maxClientHelloBytes)
		}
		if sni == "" {
			return // the missing-SNI case: nothing to gate on
		}
		name, ok := validateSNI(sni)
		if !ok {
			rendered := safeSNI(sni)
			if len(rendered) > 4*maxSNIDenyBytes+2 {
				t.Fatalf("safeSNI rendered %d bytes, want the 64-byte truncation bound", len(rendered))
			}
			if strings.ContainsRune(rendered, 0) || strings.ContainsAny(rendered, "\n\r") {
				t.Fatalf("safeSNI carried a raw control byte: %q", rendered)
			}
			return
		}
		if name != strings.ToLower(strings.TrimSuffix(sni, ".")) {
			t.Fatalf("admitted %q as %q: normalisation is not lower-case + one trailing dot", sni, name)
		}
		if len(name) > maxSNINameBytes || net.ParseIP(name) != nil {
			t.Fatalf("admitted %q: over-limit or an IP literal", name)
		}
		for _, label := range strings.Split(name, ".") {
			if !validLDHLabel(label) {
				t.Fatalf("admitted %q: label %q is not LDH", name, label)
			}
		}
	})
}
