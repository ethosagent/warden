package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// Tests for the transparent-mode ClientHello SNI sniff (#376): the parser must
// classify the first bytes on a :443 conn (valid hello with/without SNI,
// plaintext h2 preface, garbage, truncation, over-budget) and consume no more
// than the hello itself, so the bytes stay available for the TLS handshake.

// helloWithSNI builds a minimal TLS 1.2-shaped ClientHello handshake message
// with a server_name extension when sni != "", plus any raw extra extensions.
func helloWithSNI(sni string, extraExts ...[]byte) []byte {
	var exts []byte
	if sni != "" {
		exts = append(exts, serverNameExt(sni)...)
	}
	for _, e := range extraExts {
		exts = append(exts, e...)
	}
	body := []byte{0x03, 0x03}                  // legacy_version TLS 1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id: empty
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression_methods: null
	if len(exts) > 0 {
		body = append(body, byte(len(exts)>>8), byte(len(exts)))
		body = append(body, exts...)
	}
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

// serverNameExt builds the RFC 6066 server_name extension for one host_name.
func serverNameExt(sni string) []byte {
	name := []byte{0x00, byte(len(sni) >> 8), byte(len(sni))}
	name = append(name, sni...)
	list := []byte{byte(len(name) >> 8), byte(len(name))}
	list = append(list, name...)
	ext := []byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}
	return append(ext, list...)
}

// tlsRecord wraps payload in a TLS record of the given content type.
func tlsRecord(contentType byte, payload []byte) []byte {
	return append([]byte{contentType, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

// splitRecord splits payload across two TLS handshake records at off,
// exercising the fragmented-ClientHello path (Java-style hello fragmentation).
func splitRecord(payload []byte, off int) []byte {
	if off < 0 || off > len(payload) {
		off = len(payload) / 2
	}
	return append(tlsRecord(0x16, payload[:off]), tlsRecord(0x16, payload[off:])...)
}

// sniff runs sniffClientHello over the given bytes.
func sniff(t *testing.T, wire []byte, maxBytes int) (string, error) {
	t.Helper()
	sni, _, err := sniffClientHello(bufio.NewReader(bytes.NewReader(wire)), maxBytes)
	return sni, err
}

// readAllAvailable drains a bufio.Reader over an in-memory source.
func readAllAvailable(br *bufio.Reader) ([]byte, error) {
	return io.ReadAll(br)
}

func TestSniffClientHello_ValidSNI(t *testing.T) {
	wire := append(tlsRecord(0x16, helloWithSNI("backend.test")), 'X', 'Y', 'Z')
	sni, err := sniff(t, wire, maxClientHelloBytes)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if sni != "backend.test" {
		t.Errorf("sni = %q, want backend.test", sni)
	}
}

func TestSniffClientHello_ConsumesOnlyTheHello(t *testing.T) {
	// The TLS handshake that follows replays the buffered bytes: anything after
	// the hello must stay readable, and nothing before it may be lost.
	trailing := []byte("\x16\x03\x01\x00\x05more-bytes")
	wire := append(tlsRecord(0x16, helloWithSNI("backend.test")), trailing...)
	br := bufio.NewReader(bytes.NewReader(wire))
	sni, replay, err := sniffClientHello(br, maxClientHelloBytes)
	if err != nil || sni != "backend.test" {
		t.Fatalf("sniff = %q, %v", sni, err)
	}
	if !bytes.Equal(replay, wire[:len(wire)-len(trailing)]) {
		t.Errorf("replay wire is %d bytes, want the exact hello (%d)", len(replay), len(wire)-len(trailing))
	}
	rest, err := readAllAvailable(br)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != string(trailing) {
		t.Errorf("bytes after the hello = %q, want %q", rest, trailing)
	}
}

func TestSniffClientHello_WholeHelloConsumedWithExtensionsAfterServerName(t *testing.T) {
	// Real clients send many extensions after server_name. The WHOLE hello must
	// be consumed, and the returned wire must be EXACTLY the hello bytes: the
	// handler replays wire + buffered remainder + conn into the TLS handshake,
	// so a dropped or duplicated byte breaks the handshake.
	ecPointFormats := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00} // type, len 2, uncompressed
	trailing := []byte("\x16\x03\x03\x00\x04more")
	hello := helloWithSNI("backend.test", serverNameExt("second.test"), ecPointFormats)
	wire := append(tlsRecord(0x16, hello), trailing...)
	br := bufio.NewReader(bytes.NewReader(wire))
	sni, got, err := sniffClientHello(br, maxClientHelloBytes)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if sni != "backend.test" {
		t.Errorf("sni = %q, want backend.test (first type-0 entry wins)", sni)
	}
	if !bytes.Equal(got, tlsRecord(0x16, hello)) {
		t.Errorf("replay wire is %d bytes, want the exact %d-byte hello", len(got), len(hello)+5)
	}
	rest, err := readAllAvailable(br)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != string(trailing) {
		t.Errorf("bytes after the hello = %q, want %q", rest, trailing)
	}
}

func TestSniffClientHello_NoSNIExtension(t *testing.T) {
	sni, err := sniff(t, tlsRecord(0x16, helloWithSNI("")), maxClientHelloBytes)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if sni != "" {
		t.Errorf("sni = %q, want empty", sni)
	}
}

func TestSniffClientHello_ServerNameWithoutHostnameEntry(t *testing.T) {
	// A server_name extension whose list carries no type-0 entry: still a
	// readable hello, but no SNI — the missing-SNI case, not a parse failure.
	ext := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00} // type 0, len 2, empty list
	sni, err := sniff(t, tlsRecord(0x16, helloWithSNI("", ext)), maxClientHelloBytes)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if sni != "" {
		t.Errorf("sni = %q, want empty", sni)
	}
}

func TestSniffClientHello_NameKeptVerbatim(t *testing.T) {
	// Case and trailing dots are returned as sent; normalization (and the
	// deny/rename decision) is the caller's job, not the parser's.
	sni, err := sniff(t, tlsRecord(0x16, helloWithSNI("Backend.Test.")), maxClientHelloBytes)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if sni != "Backend.Test." {
		t.Errorf("sni = %q, want Backend.Test.", sni)
	}
}

func TestSniffClientHello_FragmentedHello(t *testing.T) {
	// A hello fragmented across two records (Java clients do this) must parse.
	hello := helloWithSNI("backend.test")
	sni, err := sniff(t, splitRecord(hello, 9), maxClientHelloBytes)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if sni != "backend.test" {
		t.Errorf("sni = %q, want backend.test", sni)
	}
}

func TestSniffClientHello_Garbage(t *testing.T) {
	sni, err := sniff(t, []byte("GET / HTTP/1.1\r\n\r\n"), maxClientHelloBytes)
	if !errors.Is(err, errNotTLSRecord) {
		t.Errorf("err = %v, want errNotTLSRecord", err)
	}
	if sni != "" {
		t.Errorf("sni = %q, want empty", sni)
	}
}

func TestSniffClientHello_H2PriorKnowledge(t *testing.T) {
	_, err := sniff(t, []byte(h2ClientPreface), maxClientHelloBytes)
	if !errors.Is(err, errH2PriorKnowledge) {
		t.Errorf("err = %v, want errH2PriorKnowledge", err)
	}
}

func TestSniffClientHello_H2PrefaceTruncated(t *testing.T) {
	// A connection that starts with the preface but dies mid-way is still the
	// h2 prior-knowledge case (it can never be a TLS hello).
	partial := h2ClientPreface[:len(h2ClientPreface)-5]
	_, err := sniff(t, []byte(partial), maxClientHelloBytes)
	if !errors.Is(err, errH2PriorKnowledge) {
		t.Errorf("err = %v, want errH2PriorKnowledge", err)
	}
}

func TestSniffClientHello_TruncatedHello(t *testing.T) {
	// Record header promises more bytes than were sent: the client went away
	// (or stalled) mid-hello — the truncation case, dropped silently.
	full := tlsRecord(0x16, helloWithSNI("backend.test"))
	truncated := full[:len(full)-10]
	_, err := sniff(t, truncated, maxClientHelloBytes)
	if !errors.Is(err, errHelloTruncated) {
		t.Errorf("err = %v, want errHelloTruncated", err)
	}
}

func TestSniffClientHello_TruncatedAfterHeader(t *testing.T) {
	// Only a partial record header arrived.
	_, err := sniff(t, []byte{0x16, 0x03}, maxClientHelloBytes)
	if !errors.Is(err, errHelloTruncated) {
		t.Errorf("err = %v, want errHelloTruncated", err)
	}
}

func TestSniffClientHello_TooLarge(t *testing.T) {
	full := tlsRecord(0x16, helloWithSNI("backend.test"))

	// A tight budget must reject a hello that would not fit, even though the
	// bytes themselves are a perfectly valid hello.
	if _, err := sniff(t, full, 32); !errors.Is(err, errHelloTooLarge) {
		t.Errorf("tight budget: err = %v, want errHelloTooLarge", err)
	}
	// A record whose declared length exceeds the budget is rejected before any
	// of it is read.
	big := tlsRecord(0x16, make([]byte, 15000))
	if _, err := sniff(t, big, 4096); !errors.Is(err, errHelloTooLarge) {
		t.Errorf("big record: err = %v, want errHelloTooLarge", err)
	}
}

// helloBody assembles a ClientHello body from raw pieces, so malformed-shape
// tests can inject wrong lengths without mid-literal spreads.
func helloBody(sessionID []byte, cipherLen int, extra ...byte) []byte {
	body := []byte{0x03, 0x03}               // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = append(body, byte(cipherLen>>8), byte(cipherLen))
	body = append(body, 0x01, 0x00) // compression_methods: null
	return append(body, extra...)
}

func handshakeMsg(typ byte, body []byte) []byte {
	hs := []byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func TestSniffClientHello_Malformed(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
	}{
		{
			name: "empty record",
			wire: tlsRecord(0x16, nil),
		},
		{
			name: "not a handshake message",
			// Handshake type 0x02 (ServerHello) on a client-facing port.
			wire: tlsRecord(0x16, []byte{0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00}),
		},
		{
			name: "session_id overruns the record",
			wire: tlsRecord(0x16, handshakeMsg(0x01, []byte{
				0x03, 0x03, // legacy_version
				0xff, // session_id len 255, but no bytes follow
			})),
		},
		{
			name: "odd cipher_suites length",
			wire: tlsRecord(0x16, handshakeMsg(0x01, helloBody(nil, 3, 0x00, 0x13, 0x01))),
		},
		{
			name: "extensions length disagrees with the message",
			// Extensions length 65535 while zero bytes remain in the message.
			wire: tlsRecord(0x16, handshakeMsg(0x01, helloBody(nil, 2, 0xff, 0xff))),
		},
		{
			name: "extension overruns the extensions block",
			// Extensions block of 4 bytes holding one ext claiming length 65535.
			wire: tlsRecord(0x16, handshakeMsg(0x01, helloBody(nil, 2,
				0x00, 0x04, // extensions length 4
				0x00, 0x00, 0xff, 0xff, // ext type server_name, len 65535
			))),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sni, err := sniff(t, tc.wire, maxClientHelloBytes)
			if !errors.Is(err, errHelloMalformed) {
				t.Errorf("err = %v, want errHelloMalformed", err)
			}
			if sni != "" {
				t.Errorf("sni = %q, want empty", sni)
			}
		})
	}
}

func TestSniffClientHello_EmptyConn(t *testing.T) {
	// Nothing at all before EOF: no hello ever arrived, nothing was gated.
	sni, err := sniff(t, nil, maxClientHelloBytes)
	if !errors.Is(err, errHelloTruncated) {
		t.Errorf("err = %v, want errHelloTruncated", err)
	}
	if sni != "" {
		t.Errorf("sni = %q, want empty", sni)
	}
}

// repeatLDH builds "a.b.c.d" from labels of the given lengths, for the
// total-length boundary rows.
func repeatLDH(lens ...int) string {
	parts := make([]string, len(lens))
	for i, n := range lens {
		parts[i] = strings.Repeat(string(rune('a'+i)), n)
	}
	return strings.Join(parts, ".")
}

// TestValidateSNIHost pins the SNI admission grammar (#376 review): the sniffed
// server_name is client-chosen bytes on an unauthenticated port, so only a
// plain LDH DNS name may reach policy and the leaf minter — lower-cased, one
// optional trailing dot removed, labels 1..63 bytes, total at most 253, no
// empty label, no underscore, no control bytes, and never an IP literal. A
// single-label name passes the grammar (policy still has to allow it).
func TestValidateSNIHost(t *testing.T) {
	tests := []struct {
		name string
		sni  string
		want string // "" = refuse
	}{
		{name: "plain", sni: "backend.test", want: "backend.test"},
		{name: "lower-cased", sni: "Backend.Test", want: "backend.test"},
		{name: "one trailing dot removed", sni: "backend.test.", want: "backend.test"},
		{name: "lower-cased with trailing dot", sni: "BACKEND.Test.", want: "backend.test"},
		{name: "single label", sni: "backend", want: "backend"},
		{name: "inner hyphen", sni: "a-b.cd-ef", want: "a-b.cd-ef"},
		{name: "digits", sni: "host1.test2", want: "host1.test2"},
		{name: "63-byte label", sni: repeatLDH(63, 3), want: repeatLDH(63, 3)},
		{name: "253 bytes total", sni: repeatLDH(63, 63, 63, 61), want: repeatLDH(63, 63, 63, 61)},
		{name: "64-byte label", sni: repeatLDH(64, 3)},
		{name: "254 bytes total", sni: repeatLDH(63, 63, 63, 62)},
		{name: "empty", sni: ""},
		{name: "only a dot", sni: "."},
		{name: "second trailing dot is an empty label", sni: "backend.test.."},
		{name: "empty middle label", sni: "backend..test"},
		{name: "leading hyphen", sni: "-backend.test"},
		{name: "trailing hyphen", sni: "backend-.test"},
		{name: "underscore", sni: "under_score.test"},
		{name: "space", sni: "a b.test"},
		{name: "at sign", sni: "x@y.test"},
		{name: "NUL byte", sni: "a\x00.test"},
		{name: "CRLF", sni: "x\r\ny.test"},
		{name: "non-ASCII", sni: "alïce.test"},
		{name: "IPv4 literal", sni: "10.0.0.1"},
		{name: "loopback v4 literal", sni: "127.0.0.1"},
		{name: "IPv6 literal", sni: "::1"},
		{name: "full IPv6 literal", sni: "2001:db8::1"},
		{name: "obfuscated decimal v4 is one long label", sni: strings.Repeat("2", 64)},
		{name: "9000-byte label", sni: strings.Repeat("x", 9000)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := validateSNI(tc.sni)
			if tc.want == "" {
				if ok {
					t.Errorf("validateSNI(%q) = (%q, true), want refusal", tc.sni, got)
				}
				return
			}
			if !ok || got != tc.want {
				t.Errorf("validateSNI(%q) = (%q, %v), want (%q, true)", tc.sni, got, ok, tc.want)
			}
		})
	}
}

// TestSafeSNI pins the deny-event rendering of a refused server_name: bounded
// and %q-escaped, so raw control bytes never ride an event (analytics hygiene)
// while an operator can still tell what was refused.
func TestSafeSNI(t *testing.T) {
	if got := safeSNI("x\r\ny"); got != `"x\r\ny"` {
		t.Errorf("safeSNI control bytes = %s, want the escaped form", got)
	}
	if got := safeSNI("ok.test"); got != `"ok.test"` {
		t.Errorf("safeSNI plain name = %s, want the quoted name", got)
	}
	long := strings.Repeat("a", 9000) + "\x00"
	got := safeSNI(long)
	if len(got) > 4*maxSNIDenyBytes+2 {
		t.Errorf("safeSNI rendered %d bytes, want it bounded by the 64-byte truncation", len(got))
	}
	if strings.ContainsRune(got, 0) || strings.ContainsAny(got, "\n\r") {
		t.Errorf("safeSNI carried a raw control byte: %q", got)
	}
	if !strings.HasPrefix(got, `"aaaa`) {
		t.Errorf("safeSNI lost the name's head: %q", got)
	}
}

func TestSniffClientHello_MultipleSNINames(t *testing.T) {
	// RFC 6066 allows one host_name; if a client sends a second entry anyway,
	// the first type-0 name wins.
	entry := func(host string) []byte {
		e := []byte{0x00, byte(len(host) >> 8), byte(len(host))}
		return append(e, host...)
	}
	e1, e2 := entry("backend.test"), entry("second.host!")
	list := []byte{byte((len(e1) + len(e2)) >> 8), byte(len(e1) + len(e2))}
	list = append(list, e1...)
	list = append(list, e2...)
	ext := []byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}
	ext = append(ext, list...)
	sni, err := sniff(t, tlsRecord(0x16, helloWithSNI("", ext)), maxClientHelloBytes)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if sni != "backend.test" {
		t.Errorf("sni = %q, want backend.test", sni)
	}
}
