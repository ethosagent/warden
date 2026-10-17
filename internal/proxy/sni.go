package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
)

// The transparent :443 listener sees raw TCP, so the ClientHello IS the
// admission ticket (#376): its server_name decides policy before any TLS
// handshake happens. sniffClientHello parses it incrementally — never
// buffering a whole record that declared a huge length — and classifies
// everything a hostile or confused client can put on the wire:
//
//   - a readable hello with a server_name  → (sni, nil)
//   - a readable hello without one (incl. ECH, whose outer hello carries no
//     plaintext server_name)               → ("", nil) — the missing-SNI case
//   - the plaintext HTTP/2 prior-knowledge preface → errH2PriorKnowledge
//   - bytes that are not TLS at all        → errNotTLSRecord
//   - a well-formed-looking hello whose lengths lie → errHelloMalformed
//   - a hello over the byte budget         → errHelloTooLarge
//   - EOF/timeout before the hello finished → errHelloTruncated
//
// Parse failures and over-budget hellos are audit-worthy (deny +
// transparent_bad_client_hello); a truncated hello mirrors the CONNECT floor's
// silent drop for a client that vanished before its preamble (nothing was
// gated), and the handler maps the other errors to their declared reasons.
var (
	errH2PriorKnowledge = errors.New("proxy: plaintext HTTP/2 preface on a TLS listener")
	errNotTLSRecord     = errors.New("proxy: not a TLS handshake record")
	errHelloMalformed   = errors.New("proxy: malformed TLS ClientHello")
	errHelloTooLarge    = errors.New("proxy: TLS ClientHello over the byte budget")
	errHelloTruncated   = errors.New("proxy: TLS ClientHello truncated before completion")
)

// maxClientHelloBytes caps how many bytes a ClientHello may occupy on the wire.
// It is the same order as the CONNECT preamble budget: a knob would let a
// misconfiguration re-open the unbounded-read hole the CONNECT floor closes.
const maxClientHelloBytes = 64 << 10 // 64 KiB

// maxTLSRecordBytes is the RFC 5246 TLSPlaintext.length cap; a record claiming
// more is not TLS.
const maxTLSRecordBytes = 1 << 14

// The SNI admission grammar (#376 review). The sniffed server_name is
// client-chosen bytes on an unauthenticated port: before anything evaluates
// policy on it — and before any certificate is minted for it — it must be a
// plain LDH DNS name. The caps are the RFC 1035 wire limits, held as constants
// on purpose like the hello/preamble budgets: a knob would let a
// misconfiguration re-open the unbounded-growth hole (see maxCertCacheEntries).
const (
	// maxSNINameBytes caps a fully-qualified name (RFC 1035 §2.3.4: 255 octets
	// on the wire, 253 in its textual presentation form).
	maxSNINameBytes = 253
	// maxSNILabelBytes caps one label (RFC 1035 §2.3.1).
	maxSNILabelBytes = 63
	// maxSNIDenyBytes caps how much of a REFUSED name a deny event carries;
	// safeSNI %q-escapes it, so the rendered form stays bounded at 4x.
	maxSNIDenyBytes = 64
)

// validateSNI admits the sniffed server_name only as a plain LDH DNS name and
// returns its normalised form: lower-cased, one optional trailing dot removed.
// Each label must be 1..maxSNILabelBytes bytes of letters/digits/hyphen with no
// leading or trailing hyphen, the whole name at most maxSNINameBytes bytes, and
// an IP literal (v4 or v6) is never a name — a numeric SNI is a dial target,
// not a hostname, and policy matches hostnames. A single-label name passes the
// grammar; whether it is ALLOWED stays entirely policy's decision. ok=false
// means refuse with transparent_bad_client_hello — never evaluate policy, never
// mint a certificate for the string.
func validateSNI(sni string) (string, bool) {
	name := strings.ToLower(sni)
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > maxSNINameBytes {
		return "", false
	}
	// After the LDH check below an IPv6 literal is already impossible (a colon
	// is not LDH); the parse catches the dotted v4 forms, which are pure LDH.
	if net.ParseIP(name) != nil {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if !validLDHLabel(label) {
			return "", false
		}
	}
	return name, true
}

// validLDHLabel reports whether label is one LDH label: 1..maxSNILabelBytes
// bytes of ASCII letters, digits or hyphen, with no leading or trailing hyphen.
func validLDHLabel(label string) bool {
	if len(label) == 0 || len(label) > maxSNILabelBytes {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false // anything else — space, NUL, underscore, UTF-8, ':' …
	}
	return true
}

// safeSNI renders a server_name that failed validation for a deny event's
// Domain: truncated to its first maxSNIDenyBytes bytes and %q-escaped, so raw
// control bytes never ride an event while an operator can still tell what was
// refused. The normalised, validated name rides events everywhere else.
func safeSNI(sni string) string {
	if len(sni) > maxSNIDenyBytes {
		sni = sni[:maxSNIDenyBytes]
	}
	return fmt.Sprintf("%q", sni)
}

// h2ClientPreface is the exact 24-byte HTTP/2 connection preface (RFC 9113).
const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// sniffClientHello reads the first ClientHello from br and returns its
// server_name together with every byte it consumed. The consumed wire is the
// caller's replay source: the TLS handshake that follows must see the hello
// again, and the bytes are already off the socket, so the handler re-serves
// them (plus whatever stayed buffered in br, plus the conn) into the
// handshake. maxBytes bounds the hello; see the classification comment above
// for the error taxonomy.
func sniffClientHello(br *bufio.Reader, maxBytes int) (string, []byte, error) {
	h := &helloParser{br: br, maxLeft: maxBytes}
	sni, err := h.parse()
	return sni, h.wire, err
}

// parse walks the hello (see sniffClientHello). It is split from the exported
// entry so the parser can own the recording buffer without the callers seeing
// it.
func (h *helloParser) parse() (string, error) {
	b0, err := h.br.ReadByte()
	if err != nil {
		// The client said nothing (or the deadline passed): nothing was gated.
		return "", fmt.Errorf("%w", errHelloTruncated)
	}
	h.record(b0)
	if b0 != 0x16 {
		return "", classifyNonTLS(b0, h.br)
	}

	// Finish the first record header: version(2) + length(2); the type byte is
	// already consumed. The version is not validated — legal ClientHellos
	// legitimately vary their legacy_version.
	if _, err := h.rawByte(); err != nil {
		return "", err
	}
	if _, err := h.rawByte(); err != nil {
		return "", err
	}
	hi, err := h.rawByte()
	if err != nil {
		return "", err
	}
	lo, err := h.rawByte()
	if err != nil {
		return "", err
	}
	recLen := int(hi)<<8 | int(lo)
	if recLen == 0 || recLen > maxTLSRecordBytes {
		return "", fmt.Errorf("%w: record length %d", errHelloMalformed, recLen)
	}
	if recLen > h.maxLeft {
		return "", fmt.Errorf("%w: record length %d over budget", errHelloTooLarge, recLen)
	}
	h.recLeft = recLen

	// Handshake header inside the record: type(1) + length(3). Only a
	// ClientHello (0x01) is meaningful on this port.
	ht, err := h.rawByte()
	if err != nil {
		return "", err
	}
	if ht != 0x01 {
		return "", fmt.Errorf("%w: handshake type %#x", errHelloMalformed, ht)
	}
	m0, err := h.rawByte()
	if err != nil {
		return "", err
	}
	m1, err := h.rawByte()
	if err != nil {
		return "", err
	}
	m2, err := h.rawByte()
	if err != nil {
		return "", err
	}
	hsLen := int(m0)<<16 | int(m1)<<8 | int(m2)
	if hsLen == 0 {
		return "", fmt.Errorf("%w: empty handshake message", errHelloMalformed)
	}
	h.hsLeft = hsLen
	// The handshake header came OUT of this record: the remaining record
	// payload is recLen minus the 4 header bytes just consumed.
	h.recLeft -= 4

	// ClientHello body: version(2) random(32) session_id cipher_suites
	// compression_methods [extensions].
	if err := h.skip(34); err != nil {
		return "", err
	}
	sidLen, err := h.u8()
	if err != nil {
		return "", err
	}
	if err := h.skip(sidLen); err != nil {
		return "", err
	}
	csHi, err := h.u8()
	if err != nil {
		return "", err
	}
	csLo, err := h.u8()
	if err != nil {
		return "", err
	}
	csLen := int(csHi)<<8 | int(csLo)
	if csLen%2 != 0 {
		return "", fmt.Errorf("%w: cipher_suites length %d is odd", errHelloMalformed, csLen)
	}
	if err := h.skip(csLen); err != nil {
		return "", err
	}
	compLen, err := h.u8()
	if err != nil {
		return "", err
	}
	if compLen == 0 {
		return "", fmt.Errorf("%w: empty compression_methods", errHelloMalformed)
	}
	if err := h.skip(compLen); err != nil {
		return "", err
	}

	// Extensions, if the message carries any. The block must fill exactly the
	// rest of the message. The WHOLE hello is walked even after the name is
	// found — a byte left unconsumed would surface as the TLS handshake's
	// first record.
	var sni string
	if h.hsLeft > 0 {
		if h.hsLeft < 2 {
			return "", fmt.Errorf("%w: truncated extensions length", errHelloMalformed)
		}
		bodyLeft := h.hsLeft
		eHi, err := h.u8()
		if err != nil {
			return "", err
		}
		eLo, err := h.u8()
		if err != nil {
			return "", err
		}
		extTotal := int(eHi)<<8 | int(eLo)
		if extTotal != bodyLeft-2 {
			return "", fmt.Errorf("%w: extensions length %d != remaining %d", errHelloMalformed, extTotal, bodyLeft-2)
		}
		for extTotal > 0 {
			if extTotal < 4 {
				return "", fmt.Errorf("%w: extension header overruns the block", errHelloMalformed)
			}
			tHi, err := h.u8()
			if err != nil {
				return "", err
			}
			tLo, err := h.u8()
			if err != nil {
				return "", err
			}
			lHi, err := h.u8()
			if err != nil {
				return "", err
			}
			lLo, err := h.u8()
			if err != nil {
				return "", err
			}
			extTotal -= 4
			extLen := int(lHi)<<8 | int(lLo)
			if extLen > extTotal {
				return "", fmt.Errorf("%w: extension length %d overruns the block", errHelloMalformed, extLen)
			}
			extTotal -= extLen
			if tHi == 0 && tLo == 0 && sni == "" {
				// The first type-0 entry wins; the walk continues so no byte
				// of the hello stays buffered for the handshake to trip on.
				name, err := parseServerName(h, extLen)
				if err != nil {
					return "", err
				}
				sni = name
				continue
			}
			if err := h.skip(extLen); err != nil {
				return "", err
			}
		}
	}
	// sni is the extracted name, "" when the hello carried none (missing-SNI).
	return sni, nil
}

// classifyNonTLS decides what a first byte that is not a handshake record
// means: the plaintext h2 prior-knowledge preface (its own declared reason), a
// mid-preface truncation (still recognizable once "PRI" matched), or bytes
// that are simply not TLS.
func classifyNonTLS(b0 byte, br *bufio.Reader) error {
	if b0 != h2ClientPreface[0] {
		return errNotTLSRecord
	}
	matched := 1
	for matched < len(h2ClientPreface) {
		b, err := br.ReadByte()
		if err != nil {
			if matched >= 3 {
				// "PRI" matched and the conn died: it began with the preface.
				return errH2PriorKnowledge
			}
			return errHelloTruncated
		}
		if b != h2ClientPreface[matched] {
			return errNotTLSRecord
		}
		matched++
	}
	return errH2PriorKnowledge
}

// parseServerName parses the RFC 6066 server_name extension body (extLen bytes
// of it, already length-checked) to its END — the first type-0 host_name wins,
// and every later byte of the list is still consumed, because the TLS handshake
// that follows replays the reader and cannot be handed mid-extension bytes. A
// list with no type-0 entry yields the missing-SNI case, not a parse failure.
func parseServerName(h *helloParser, extLen int) (string, error) {
	if extLen < 2 {
		return "", fmt.Errorf("%w: server_name list length %d", errHelloMalformed, extLen)
	}
	lHi, err := h.u8()
	if err != nil {
		return "", err
	}
	lLo, err := h.u8()
	if err != nil {
		return "", err
	}
	listLen := int(lHi)<<8 | int(lLo)
	if listLen != extLen-2 {
		return "", fmt.Errorf("%w: server_name list length %d != extension body %d", errHelloMalformed, listLen, extLen-2)
	}
	var first string
	for listLen > 0 {
		if listLen < 3 {
			return "", fmt.Errorf("%w: server_name entry overruns the list", errHelloMalformed)
		}
		nameType, err := h.u8()
		if err != nil {
			return "", err
		}
		nHi, err := h.u8()
		if err != nil {
			return "", err
		}
		nLo, err := h.u8()
		if err != nil {
			return "", err
		}
		nameLen := int(nHi)<<8 | int(nLo)
		if nameLen+3 > listLen {
			return "", fmt.Errorf("%w: host_name length %d overruns the list", errHelloMalformed, nameLen)
		}
		listLen -= 3 + nameLen
		if nameType != 0 || first != "" {
			if err := h.skip(nameLen); err != nil {
				return "", err
			}
			continue
		}
		name := make([]byte, nameLen)
		for i := range name {
			name[i], err = h.nextByte()
			if err != nil {
				return "", err
			}
		}
		first = string(name)
	}
	return first, nil
}

// helloParser walks a (possibly record-fragmented) ClientHello, counting every
// consumed byte against one budget AND recording every consumed byte, so the
// caller can replay the hello to the TLS handshake (the bytes are already off
// the socket). nextByte walks handshake-message bytes and crosses record
// boundaries when a hello is fragmented; rawByte reads framing bytes
// (record/handshake headers) directly.
type helloParser struct {
	br      *bufio.Reader
	maxLeft int    // whole-parse byte budget
	recLeft int    // bytes left in the current TLS record
	hsLeft  int    // bytes left in the handshake message
	wire    []byte // every byte consumed from br, for replay
}

func (h *helloParser) record(b byte) { h.wire = append(h.wire, b) }

// rawByte consumes one framing byte against the budget alone.
func (h *helloParser) rawByte() (byte, error) {
	b, err := h.br.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("%w", errHelloTruncated)
	}
	h.record(b)
	h.maxLeft--
	if h.maxLeft < 0 {
		return 0, fmt.Errorf("%w", errHelloTooLarge)
	}
	return b, nil
}

// nextRecord starts the next fragment of a fragmented handshake message. Only
// handshake records carry hello fragments; anything else mid-message is not a
// ClientHello we can gate.
func (h *helloParser) nextRecord() error {
	hi, err := h.rawByte()
	if err != nil {
		return err
	}
	if hi != 0x16 {
		return fmt.Errorf("%w: record type %#x mid-hello", errHelloMalformed, hi)
	}
	if _, err := h.rawByte(); err != nil {
		return err
	}
	if _, err := h.rawByte(); err != nil {
		return err
	}
	lHi, err := h.rawByte()
	if err != nil {
		return err
	}
	lLo, err := h.rawByte()
	if err != nil {
		return err
	}
	recLen := int(lHi)<<8 | int(lLo)
	if recLen == 0 || recLen > maxTLSRecordBytes {
		return fmt.Errorf("%w: record length %d", errHelloMalformed, recLen)
	}
	if recLen > h.maxLeft {
		return fmt.Errorf("%w: record length %d over budget", errHelloTooLarge, recLen)
	}
	h.recLeft = recLen
	return nil
}

// nextByte consumes one handshake-message byte, crossing a record boundary when
// the hello is fragmented. All three failure shapes are distinguished: a
// message overrunning its declared length is malformed; the wire ending (or the
// deadline firing) first is truncated; the budget running out is too large.
func (h *helloParser) nextByte() (byte, error) {
	if h.hsLeft == 0 {
		return 0, fmt.Errorf("%w: message overruns its length", errHelloMalformed)
	}
	if h.recLeft == 0 {
		if err := h.nextRecord(); err != nil {
			return 0, err
		}
	}
	b, err := h.br.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("%w", errHelloTruncated)
	}
	h.record(b)
	h.maxLeft--
	if h.maxLeft < 0 {
		return 0, fmt.Errorf("%w", errHelloTooLarge)
	}
	h.recLeft--
	h.hsLeft--
	return b, nil
}

func (h *helloParser) u8() (int, error) {
	b, err := h.nextByte()
	if err != nil {
		return 0, err
	}
	return int(b), nil
}

// skip consumes n message bytes without retaining them.
func (h *helloParser) skip(n int) error {
	for i := 0; i < n; i++ {
		if _, err := h.nextByte(); err != nil {
			return err
		}
	}
	return nil
}
