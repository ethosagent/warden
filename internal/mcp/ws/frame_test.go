package ws

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// buildWireFrame hand-rolls a frame's wire bytes so tests do not depend on the
// codec they verify. payload is the UNMASKED logical payload; when mask != nil
// the wire payload is masked with it.
func buildWireFrame(fin bool, opcode byte, payload []byte, mask []byte) []byte {
	var buf bytes.Buffer
	b0 := opcode & 0x0F
	if fin {
		b0 |= 0x80
	}
	buf.WriteByte(b0)

	plen := len(payload)
	var b1 byte
	if mask != nil {
		b1 = 0x80
	}
	switch {
	case plen < 126:
		buf.WriteByte(b1 | byte(plen))
	case plen <= 0xFFFF:
		buf.WriteByte(b1 | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(plen))
		buf.Write(ext[:])
	default:
		buf.WriteByte(b1 | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(plen))
		buf.Write(ext[:])
	}

	if mask != nil {
		buf.Write(mask)
		masked := make([]byte, plen)
		for i := range payload {
			masked[i] = payload[i] ^ mask[i&3]
		}
		buf.Write(masked)
	} else {
		buf.Write(payload)
	}
	return buf.Bytes()
}

func TestReadFrame_LengthBoundaries(t *testing.T) {
	// Payload sizes spanning the 7-bit / 16-bit / 64-bit length encodings.
	sizes := []int{0, 1, 125, 126, 127, 65535, 65536, 70000}
	for _, masked := range []bool{false, true} {
		for _, sz := range sizes {
			payload := make([]byte, sz)
			for i := range payload {
				payload[i] = byte(i % 251)
			}
			var mask []byte
			if masked {
				mask = []byte{0xDE, 0xAD, 0xBE, 0xEF}
			}
			wire := buildWireFrame(true, OpcodeText, payload, mask)

			f, err := ReadFrame(bufio.NewReader(bytes.NewReader(wire)))
			if err != nil {
				t.Fatalf("masked=%v sz=%d: ReadFrame: %v", masked, sz, err)
			}
			if f.Masked != masked || f.Opcode != OpcodeText || !f.Fin {
				t.Fatalf("masked=%v sz=%d: header mismatch: %+v", masked, sz, f)
			}
			if !bytes.Equal(f.Payload, payload) {
				t.Fatalf("masked=%v sz=%d: unmasked payload mismatch", masked, sz)
			}

			// Write must reproduce the exact input wire bytes.
			var out bytes.Buffer
			if err := f.Write(&out); err != nil {
				t.Fatalf("masked=%v sz=%d: Write: %v", masked, sz, err)
			}
			if !bytes.Equal(out.Bytes(), wire) {
				t.Fatalf("masked=%v sz=%d: Write did not reproduce wire bytes", masked, sz)
			}
		}
	}
}

func TestWrite_DoesNotMutatePayload(t *testing.T) {
	payload := []byte(`{"jsonrpc":"2.0"}`)
	orig := append([]byte(nil), payload...)
	f := Frame{Fin: true, Opcode: OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: payload}
	var out bytes.Buffer
	if err := f.Write(&out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, orig) {
		t.Fatalf("Write mutated the decoded payload")
	}
}

func TestReadFrame_RSVBitsPreserved(t *testing.T) {
	// b0 = FIN + RSV1 + opcode text.
	wire := []byte{0x80 | 0x40 | OpcodeText, 0x01, 0x41}
	f, err := ReadFrame(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	if !f.RSV1 || f.RSV2 || f.RSV3 {
		t.Fatalf("RSV bits not preserved: %+v", f)
	}
	var out bytes.Buffer
	if err := f.Write(&out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), wire) {
		t.Fatalf("RSV round-trip mismatch: got %x want %x", out.Bytes(), wire)
	}
}

func TestReadFrame_Truncated(t *testing.T) {
	full := buildWireFrame(true, OpcodeText, bytes.Repeat([]byte("x"), 200), []byte{1, 2, 3, 4})
	for _, cut := range []int{0, 1, 2, 4, 8, len(full) - 1} {
		_, err := ReadFrame(bufio.NewReader(bytes.NewReader(full[:cut])))
		if err == nil {
			t.Fatalf("cut=%d: expected error on truncated input", cut)
		}
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			// Any non-nil error is acceptable, but it must be an error.
			t.Logf("cut=%d: err=%v", cut, err)
		}
	}
}

func TestReadFrame_OverCap(t *testing.T) {
	// Declare a 64-bit length above MaxFramePayload with no payload bytes; must
	// error without attempting to allocate/read the body.
	var wire bytes.Buffer
	wire.WriteByte(0x80 | OpcodeBinary)
	wire.WriteByte(127)
	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], MaxFramePayload+1)
	wire.Write(ext[:])

	_, err := ReadFrame(bufio.NewReader(bytes.NewReader(wire.Bytes())))
	if err == nil {
		t.Fatal("expected ErrFrameTooLarge")
	}
	if !isTooLarge(err) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func isTooLarge(err error) bool {
	for err != nil {
		if err == ErrFrameTooLarge {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestReadFrame_ControlFrames(t *testing.T) {
	for _, op := range []byte{OpcodeClose, OpcodePing, OpcodePong} {
		wire := buildWireFrame(true, op, []byte{0x03, 0xF0}, nil)
		f, err := ReadFrame(bufio.NewReader(bytes.NewReader(wire)))
		if err != nil {
			t.Fatalf("op=%x: %v", op, err)
		}
		if !f.IsControl() {
			t.Fatalf("op=%x: IsControl false", op)
		}
		var out bytes.Buffer
		if err := f.Write(&out); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), wire) {
			t.Fatalf("op=%x: control round-trip mismatch", op)
		}
	}
}

func TestCloseFrame(t *testing.T) {
	f := closeFrame(1008)
	if f.Opcode != OpcodeClose || !f.Fin || len(f.Payload) != 2 {
		t.Fatalf("unexpected close frame: %+v", f)
	}
	if binary.BigEndian.Uint16(f.Payload) != 1008 {
		t.Fatalf("close code mismatch")
	}
}
