// Package ws implements a minimal, stdlib-only RFC 6455 WebSocket framing codec
// and a bidirectional "pump" used by the proxy to scan MCP JSON-RPC traffic that
// rides over a WebSocket upgrade.
//
// The codec is deliberately small: it reads one frame at a time, unmasks the
// payload on read, and re-serializes a frame byte-identically (re-masking with
// the same key) so the pump can forward frames transparently while still
// inspecting their decoded JSON-RPC payloads. It has zero external dependencies.
package ws

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// WebSocket opcodes (RFC 6455 §5.2).
const (
	OpcodeContinuation byte = 0x0
	OpcodeText         byte = 0x1
	OpcodeBinary       byte = 0x2
	OpcodeClose        byte = 0x8
	OpcodePing         byte = 0x9
	OpcodePong         byte = 0xA
)

// MaxFramePayload bounds a single frame's payload so a hostile (or buggy) peer
// cannot force an unbounded allocation. Frames declaring a larger length error.
const MaxFramePayload = 16 << 20 // 16 MiB

// ErrFrameTooLarge is returned by ReadFrame when a frame's declared payload
// length exceeds MaxFramePayload.
var ErrFrameTooLarge = errors.New("ws: frame payload exceeds maximum")

// Frame is one decoded WebSocket frame. Payload is always stored UNMASKED; on
// Write the payload is re-masked with MaskKey when Masked is true, reproducing
// the exact wire bytes that were read.
type Frame struct {
	Fin     bool
	RSV1    bool
	RSV2    bool
	RSV3    bool
	Opcode  byte
	Masked  bool
	MaskKey [4]byte
	Payload []byte // UNMASKED payload
}

// IsControl reports whether the frame is a control frame (close/ping/pong).
func (f Frame) IsControl() bool {
	return f.Opcode&0x8 != 0
}

// ReadFrame reads exactly one WebSocket frame from r, unmasking the payload when
// the MASK bit is set. The returned Frame's Payload is freshly allocated and
// owned by the caller. RSV bits are preserved so Write can reproduce the input.
func ReadFrame(r *bufio.Reader) (Frame, error) {
	var f Frame

	b0, err := r.ReadByte()
	if err != nil {
		return f, err
	}
	b1, err := r.ReadByte()
	if err != nil {
		return f, err
	}

	f.Fin = b0&0x80 != 0
	f.RSV1 = b0&0x40 != 0
	f.RSV2 = b0&0x20 != 0
	f.RSV3 = b0&0x10 != 0
	f.Opcode = b0 & 0x0F

	f.Masked = b1&0x80 != 0
	length := uint64(b1 & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return f, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return f, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	if length > MaxFramePayload {
		return f, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, length)
	}

	if f.Masked {
		if _, err := io.ReadFull(r, f.MaskKey[:]); err != nil {
			return f, err
		}
	}

	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return f, err
		}
		if f.Masked {
			maskInPlace(f.Payload, f.MaskKey)
		}
	}

	return f, nil
}

// Write serializes the frame to w. When Masked is true the payload is re-masked
// with MaskKey, so for a frame produced by ReadFrame this reproduces the exact
// input bytes. The payload is masked into a local copy so f.Payload (the decoded
// JSON-RPC the pump inspects) is never mutated.
func (f Frame) Write(w io.Writer) error {
	plen := len(f.Payload)
	if uint64(plen) > MaxFramePayload {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, plen)
	}

	// Header: 2 bytes + up to 8 bytes extended length + up to 4 bytes mask key.
	var header [14]byte
	header[0] = f.Opcode & 0x0F
	if f.Fin {
		header[0] |= 0x80
	}
	if f.RSV1 {
		header[0] |= 0x40
	}
	if f.RSV2 {
		header[0] |= 0x20
	}
	if f.RSV3 {
		header[0] |= 0x10
	}

	n := 2
	switch {
	case plen < 126:
		header[1] = byte(plen)
	case plen <= 0xFFFF:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(plen))
		n = 4
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(plen))
		n = 10
	}

	if f.Masked {
		header[1] |= 0x80
		copy(header[n:n+4], f.MaskKey[:])
		n += 4
	}

	if _, err := w.Write(header[:n]); err != nil {
		return err
	}
	if plen == 0 {
		return nil
	}

	if !f.Masked {
		_, err := w.Write(f.Payload)
		return err
	}

	// Mask into a copy so the caller's decoded payload is untouched.
	masked := make([]byte, plen)
	copy(masked, f.Payload)
	maskInPlace(masked, f.MaskKey)
	_, err := w.Write(masked)
	return err
}

// maskInPlace XORs payload with the 4-byte key (RFC 6455 §5.3). XOR is its own
// inverse, so the same call both masks and unmasks.
func maskInPlace(payload []byte, key [4]byte) {
	for i := range payload {
		payload[i] ^= key[i&3]
	}
}

// closeFrame builds an unmasked Close control frame carrying the given status
// code (RFC 6455 §5.5.1 / §7.4). It is used to signal a policy violation (1008).
func closeFrame(code uint16) Frame {
	var payload [2]byte
	binary.BigEndian.PutUint16(payload[:], code)
	return Frame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Payload: payload[:],
	}
}
