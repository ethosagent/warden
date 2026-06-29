// Package sse implements a minimal, streaming Server-Sent Events (SSE) parser
// used by the proxy to scan MCP "Streamable HTTP" responses event-by-event
// while forwarding every byte verbatim to the client.
//
// The parser never buffers the whole stream: bytes are forwarded as they are
// read, and only the current event's `data` payload is accumulated (bounded) so
// each event can be handed to a callback for analysis. This keeps per-event
// memory bounded regardless of total stream length.
package sse

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// ErrBlocked is returned by Scan when the onEvent callback signals that the
// stream must be terminated (e.g. an enforce-mode deny). Forwarding has already
// stopped; the caller is expected to close the connection.
var ErrBlocked = errors.New("sse: stream blocked by callback")

// maxEventDataBytes caps the accumulated `data` payload for a single event. An
// event whose data exceeds this is still forwarded verbatim, but its callback is
// skipped (no analysis on an unbounded payload).
const maxEventDataBytes = 1 << 20 // 1 MiB

// Scan streams an SSE body from src to dst, parsing each event and invoking
// onEvent with the event's `data` payload (the concatenation of its `data:`
// lines per the SSE spec, joined by "\n").
//
// Every byte read from src is forwarded to dst verbatim as it is read, so the
// client sees the stream live. Only the current event's `data` is accumulated,
// bounded by maxEventDataBytes; beyond the cap the event is forwarded but its
// callback is skipped. A final event with no trailing blank line is still
// delivered at EOF.
//
// If onEvent returns block==true, Scan stops forwarding and returns ErrBlocked.
// Any write or read error (other than io.EOF) is returned as-is.
func Scan(src io.Reader, dst io.Writer, onEvent func(data []byte) (block bool)) error {
	r := bufio.NewReader(src)

	var data []byte    // accumulated data: payload for the current event
	overCap := false   // current event's data exceeded the cap
	haveEvent := false // saw at least one field/line for the current event

	// dispatch hands the current event to onEvent (unless over cap or empty) and
	// resets the per-event accumulators. Returns true if the callback blocked.
	dispatch := func() bool {
		blocked := false
		if haveEvent && !overCap {
			blocked = onEvent(data)
		}
		data = data[:0]
		overCap = false
		haveEvent = false
		return blocked
	}

	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			// Forward verbatim BEFORE parsing so the client sees the live stream.
			if _, werr := dst.Write(line); werr != nil {
				return werr
			}

			// content is the line without its trailing "\n" (and optional "\r").
			content := line
			if content[len(content)-1] == '\n' {
				content = content[:len(content)-1]
			}
			if len(content) > 0 && content[len(content)-1] == '\r' {
				content = content[:len(content)-1]
			}

			if len(content) == 0 {
				// Blank line: event boundary.
				if dispatch() {
					return ErrBlocked
				}
			} else {
				haveEvent = true
				if d, ok := dataPayload(content); ok {
					if !overCap {
						if len(data)+1+len(d) > maxEventDataBytes {
							overCap = true
						} else {
							if len(data) > 0 {
								data = append(data, '\n')
							}
							data = append(data, d...)
						}
					}
				}
				// Non-data fields (event:, id:, retry:, comments) are forwarded
				// above but do not contribute to the data payload.
			}
		}

		if err != nil {
			if err == io.EOF {
				// Deliver a trailing event with no final blank line.
				if dispatch() {
					return ErrBlocked
				}
				return nil
			}
			return err
		}
	}
}

// dataPayload returns the `data` payload of a single SSE field line and whether
// the line is a data field. Per the spec, a field is "name:value" with one
// optional leading space stripped from value; a "data" field with no colon is an
// empty payload. Comment lines (leading ":") and other field names are not data.
func dataPayload(content []byte) (payload []byte, isData bool) {
	colon := bytes.IndexByte(content, ':')
	if colon == 0 {
		// Comment line.
		return nil, false
	}
	var name, value []byte
	if colon < 0 {
		// Field name with no value (e.g. a bare "data").
		name = content
	} else {
		name = content[:colon]
		value = content[colon+1:]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
	}
	if string(name) != "data" {
		return nil, false
	}
	return value, true
}
