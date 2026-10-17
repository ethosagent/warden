package sse

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// collectScan runs Scan over input, recording each event's data and returning
// the forwarded output and the recorded events.
func collectScan(t *testing.T, input string, block func(i int, data []byte) bool) (out string, events [][]byte, err error) {
	t.Helper()
	var dst bytes.Buffer
	i := 0
	err = Scan(strings.NewReader(input), &dst, func(data []byte) bool {
		// Copy: Scan reuses the backing array across events.
		cp := append([]byte(nil), data...)
		events = append(events, cp)
		b := false
		if block != nil {
			b = block(i, cp)
		}
		i++
		return b
	})
	return dst.String(), events, err
}

func TestScan_TwoEventsVerbatim(t *testing.T) {
	input := "data: first\n\ndata: second\n\n"
	out, events, err := collectScan(t, input, nil)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if out != input {
		t.Fatalf("output not verbatim:\n got %q\nwant %q", out, input)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d: %q", len(events), events)
	}
	if string(events[0]) != "first" || string(events[1]) != "second" {
		t.Fatalf("event data wrong: %q", events)
	}
}

func TestScan_BlockStopsForwarding(t *testing.T) {
	first := "data: first\n\n"
	input := first + "data: second\n\ndata: third\n\n"
	out, events, err := collectScan(t, input, func(i int, data []byte) bool {
		return i == 1 // block on the second event
	})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got %v", err)
	}
	// First event forwarded fully; second event's bytes were forwarded as read
	// (we forward before parsing), but the third must NOT appear.
	if strings.Contains(out, "third") {
		t.Fatalf("forwarding continued past block: %q", out)
	}
	if len(events) != 2 {
		t.Fatalf("expected callback to fire twice, got %d", len(events))
	}
}

func TestScan_MultiLineDataJoined(t *testing.T) {
	input := "data: line one\ndata: line two\n\n"
	_, events, err := collectScan(t, input, nil)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if string(events[0]) != "line one\nline two" {
		t.Fatalf("multi-line data not joined with newline: %q", events[0])
	}
}

func TestScan_CommentAndFieldsNotInData(t *testing.T) {
	input := ": this is a comment\nevent: message\nid: 42\ndata: payload\nretry: 100\n\n"
	out, events, err := collectScan(t, input, nil)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if out != input {
		t.Fatalf("non-data lines not forwarded verbatim:\n got %q\nwant %q", out, input)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if string(events[0]) != "payload" {
		t.Fatalf("data should be only the data: line, got %q", events[0])
	}
}

func TestScan_NoTrailingBlankLineAtEOF(t *testing.T) {
	input := "data: only event no blank line"
	out, events, err := collectScan(t, input, nil)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if out != input {
		t.Fatalf("output not verbatim: %q", out)
	}
	if len(events) != 1 || string(events[0]) != "only event no blank line" {
		t.Fatalf("trailing event at EOF not delivered: %q", events)
	}
}

func TestScan_OverCapForwardedSkipped(t *testing.T) {
	big := strings.Repeat("x", maxEventDataBytes+10)
	input := "data: " + big + "\n\ndata: small\n\n"
	out, events, err := collectScan(t, input, nil)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if out != input {
		t.Fatalf("over-cap event not forwarded verbatim (len got %d want %d)", len(out), len(input))
	}
	// Only the small event should be delivered to the callback.
	if len(events) != 1 || string(events[0]) != "small" {
		t.Fatalf("over-cap event should be skipped, got %d events: first=%q", len(events), firstOf(events))
	}
}

func TestScan_CRLFLineEndings(t *testing.T) {
	input := "data: hello\r\n\r\n"
	out, events, err := collectScan(t, input, nil)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if out != input {
		t.Fatalf("CRLF output not verbatim: %q", out)
	}
	if len(events) != 1 || string(events[0]) != "hello" {
		t.Fatalf("CRLF data wrong: %q", events)
	}
}

func TestScan_OptionalLeadingSpaceStripped(t *testing.T) {
	// "data:value" (no space) and "data:  two spaces" (one stripped).
	input := "data:value\n\ndata:  two\n\n"
	_, events, err := collectScan(t, input, nil)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if string(events[0]) != "value" {
		t.Fatalf("no-space data wrong: %q", events[0])
	}
	if string(events[1]) != " two" {
		t.Fatalf("only one leading space should be stripped: %q", events[1])
	}
}

// errWriter fails after n successful writes, to exercise the write-error path.
type errWriter struct {
	n int
}

func (w *errWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errors.New("write failure")
	}
	w.n--
	return len(p), nil
}

func TestScan_WriteErrorPropagates(t *testing.T) {
	err := Scan(strings.NewReader("data: a\n\ndata: b\n\n"), &errWriter{n: 1}, func(data []byte) bool { return false })
	if err == nil {
		t.Fatal("expected write error to propagate")
	}
	if errors.Is(err, ErrBlocked) {
		t.Fatalf("write error should not be ErrBlocked: %v", err)
	}
}

func firstOf(events [][]byte) []byte {
	if len(events) == 0 {
		return nil
	}
	return events[0]
}

var _ io.Reader = (*bytes.Reader)(nil)

func TestScanHeld_DeniedEventNeverForwarded(t *testing.T) {
	var dst bytes.Buffer
	input := "data: ok\n\nevent: message\ndata: poison\n\ndata: after\n\n"
	err := ScanHeld(strings.NewReader(input), &dst, func(data []byte) bool {
		return string(data) == "poison"
	})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got %v", err)
	}
	if got, want := dst.String(), "data: ok\n\n"; got != want {
		t.Fatalf("forwarded %q, want only the allowed event %q", got, want)
	}
}

func TestScanHeld_AllowedForwardedUnchangedInOrder(t *testing.T) {
	var dst bytes.Buffer
	input := ": keepalive\n\nid: 1\r\nevent: m\r\ndata: a\r\ndata: b\r\n\r\ndata: tail"
	if err := ScanHeld(strings.NewReader(input), &dst, func([]byte) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if dst.String() != input {
		t.Fatalf("got %q want %q", dst.String(), input)
	}
}

func TestScanHeld_TrailingDeniedEventAtEOFNotForwarded(t *testing.T) {
	var dst bytes.Buffer
	err := ScanHeld(strings.NewReader("data: bad"), &dst, func([]byte) bool { return true })
	if !errors.Is(err, ErrBlocked) || dst.Len() != 0 {
		t.Fatalf("err=%v forwarded=%q", err, dst.String())
	}
}

func TestScanHeld_OverCapFailsClosed(t *testing.T) {
	var dst bytes.Buffer
	called := false
	input := "data: ok\n\ndata: " + strings.Repeat("x", maxEventDataBytes+10) + "\n\n"
	err := ScanHeld(strings.NewReader(input), &dst, func(d []byte) bool {
		if len(d) > maxEventDataBytes {
			called = true
		}
		return false
	})
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("expected ErrEventTooLarge, got %v", err)
	}
	if dst.String() != "data: ok\n\n" {
		t.Fatalf("over-cap event leaked: len=%d", dst.Len())
	}
	if called {
		t.Fatal("callback saw the over-cap payload")
	}
}
