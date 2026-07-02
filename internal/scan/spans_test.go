package scan

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

// spanFor returns the first span with the given pattern name, or nil.
func spanFor(spans []SpanDetection, pattern string) *SpanDetection {
	for i := range spans {
		if spans[i].Pattern == pattern {
			return &spans[i]
		}
	}
	return nil
}

func encodedHas(dets []Detection, pattern string) bool {
	for _, d := range dets {
		if d.Pattern == pattern {
			return true
		}
	}
	return false
}

// A raw-body match is returned as a span with offsets that slice back to the match.
func TestScanRequestSpans_RawOffsets(t *testing.T) {
	s := NewScanner().(RequestScanner)
	body := []byte("prefix AKIAIOSFODNN7EXAMPLE suffix")
	spans, encoded := s.ScanRequestSpans(body)

	sp := spanFor(spans, "aws_access_key")
	if sp == nil {
		t.Fatalf("expected an aws_access_key span, got %+v", spans)
	}
	if got := string(body[sp.Start:sp.End]); got != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("span offsets [%d:%d] slice to %q, want the AKIA key", sp.Start, sp.End, got)
	}
	if !containsClass(sp.Classes, ClassCredentials) {
		t.Fatalf("span must carry the credentials class, got %v", sp.Classes)
	}
	if encodedHas(encoded, "aws_access_key") {
		t.Fatalf("a redactable raw span must NOT also appear in encoded: %+v", encoded)
	}
}

// Multiple distinct matches of the same pattern keep their individual offsets
// (dedup is per (pattern,start,end), not collapsed to one like ScanResponse).
func TestScanRequestSpans_MultipleKeepsOffsets(t *testing.T) {
	s := NewScanner().(RequestScanner)
	body := []byte("a@b.com and c@d.com here")
	spans, _ := s.ScanRequestSpans(body)

	var emails []SpanDetection
	for _, sp := range spans {
		if sp.Pattern == "email" {
			emails = append(emails, sp)
		}
	}
	if len(emails) != 2 {
		t.Fatalf("expected 2 distinct email spans, got %d (%+v)", len(emails), emails)
	}
	for _, sp := range emails {
		got := string(body[sp.Start:sp.End])
		if !strings.Contains(got, "@") {
			t.Fatalf("email span %q does not look like an email", got)
		}
	}
}

// A whole-body classifier finding (source_code) is UNREDACTABLE: it goes to encoded,
// never to spans (there is no single span to scrub).
func TestScanRequestSpans_ClassifierIsEncoded(t *testing.T) {
	s := NewScanner().(RequestScanner)
	body := []byte("package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n")
	spans, encoded := s.ScanRequestSpans(body)

	if spanFor(spans, "code_go") != nil {
		t.Fatalf("a classifier finding must not be a span: %+v", spans)
	}
	if !encodedHas(encoded, "code_go") {
		t.Fatalf("expected code_go in encoded (unredactable), got %+v", encoded)
	}
}

// A credential hidden inside a base64 block has NO raw offset: it surfaces only in
// encoded (the decoded layer), never as a redactable span.
func TestScanRequestSpans_DecodedLayerIsEncoded(t *testing.T) {
	s := NewScanner().(RequestScanner)
	plain := "AKIAIOSFODNN7EXAMPLE is the leaked key value padded out"
	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	if len(b64) < 64 {
		t.Fatalf("test setup: base64 block must be >=64 chars, got %d", len(b64))
	}
	body := []byte("payload " + b64)

	spans, encoded := s.ScanRequestSpans(body)
	if spanFor(spans, "aws_access_key") != nil {
		t.Fatalf("a decoded-layer key must not produce a raw span: %+v", spans)
	}
	if !encodedHas(encoded, "aws_access_key") {
		t.Fatalf("expected aws_access_key in encoded (decoded layer), got %+v", encoded)
	}
}

// Wire hygiene: SpanDetection's offsets must carry NO json/db serialization tag —
// offsets are in-process only and must never cross a wire. (SpanDetection itself is
// never marshaled; this guards against a future field gaining a tag.)
func TestSpanDetection_NeverSerializesOffsets(t *testing.T) {
	typ := reflect.TypeOf(SpanDetection{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Name != "Start" && f.Name != "End" {
			continue
		}
		if tag := f.Tag.Get("json"); tag != "" {
			t.Fatalf("SpanDetection.%s must have NO json tag, got %q", f.Name, tag)
		}
		if tag := f.Tag.Get("db"); tag != "" {
			t.Fatalf("SpanDetection.%s must have NO db tag, got %q", f.Name, tag)
		}
	}
}
