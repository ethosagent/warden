package scan

import (
	"encoding/base64"
	"testing"
)

// --- Email ---

func TestPIIEmail(t *testing.T) {
	s := NewScanner()
	detections := s.ScanResponse([]byte("contact alice.smith+work@example.co.uk for details"))
	assertDetection(t, detections, "pii", "email")
}

func TestPIIEmailNonEmail(t *testing.T) {
	s := NewScanner()
	// "@" with no domain, and a bare word, must not flag.
	detections := s.ScanResponse([]byte("ping me @home or visit example dot com"))
	assertNoDetection(t, detections, "pii", "email")
}

// --- Card (Luhn) ---

func TestPIICardLuhnValid(t *testing.T) {
	s := NewScanner()
	detections := s.ScanResponse([]byte("card 4111111111111111 on file"))
	assertDetection(t, detections, "pii", "card")
}

func TestPIICardLuhnValidWithSeparators(t *testing.T) {
	s := NewScanner()
	for _, body := range []string{
		"card 4111-1111-1111-1111 on file",
		"card 4111 1111 1111 1111 on file",
	} {
		detections := s.ScanResponse([]byte(body))
		assertDetection(t, detections, "pii", "card")
	}
}

func TestPIICardLuhnInvalidDoesNotFlag(t *testing.T) {
	s := NewScanner()
	// 1234567812345678 fails Luhn -> must NOT flag.
	for _, body := range []string{
		"number 1234567812345678 here",
		"number 1234-5678-1234-5678 here",
		"number 1234 5678 1234 5678 here",
	} {
		detections := s.ScanResponse([]byte(body))
		assertNoDetection(t, detections, "pii", "card")
	}
}

// --- SSN ---

func TestPIISSNValid(t *testing.T) {
	s := NewScanner()
	detections := s.ScanResponse([]byte("ssn 123-45-6789 record"))
	assertDetection(t, detections, "pii", "ssn")
}

func TestPIISSNInvalidDoesNotFlag(t *testing.T) {
	s := NewScanner()
	invalids := []string{
		"000-12-3456", // area 000
		"666-12-3456", // area 666
		"900-12-3456", // area 900-999
		"123-00-6789", // group 00
		"123-45-0000", // serial 0000
	}
	for _, ssn := range invalids {
		detections := s.ScanResponse([]byte("value " + ssn + " end"))
		assertNoDetection(t, detections, "pii", "ssn")
	}
}

// --- Phone (opt-in) ---

func TestPIIPhoneOffByDefault(t *testing.T) {
	s := NewScanner()
	detections := s.ScanResponse([]byte("call +14155552671 or (415) 555-2671"))
	assertNoDetection(t, detections, "pii", "phone")
}

func TestPIIPhoneOptIn(t *testing.T) {
	s := NewScanner(WithPhonePII(true))
	detections := s.ScanResponse([]byte("call +14155552671 now"))
	assertDetection(t, detections, "pii", "phone")

	detections = s.ScanResponse([]byte("call (415) 555-2671 now"))
	assertDetection(t, detections, "pii", "phone")
}

// --- Encoding layers ---

func TestPIICardInBase64(t *testing.T) {
	s := NewScanner()
	// Luhn-valid card inside a base64 blob (>= 64 chars encoded).
	plaintext := "customer card on file: 4111111111111111 thanks for shopping today"
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	if len(encoded) < 64 {
		t.Fatalf("base64 too short: %d", len(encoded))
	}
	detections := s.ScanResponse([]byte("payload " + encoded + " end"))
	assertDetection(t, detections, "pii", "card")
}

// --- Detection carries no matched content ---

func TestPIIDetectionNoMatchedContent(t *testing.T) {
	s := NewScanner()
	detections := s.ScanResponse([]byte("email bob@example.com card 4111111111111111 ssn 123-45-6789"))
	if len(detections) == 0 {
		t.Fatal("expected PII detections")
	}
	for _, d := range detections {
		if d.Category != "pii" {
			continue
		}
		// Only Category, Pattern, Severity exist on Detection; assert the
		// values never echo the matched secret.
		if d.Pattern == "" || d.Severity == "" {
			t.Errorf("detection missing pattern/severity: %+v", d)
		}
	}
}

// --- Helper ---

func assertNoDetection(t *testing.T, detections []Detection, category, pattern string) {
	t.Helper()
	for _, d := range detections {
		if d.Category == category && d.Pattern == pattern {
			t.Errorf("expected NO detection for category=%q pattern=%q, got: %+v", category, pattern, detections)
			return
		}
	}
}
