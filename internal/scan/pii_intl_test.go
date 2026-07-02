package scan

import (
	"strconv"
	"testing"
)

// validAadhaarNumber returns a 12-digit string with a correct Verhoeff check
// digit for the given 11-digit prefix, plus a deliberately-wrong variant. It
// drives the corpus without hardcoding a magic constant: the ONLY check digit
// the validator accepts is the correct one, which is exactly what we assert.
func validAadhaarNumber(t *testing.T, prefix11 string) (valid, invalid string) {
	t.Helper()
	if len(prefix11) != 11 {
		t.Fatalf("prefix must be 11 digits, got %q", prefix11)
	}
	for d := 0; d <= 9; d++ {
		cand := prefix11 + strconv.Itoa(d)
		if validAadhaar(cand) {
			// A different check digit must fail (proves discrimination).
			bad := prefix11 + strconv.Itoa((d+1)%10)
			return cand, bad
		}
	}
	t.Fatalf("no valid Verhoeff check digit for prefix %q", prefix11)
	return "", ""
}

func TestAadhaarVerhoeff(t *testing.T) {
	s := NewScanner()
	valid, invalid := validAadhaarNumber(t, "23412341234")

	dets := s.ScanResponse([]byte("aadhaar " + valid + " on file"))
	assertDetection(t, dets, "pii", "aadhaar")
	if !hasClass(dets, "aadhaar", ClassPIIIdentity) {
		t.Fatalf("aadhaar must carry pii.identity")
	}

	// Bad checksum → rejected.
	dets = s.ScanResponse([]byte("aadhaar " + invalid + " on file"))
	assertNoDetection(t, dets, "pii", "aadhaar")

	// Leading 0/1 is never a real Aadhaar → the regex first-digit rule rejects.
	dets = s.ScanResponse([]byte("value 123412341234 end"))
	assertNoDetection(t, dets, "pii", "aadhaar")
}

func TestPANStructure(t *testing.T) {
	s := NewScanner()
	// 4th char 'P' (individual) is a valid holder type.
	dets := s.ScanResponse([]byte("pan ABCPE1234F verified"))
	assertDetection(t, dets, "pii", "pan")

	// 4th char 'D' is not a valid holder type → rejected.
	dets = s.ScanResponse([]byte("pan ABCDE1234F verified"))
	assertNoDetection(t, dets, "pii", "pan")

	// Lowercase is not a PAN.
	dets = s.ScanResponse([]byte("pan abcpe1234f verified"))
	assertNoDetection(t, dets, "pii", "pan")
}

func TestUKNationalInsurance(t *testing.T) {
	s := NewScanner()
	for _, ok := range []string{"AB123456C", "AB 12 34 56 C"} {
		dets := s.ScanResponse([]byte("NI " + ok + " on record"))
		assertDetection(t, dets, "pii", "uk_ni")
	}
	// Invalid prefixes / suffixes.
	for _, bad := range []string{
		"DA123456C", // first letter D banned
		"AO123456C", // second letter O banned
		"BG123456C", // reserved prefix
		"AB123456E", // suffix out of A-D
	} {
		dets := s.ScanResponse([]byte("NI " + bad + " on record"))
		assertNoDetection(t, dets, "pii", "uk_ni")
	}
}

func TestEUVAT(t *testing.T) {
	s := NewScanner()
	for _, ok := range []string{"DE123456789", "FR12345678901", "IT12345678901"} {
		dets := s.ScanResponse([]byte("vat " + ok + " billed"))
		assertDetection(t, dets, "pii", "eu_vat")
	}
	for _, bad := range []string{
		"DE12345678",   // 8 digits, DE needs 9
		"ZZ123456789",  // not an EU country code
		"FR1234567890", // 10 chars, FR needs 11
	} {
		dets := s.ScanResponse([]byte("vat " + bad + " billed"))
		assertNoDetection(t, dets, "pii", "eu_vat")
	}
}

func TestPassportContext(t *testing.T) {
	s := NewScanner()
	dets := s.ScanResponse([]byte("passport number: X1234567"))
	assertDetection(t, dets, "pii", "passport")

	// A bare alphanumeric with no passport keyword must not flag as passport.
	dets = s.ScanResponse([]byte("order id X1234567 shipped"))
	assertNoDetection(t, dets, "pii", "passport")
}

func TestIBANMod97(t *testing.T) {
	s := NewScanner()
	for _, ok := range []string{
		"DE89370400440532013000",
		"GB82WEST12345698765432",
	} {
		dets := s.ScanResponse([]byte("iban " + ok + " for wire"))
		assertDetection(t, dets, "pii", "iban")
		if !hasClass(dets, "iban", ClassPIIFinancial) {
			t.Fatalf("iban must carry pii.financial")
		}
	}
	// Bad check digits (last char mutated) → mod-97 != 1 → rejected.
	for _, bad := range []string{
		"DE89370400440532013001",
		"GB82WEST12345698765433",
	} {
		dets := s.ScanResponse([]byte("iban " + bad + " for wire"))
		assertNoDetection(t, dets, "pii", "iban")
	}
}

func TestABARouting(t *testing.T) {
	s := NewScanner()
	// Real routing numbers (valid checksum + valid lead range).
	for _, ok := range []string{"021000021", "011401533", "121000248"} {
		dets := s.ScanResponse([]byte("routing " + ok + " account"))
		assertDetection(t, dets, "pii", "aba_routing")
	}
	// Bad checksum, and a valid-checksum-but-invalid-lead-range number.
	for _, bad := range []string{
		"021000020", // fails weighted checksum
		"999999992", // lead 99 out of valid routing-symbol ranges
	} {
		dets := s.ScanResponse([]byte("routing " + bad + " account"))
		assertNoDetection(t, dets, "pii", "aba_routing")
	}
}
