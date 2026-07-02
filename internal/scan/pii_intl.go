package scan

import (
	"regexp"
	"strings"
)

// This file adds the international / structured PII detector families:
// pii.identity (Aadhaar, PAN, UK NI, EU VAT, passport) and pii.financial (IBAN,
// ABA routing). Every one carries a MANDATORY validator — the regexes are shaped
// but deliberately loose, and the validator (checksum or structural rule) is what
// makes the family low-false-positive, exactly as validLuhn/validSSN gate card
// and ssn. Detectors keep Category "pii" for back-compat with the response
// scanner + MCP gateway; their precise class comes from classesFor via the
// pattern name (patternClasses in classes.go).

// buildIdentityPatterns returns the pii.identity detectors. Compiled fresh per
// NewScanner call (a handful at boot); each *regexp.Regexp is immutable and
// concurrency-safe thereafter.
func buildIdentityPatterns() []compiledPattern {
	return []compiledPattern{
		{
			// Aadhaar: 12 digits, first digit 2-9, optionally grouped 4-4-4.
			name:     "aadhaar",
			re:       regexp.MustCompile(`\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b`),
			severity: "high",
			category: "pii",
			validate: validAadhaar,
		},
		{
			// PAN: 5 letters, 4 digits, 1 letter (India income-tax ID).
			name:     "pan",
			re:       regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`),
			severity: "medium",
			category: "pii",
			validate: validPAN,
		},
		{
			// UK National Insurance number: 2 letters, 6 digits, 1 suffix A-D,
			// optional spaces.
			name:     "uk_ni",
			re:       regexp.MustCompile(`\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`),
			severity: "medium",
			category: "pii",
			validate: validUKNI,
		},
		{
			// EU VAT: 2-letter country code + 8-12 alphanumerics.
			name:     "eu_vat",
			re:       regexp.MustCompile(`\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[0-9A-Z]{8,12}\b`),
			severity: "medium",
			category: "pii",
			validate: validEUVAT,
		},
		{
			// Passport: keyword+context — "passport" near a 6-9 char alphanumeric.
			// The keyword requirement is what keeps this from matching every short
			// alphanumeric token; no separate validator needed.
			name:     "passport",
			re:       regexp.MustCompile(`(?i)passport(?:\s*(?:number|no\.?|#))?\s*[:=-]?\s*[A-Z0-9]{6,9}\b`),
			severity: "medium",
			category: "pii",
		},
	}
}

// buildFinancialPatterns returns the pii.financial detectors (card/Luhn stays in
// scan.go). Both carry a checksum validator.
func buildFinancialPatterns() []compiledPattern {
	return []compiledPattern{
		{
			// IBAN: 2 letters (country), 2 check digits, 11-30 alphanumerics.
			name:     "iban",
			re:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`),
			severity: "high",
			category: "pii",
			validate: validIBAN,
		},
		{
			// US ABA routing number: 9 digits + routing checksum.
			name:     "aba_routing",
			re:       regexp.MustCompile(`\b\d{9}\b`),
			severity: "medium",
			category: "pii",
			validate: validABA,
		},
	}
}

// buildHealthPatterns returns the pii.health detectors. DEFAULT OFF (high FP):
// NewScanner only appends these WhenHealthPII(true). They are keyword+context
// based — a health vocabulary word adjacent to an identifier, or an ICD-10-shaped
// code — never bare regex, because that over-matches ordinary prose.
func buildHealthPatterns() []compiledPattern {
	return []compiledPattern{
		{
			name:     "health_diagnosis",
			re:       regexp.MustCompile(`(?i)\b(?:diagnos(?:is|ed|es)|patient|symptom|prognosis)\b[^.\n]{0,40}?\b(?:with|of|for|:)\b`),
			severity: "medium",
			category: "pii",
		},
		{
			name:     "health_medication",
			re:       regexp.MustCompile(`(?i)\b(?:prescri(?:bed|ption)|medication|dosage|mg\b)\b[^.\n]{0,30}?\b(?:daily|twice|mg|ml|tablet|dose)\b`),
			severity: "medium",
			category: "pii",
		},
		{
			// ICD-10 code shape (letter, 2 digits, optional .N) next to a clinical
			// keyword, so a bare "A12" in unrelated text does not flag.
			name:     "health_icd10",
			re:       regexp.MustCompile(`(?i)\b(?:icd|diagnosis|code)\b[^.\n]{0,20}?\b[A-TV-Z][0-9]{2}(?:\.[0-9]{1,2})?\b`),
			severity: "medium",
			category: "pii",
		},
	}
}

// --- Validators (small, named, pure) ---

// digitsOf extracts the decimal digits of s as ints, dropping any separators.
func digitsOf(s string) []int {
	d := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d = append(d, int(r-'0'))
		}
	}
	return d
}

// verhoeffD is the D5 dihedral-group multiplication table.
var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// verhoeffP is the permutation table (position-dependent).
var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// validAadhaar reports whether match is a 12-digit Aadhaar with a valid Verhoeff
// checksum. The first digit must be 2-9 (UIDAI never issues 0/1 leading).
func validAadhaar(match string) bool {
	d := digitsOf(match)
	if len(d) != 12 || d[0] < 2 {
		return false
	}
	c := 0
	for i := 0; i < len(d); i++ {
		c = verhoeffD[c][verhoeffP[i%8][d[len(d)-1-i]]]
	}
	return c == 0
}

// panHolderTypes is the set of valid 4th-character holder codes in an Indian PAN.
var panHolderTypes = map[byte]bool{
	'A': true, 'B': true, 'C': true, 'F': true, 'G': true,
	'H': true, 'J': true, 'L': true, 'P': true, 'T': true,
}

// validPAN reports whether match is a structurally valid PAN: AAAAA9999A where
// the 4th letter is a recognised holder type.
func validPAN(match string) bool {
	if len(match) != 10 {
		return false
	}
	return panHolderTypes[match[3]]
}

// niFirstBanned / niSecondBanned are the disallowed prefix letters; niBadPrefixes
// are the reserved two-letter combinations.
var (
	niFirstBanned  = map[byte]bool{'D': true, 'F': true, 'I': true, 'O': true, 'Q': true, 'U': true, 'V': true}
	niSecondBanned = map[byte]bool{'D': true, 'F': true, 'I': true, 'O': true, 'Q': true, 'U': true, 'V': true}
	niBadPrefixes  = map[string]bool{"BG": true, "GB": true, "KN": true, "NK": true, "NT": true, "TN": true, "ZZ": true}
)

// validUKNI reports whether match satisfies the UK NI prefix rules (the format is
// already guaranteed by the regex): first letter not D/F/I/O/Q/U/V, second not
// D/F/I/O/Q/U/V, and the two-letter prefix not reserved.
func validUKNI(match string) bool {
	s := strings.ToUpper(strings.ReplaceAll(match, " ", ""))
	if len(s) != 9 {
		return false
	}
	if niFirstBanned[s[0]] || niSecondBanned[s[1]] {
		return false
	}
	return !niBadPrefixes[s[0:2]]
}

// vatLengths maps an EU VAT country code to the number of characters that FOLLOW
// the two-letter prefix. Countries with a fixed all-digit body are validated on
// length; the shorter/variable schemes accept the documented range.
var vatLengths = map[string][]int{
	"AT": {9}, "BE": {10}, "BG": {9, 10}, "CY": {9}, "CZ": {8, 9, 10},
	"DE": {9}, "DK": {8}, "EE": {9}, "EL": {9}, "ES": {9}, "FI": {8},
	"FR": {11}, "GB": {9, 12}, "HR": {11}, "HU": {8}, "IE": {8, 9},
	"IT": {11}, "LT": {9, 12}, "LU": {8}, "LV": {11}, "MT": {8},
	"NL": {12}, "PL": {10}, "PT": {9}, "RO": {2, 3, 4, 5, 6, 7, 8, 9, 10},
	"SE": {12}, "SI": {8}, "SK": {10},
}

// validEUVAT reports whether match is a country code with a body length the
// country actually uses. The regex guarantees the code and an 8-12 char body.
func validEUVAT(match string) bool {
	if len(match) < 3 {
		return false
	}
	cc := match[0:2]
	body := match[2:]
	lens, ok := vatLengths[cc]
	if !ok {
		return false
	}
	for _, n := range lens {
		if len(body) == n {
			return true
		}
	}
	return false
}

// validIBAN reports whether match passes the ISO 13616 mod-97 check: move the
// first four characters to the end, map letters A=10..Z=35, and confirm the
// resulting integer mod 97 == 1.
func validIBAN(match string) bool {
	s := strings.ToUpper(strings.ReplaceAll(match, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// Rearrange: first 4 chars to the tail.
	rearr := s[4:] + s[0:4]
	// Compute mod 97 incrementally over the letter-expanded digit string.
	rem := 0
	for _, r := range rearr {
		switch {
		case r >= '0' && r <= '9':
			rem = (rem*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			v := int(r-'A') + 10 // two digits: 10..35
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// abaLeadRanges are the valid leading two-digit routing-symbol ranges (Federal
// Reserve districts + special institutions), used to trim the checksum's FP tail.
func abaLeadValid(lead int) bool {
	switch {
	case lead >= 0 && lead <= 12: // Fed districts
		return true
	case lead >= 21 && lead <= 32: // thrift
		return true
	case lead >= 61 && lead <= 72: // electronic
		return true
	case lead == 80: // traveler's cheque / misc
		return true
	default:
		return false
	}
}

// validABA reports whether match is a 9-digit US ABA routing number: the leading
// two digits are a valid routing symbol AND the weighted checksum
// 3(d1+d4+d7)+7(d2+d5+d8)+(d3+d6+d9) mod 10 == 0.
func validABA(match string) bool {
	d := digitsOf(match)
	if len(d) != 9 {
		return false
	}
	if !abaLeadValid(d[0]*10 + d[1]) {
		return false
	}
	sum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return sum%10 == 0
}
