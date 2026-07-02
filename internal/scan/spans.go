package scan

import "strconv"

// SpanDetection is a Detection plus the [Start,End) byte offsets of its match in
// the RAW request body. It is the IN-PROCESS-ONLY payload the DLP redactor needs to
// locate and scrub a match against the caller's own copy of the body.
//
// It deliberately carries NO json/db struct tags and is NEVER marshaled or
// persisted: offsets must not cross a wire. A serialized offset would let a reader
// reconstruct where a secret sat in the body — a partial content leak — which would
// break the standing invariant that detections carry class/pattern/severity but
// never matched content or its position. ScanRequestSpans is the sole producer;
// the proxy consumes the offsets against its own buffer and then DISCARDS them.
// A wire-hygiene test (spans_test.go) asserts Start/End carry no serialization tag.
type SpanDetection struct {
	Detection
	Start int // inclusive byte offset of the match into the raw (scanned) body
	End   int // exclusive byte offset of the match into the raw (scanned) body
}

// RequestScanner is the span-carrying scan seam used ONLY by the in-process DLP
// redactor. It is intentionally SEPARATE from Scanner: offsets are in-process-only,
// so the wire-facing Scanner interface (consumed by the MCP subsystem and response
// scanner) must NOT expose them. The proxy reaches this method via a type assertion
// on the concrete scanner NewScanner returns; nothing that serializes ever sees it.
type RequestScanner interface {
	Scanner
	// ScanRequestSpans scans body and returns redactable spans (raw-body offsets)
	// plus unredactable findings (decoded-layer / whole-body classifier), never the
	// matched bytes.
	ScanRequestSpans(body []byte) (spans []SpanDetection, encoded []Detection)
}

// allPatterns returns the combined single-regex detector set (injection +
// credential + PII + infrastructure + custom) in one slice. Shared by ScanResponse
// and ScanRequestSpans so the two entry points can never drift in which patterns
// they run.
func (s *patternScanner) allPatterns() []compiledPattern {
	all := make([]compiledPattern, 0, len(s.injectionPatterns)+len(s.credentialPatterns)+len(s.piiPatterns)+len(s.infrastructurePatterns)+len(s.customPatterns))
	all = append(all, s.injectionPatterns...)
	all = append(all, s.credentialPatterns...)
	all = append(all, s.piiPatterns...)
	all = append(all, s.infrastructurePatterns...)
	all = append(all, s.customPatterns...)
	return all
}

// matchSpans returns the [start,end) offsets of EVERY match of p in data that also
// satisfies p.validate when present (Luhn, SSN structure, checksums). Unlike
// firstMatch (which returns only the first valid match, content-only) it returns
// all valid matches WITH offsets, so the redactor can scrub every occurrence.
func matchSpans(p compiledPattern, data []byte) [][]int {
	locs := p.re.FindAllIndex(data, -1)
	if p.validate == nil {
		return locs
	}
	// Filter in place: valid's write index never overtakes the read index.
	valid := locs[:0]
	for _, loc := range locs {
		if p.validate(string(data[loc[0]:loc[1]])) {
			valid = append(valid, loc)
		}
	}
	return valid
}

// ScanRequestSpans is the redaction-facing scan. It returns:
//
//   - spans: detections in the RAW body, each carrying valid [Start,End) offsets so
//     the caller can redact them against its own copy of body. Deduped by
//     (pattern,start,end) — distinct byte ranges are all kept, and overlapping
//     matches of DIFFERENT patterns/classes both appear (unlike ScanResponse's
//     dedup, which collapses to one offset-free Detection per class).
//
//   - encoded: detections with NO redactable offset in the raw body. Two sources:
//     (a) whole-body CLASSIFIER findings (source_code, k8s manifest) — structural
//     co-occurrence/density, not a single span, so there is nothing to scrub; and
//     (b) detections that surfaced ONLY inside a decoded base64/URL layer, whose
//     positions do not map back to the raw body. Class/pattern/severity only, never
//     an offset. A finding already present as a raw span is NOT duplicated here.
//
// DESIGN NOTE (classifier findings are unredactable, per plan D4.1): a source_code
// or k8s finding covers the whole body, so "redacting" it would mean replacing the
// entire file with one marker — that is a block-or-allow decision, not a span edit.
// We therefore route classifier findings to encoded, so a redact rule on such a
// class fails closed to block (escalation) rather than mangling the body.
//
// It respects the same 1 MB cap and validators as ScanResponse.
func (s *patternScanner) ScanRequestSpans(body []byte) (spans []SpanDetection, encoded []Detection) {
	if len(body) > maxScanSize {
		body = body[:maxScanSize]
	}

	patterns := s.allPatterns()

	// 1. Raw body: every valid match with offsets. Dedup identical (pattern,start,end)
	//    spans, keep distinct ranges. Track which (category,pattern,severity) keys are
	//    redactable as raw spans so the encoded pass can skip them.
	spanSeen := make(map[string]struct{})
	rawKeys := make(map[string]struct{})
	for _, p := range patterns {
		for _, loc := range matchSpans(p, body) {
			skey := p.name + "|" + strconv.Itoa(loc[0]) + "|" + strconv.Itoa(loc[1])
			if _, dup := spanSeen[skey]; dup {
				continue
			}
			spanSeen[skey] = struct{}{}
			det := Detection{Category: p.category, Pattern: p.name, Severity: p.severity, Classes: classesForPattern(p)}
			if s.evidence {
				det.Evidence = maskMatch(string(body[loc[0]:loc[1]]))
			}
			spans = append(spans, SpanDetection{Detection: det, Start: loc[0], End: loc[1]})
			rawKeys[detKey(det)] = struct{}{}
		}
	}

	// encoded accumulator: dedup by (category,pattern,severity); never re-add a key
	// already redactable as a raw span.
	encSeen := make(map[string]struct{})
	addEncoded := func(det Detection) {
		key := detKey(det)
		if _, dup := rawKeys[key]; dup {
			return
		}
		if _, dup := encSeen[key]; dup {
			return
		}
		encSeen[key] = struct{}{}
		encoded = append(encoded, det)
	}

	// scanEncodedLayer runs single-regex patterns + classifiers over a layer that has
	// no raw-body offset mapping (a decoded block, or the whole body for classifiers).
	scanEncodedLayer := func(data []byte, runPatterns bool) {
		if runPatterns {
			for _, p := range patterns {
				m, ok := firstMatch(p, data)
				if !ok {
					continue
				}
				det := Detection{Category: p.category, Pattern: p.name, Severity: p.severity, Classes: classesForPattern(p)}
				if s.evidence {
					det.Evidence = maskMatch(m)
				}
				addEncoded(det)
			}
		}
		for _, c := range s.classifiers {
			for _, det := range c(data) {
				det.Classes = classesFor(det.Pattern, det.Category)
				addEncoded(det)
			}
		}
	}

	// 2. Whole-body classifiers on the raw body (patterns already handled above).
	scanEncodedLayer(body, false)

	// 3. Decoded layers: patterns + classifiers, all unredactable (no raw offset).
	for _, block := range decodeBase64Blocks(body) {
		scanEncodedLayer(block, true)
	}
	if urlDecoded := decodeURLEncoded(body); urlDecoded != nil {
		scanEncodedLayer(urlDecoded, true)
	}

	return spans, encoded
}

// classesForPattern resolves a compiled pattern's data classes: its explicit
// per-pattern classes (custom.<name>) when set, else the central classesFor table.
// Mirrors the resolution in ScanResponse's scanLayer so the two paths agree.
func classesForPattern(p compiledPattern) []DataClass {
	if p.classes != nil {
		return p.classes
	}
	return classesFor(p.name, p.category)
}

// detKey is the dedup/identity key for a detection on the wire-safe axes
// (category, pattern, severity) — the same key ScanResponse dedups on, so the raw
// vs encoded partition is consistent with the offset-free scan.
func detKey(d Detection) string {
	return d.Category + "|" + d.Pattern + "|" + d.Severity
}
