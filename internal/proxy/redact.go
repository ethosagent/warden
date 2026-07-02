package proxy

import (
	"bytes"
	"io"
	"sort"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/scan"
)

// dlpApplyRedact handles a whole-body verdict of "redact". It is the ENFORCE-mode
// inline redactor and the MONITOR-mode no-mutate recorder in one place, because both
// need the same span-carrying scan to decide the encoded-escalation flag.
//
// The sequence (all fail-closed):
//
//  1. Re-scan the (capped) body for SPANS + ENCODED findings. If the span seam is
//     somehow unavailable, enforce fails closed to block; monitor just forwards.
//  2. DECODED-LAYER / CLASSIFIER ESCALATION (fail-closed): an "encoded" finding has
//     no locatable offset in the raw body, so a redact rule cannot scrub it. If any
//     encoded finding's class resolves to redact (or block), set DLPEncoded=true and
//     — in ENFORCE — escalate the WHOLE request to a 403 block. We never forward a
//     body a redact rule wanted scrubbed but we could not locate. MONITOR records the
//     flag + would-be action and forwards the original.
//  3. MONITOR never mutates: with no escalation it simply forwards the ORIGINAL body,
//     recording the would-be redact action (already set by the caller).
//  4. ENFORCE builds the redacted body from the raw spans whose class resolves to
//     redact (redactSpans: sort, merge overlaps, non-destructive rewrite) and reframes
//     the request (body + Content-Length). If nothing redactable is produced for a
//     redact verdict, it fails closed to block rather than forward unchanged.
//
// Ordering note: dlpScan runs BEFORE swapSecrets, so redaction operates on the
// PRE-SWAP body (placeholder NAMES, never real secret values) and swapSecrets then
// reads the REDACTED bytes via the shared scope buffer and recomputes Content-Length
// after its own swap — so the final on-wire framing is valid after BOTH stages.
func (p *Proxy) dlpApplyRedact(s *requestScope, body []byte) (endSession bool) {
	d := p.dlp()
	enforce := d.mode == config.DLPModeEnforce

	scanBody := body
	if len(scanBody) > maxDLPScanSize {
		scanBody = scanBody[:maxDLPScanSize]
	}
	spans, encoded, ok := d.scanSpans(scanBody)
	if !ok {
		// Span seam unavailable: cannot locate anything to scrub. Fail closed in
		// enforce; monitor forwards (it never mutates and never blocks).
		if enforce {
			return p.dlpDeny(s)
		}
		return false
	}

	// Step 2 — decoded-layer / classifier escalation.
	for _, det := range encoded {
		for _, c := range det.Classes {
			if a := d.classAction(c, s.domain); a == config.DLPActionRedact || a == config.DLPActionBlock {
				s.dlpEncoded = true
			}
		}
	}
	if s.dlpEncoded {
		if enforce {
			// Fail closed: a redact rule wanted this scrubbed but it lives only in a
			// decoded/classifier layer with no raw offset — block the whole request.
			return p.dlpDeny(s)
		}
		// monitor: fall through to forward the original, would-be redact recorded.
		return false
	}

	// Step 3 — monitor never mutates.
	if !enforce {
		return false
	}

	// Step 4 — enforce: scrub the redactable spans and reframe the request.
	redacted, redactedOK := redactSpans(body, spans, d, s.domain)
	if !redactedOK {
		// Verdict was redact but nothing locatable resolved to redact (or the rewrite
		// could not be produced): fail closed rather than forward an unredacted body.
		return p.dlpDeny(s)
	}
	s.reqBody = redacted
	s.req.Body = io.NopCloser(bytes.NewReader(redacted))
	s.req.ContentLength = int64(len(redacted))
	// s.dlpAction ("redact"), s.dlpClasses, s.dlpRule are already set by the caller;
	// the request now forwards through swapSecrets (which reads the redacted buffer).
	return false
}

// redactRange is one resolved byte range to scrub, plus the marker label to emit.
type redactRange struct {
	start, end int
	label      string
}

// redactSpans selects the spans whose class resolves to redact at dest, labels each
// with its most-specific redacting class, and rewrites body via redactRanges. It
// returns ok=false when no span is redactable (so a redact verdict with nothing to
// scrub fails closed upstream). It never mutates the input body.
func redactSpans(body []byte, spans []scan.SpanDetection, d *DLPScanner, dest string) (redacted []byte, ok bool) {
	var ranges []redactRange
	for _, sp := range spans {
		label, redact := d.redactLabel(sp.Classes, dest)
		if !redact {
			continue
		}
		// Guard offsets against the body we are rewriting (spans came from the capped
		// prefix, which is a prefix of body, so valid offsets always fit).
		if sp.Start < 0 || sp.End > len(body) || sp.Start >= sp.End {
			continue
		}
		ranges = append(ranges, redactRange{start: sp.Start, end: sp.End, label: label})
	}
	if len(ranges) == 0 {
		return nil, false
	}
	return redactRanges(body, ranges), true
}

// redactLabel returns the label to stamp on a span and whether it should be redacted.
// It picks the FIRST class (Classes is ordered most-specific-first, e.g. a PEM key is
// [credentials, source_code]) that resolves to redact at dest — so a multi-class span
// gets one deterministic marker. A span with no redacting class is left untouched.
func (d *DLPScanner) redactLabel(classes []scan.DataClass, dest string) (label string, redact bool) {
	for _, c := range classes {
		if d.classAction(c, dest) == config.DLPActionRedact {
			return string(c), true
		}
	}
	return "", false
}

// redactRanges is the pure, non-destructive body rewrite: it sorts the ranges by
// start (then longer-first so a merged group keeps the outermost span's label),
// MERGES overlapping ranges into one marker (a byte covered by several classes yields
// a single [REDACTED:<label>] using the first/most-specific class), copies the gaps
// between ranges verbatim, and replaces each covered range with [REDACTED:<label>].
// All offset math is on the ORIGINAL body while emitting the new one, so overlapping,
// adjacent, offset-0, and end-of-body ranges are all handled correctly. Adjacent
// (touching, non-overlapping) ranges of different classes stay as two markers.
func redactRanges(body []byte, ranges []redactRange) []byte {
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		return ranges[i].end > ranges[j].end
	})

	var out bytes.Buffer
	cursor := 0
	for i := 0; i < len(ranges); {
		cur := ranges[i]
		// Merge every subsequent range that STRICTLY overlaps the growing group.
		j := i + 1
		for j < len(ranges) && ranges[j].start < cur.end {
			if ranges[j].end > cur.end {
				cur.end = ranges[j].end
			}
			j++
		}
		if cur.start > cursor {
			out.Write(body[cursor:cur.start])
		}
		out.WriteString("[REDACTED:" + cur.label + "]")
		cursor = cur.end
		i = j
	}
	if cursor < len(body) {
		out.Write(body[cursor:])
	}
	return out.Bytes()
}
