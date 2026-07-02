package proxy

import (
	"github.com/ethosagent/warden/internal/scan"
)

// dlpMonitor is the only action DLP takes in Phase 1. The config vocabulary is
// off|monitor|enforce (validated in internal/config), but the proxy never
// blocks or redacts this phase: off disables the stage (nil scanner), and both
// monitor and enforce record findings as "monitor". Phase 3 adds the enforce
// action; that is where a dlpEnforce/dlpBlock constant will earn its place.
const dlpMonitor = "monitor"

// maxDLPScanSize bounds how much of a request body the DLP stage inspects. It
// mirrors the scanner's own internal cap (scan.maxScanSize, 1 MB): a body larger
// than this is scanned on its first 1 MB and the event is flagged dlp_partial so
// the coverage gap is honest, never silent.
const maxDLPScanSize = 1 << 20 // 1 MB

// DLPScanner scans OUTBOUND request bodies for credential leakage, prompt
// injection, and PII using the SAME detectors the response scanner and MCP wedge
// use. Phase 1 supports monitor only: it records findings on the audit event +
// bounded metrics but never mutates the body and never blocks. enforce is
// accepted as config (see NewDLPScanner) but behaves as monitor this phase.
//
// It is safe for concurrent use (scan.Scanner is immutable after construction).
// A nil *DLPScanner means DLP is disabled: the dlpScan stage returns immediately
// with no body read — byte-identical to before.
type DLPScanner struct {
	scanner scan.Scanner
	mode    string
}

// NewDLPScanner builds a DLP scanner for the given mode. evidence is off in
// Phase 1's wiring (findings carry only bounded class/pattern/severity, never a
// content sample); the option is threaded so a later phase can opt in without a
// signature change, mirroring NewResponseScanner. An empty mode normalizes to
// monitor. enforce is accepted here but treated as monitor until Phase 3 wires
// blocking; the worker logs once that enforce is not yet active.
func NewDLPScanner(mode string, phonePII, evidence bool) *DLPScanner {
	if mode == "" {
		mode = dlpMonitor
	}
	return &DLPScanner{
		scanner: scan.NewScanner(scan.WithPhonePII(phonePII), scan.WithEvidence(evidence)),
		mode:    mode,
	}
}

// scan runs the detectors over the (already length-bounded) request body and
// returns the deduplicated detections. It reuses ScanResponse, which scans any
// body despite the name (the scanner is direction-agnostic).
func (d *DLPScanner) scan(body []byte) []scan.Detection {
	return d.scanner.ScanResponse(body)
}
