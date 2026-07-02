package proxy

import (
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dlp"
	"github.com/ethosagent/warden/internal/scan"
)

// dlpMonitor is the action recorded when DLP inspected a request but took no
// allow/block/redact decision: mode=monitor with no policy (pure observability),
// or a request with no data class to police. When a policy IS configured and a
// class is detected, the recorded action is the evaluator's verdict instead.
const dlpMonitor = config.DLPActionMonitor

// maxDLPScanSize bounds how much of a request body the DLP stage inspects. It
// mirrors the scanner's own internal cap (scan.maxScanSize, 1 MB): a body larger
// than this is scanned on its first 1 MB and the event is flagged dlp_partial so
// the coverage gap is honest, never silent.
const maxDLPScanSize = 1 << 20 // 1 MB

// DLPScanner scans OUTBOUND request bodies for credential leakage, PII, source
// code, and operator custom classes, then applies the per-class per-destination
// egress policy. In monitor mode it records the would-be action but never blocks
// or mutates; in enforce mode a block terminates the request with 403 and a redact
// scrubs the matched spans inline. mode=off never constructs one (nil scanner
// disables the stage).
//
// It is safe for concurrent use (scan.Scanner is immutable after construction and
// the config is read-only). A nil *DLPScanner means DLP is disabled: the dlpScan
// stage returns immediately with no body read — byte-identical to before.
type DLPScanner struct {
	scanner scan.Scanner
	mode    string           // monitor|enforce (off never builds a scanner)
	cfg     config.DLPConfig // rules + class defaults for the evaluator
}

// NewDLPScanner builds a DLP scanner from the dlp config block. Custom classes are
// compiled into the scanner; the mode + rules + class defaults drive enforcement.
// phonePII/evidence are threaded (evidence off in wiring: findings carry only
// bounded class/pattern/severity). An empty mode normalizes to monitor.
func NewDLPScanner(cfg config.DLPConfig, phonePII, evidence bool) *DLPScanner {
	mode := cfg.Mode
	if mode == "" {
		mode = config.DLPModeMonitor
	}
	var custom []scan.CustomClass
	for _, c := range cfg.Custom {
		custom = append(custom, scan.CustomClass{Name: c.Name, Regex: c.Regex, Severity: c.Severity})
	}
	return &DLPScanner{
		scanner: scan.NewScanner(
			scan.WithPhonePII(phonePII),
			scan.WithEvidence(evidence),
			scan.WithCustomClasses(custom),
		),
		mode: mode,
		cfg:  cfg,
	}
}

// scan runs the detectors over the (already length-bounded) request body and
// returns the deduplicated detections. It reuses ScanResponse, which scans any
// body despite the name (the scanner is direction-agnostic).
func (d *DLPScanner) scan(body []byte) []scan.Detection {
	return d.scanner.ScanResponse(body)
}

// hasPolicy reports whether any egress policy is configured (rules or class
// defaults). With no policy, DLP is pure observability: the stage records classes
// and action=monitor and never blocks — byte-identical to the monitor-only phase.
func (d *DLPScanner) hasPolicy() bool {
	return len(d.cfg.Rules) > 0 || len(d.cfg.Classes) > 0
}

// decide evaluates the egress policy for the whole body's detected classes at dest
// and returns the winning action + its bounded rule id. It is a pure lookup: the
// caller (dlpScan) maps the action onto behavior — block/redact only ENFORCE, while
// monitor records the would-be action and forwards. The verdict is the most
// restrictive across all classes (deny-wins), so a body carrying one redact class
// and one allow class resolves to redact.
func (d *DLPScanner) decide(classes []scan.DataClass, dest string) (action, rule string) {
	v := dlp.Evaluate(classes, dest, d.cfg)
	return v.Action, v.Rule
}

// classAction resolves the egress action for a SINGLE class at dest. The redactor
// uses it for per-class decisions: only spans whose class resolves to redact are
// scrubbed, and an unredactable (decoded/classifier) finding whose class resolves to
// redact/block escalates the request to a fail-closed block.
func (d *DLPScanner) classAction(c scan.DataClass, dest string) string {
	return dlp.Evaluate([]scan.DataClass{c}, dest, d.cfg).Action
}

// scanSpans runs the span-carrying scan for the redactor. ok is false when the
// scanner does not implement the in-process RequestScanner seam — a build-time
// impossibility for the concrete pattern scanner NewDLPScanner constructs, but the
// caller treats !ok as fail-closed (block in enforce) rather than forwarding
// unredacted. The returned offsets are in-process only and never leave the proxy.
func (d *DLPScanner) scanSpans(body []byte) (spans []scan.SpanDetection, encoded []scan.Detection, ok bool) {
	rs, ok := d.scanner.(scan.RequestScanner)
	if !ok {
		return nil, nil, false
	}
	spans, encoded = rs.ScanRequestSpans(body)
	return spans, encoded, true
}
