// Package integration is Warden's embeddable alert-delivery pipeline: producers
// publish typed Findings onto a Bus, the AlertManager dedups them into stateful
// Alerts and persists every one to a SQLite Store (the system-of-record), and a
// Router PUSHES the resulting Alerts to configured outbound integrations
// (webhook, Slack, …) selected by per-instance routing predicates.
//
// This package is deliberately self-contained: it imports no other Warden
// package. Phase 2 wires it into the control plane / worker; nothing here
// depends on config, controlplane, or analytics.
//
// Egress hygiene is a core invariant. Alerts cross Warden's trust boundary (they
// are pushed to third-party webhooks), so Alert.Summary and Alert.Evidence are
// bounded by construction (boundedSummary/boundEvidence) and re-asserted at the
// router boundary (assertEgressSafe) before any integration sees an Alert.
// Warden must never become an egress vector via its own alerts.
package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Severity is a finding/alert's intrinsic severity, ordered so a numeric max
// (used by the store's ON CONFLICT escalation) is a valid "most severe" merge.
type Severity int

const (
	// SevInfo is the lowest severity.
	SevInfo Severity = iota
	// SevLow is a low-severity finding.
	SevLow
	// SevMedium is a medium-severity finding.
	SevMedium
	// SevHigh is a high-severity finding.
	SevHigh
	// SevCritical is the highest severity.
	SevCritical
)

// String returns the lowercase canonical name used in config matching and logs.
func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

// ParseSeverity parses a case-insensitive severity name.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SevInfo, nil
	case "low":
		return SevLow, nil
	case "medium":
		return SevMedium, nil
	case "high":
		return SevHigh, nil
	case "critical":
		return SevCritical, nil
	default:
		return SevInfo, fmt.Errorf("integration: unknown severity %q", s)
	}
}

// MarshalText makes Severity render as its name in structured logs / JSON.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// maxSeverity returns the more severe of a and b (used on collapse/escalation).
func maxSeverity(a, b Severity) Severity {
	if a >= b {
		return a
	}
	return b
}

// Status is an Alert's lifecycle state. acked/muted land in a later milestone.
type Status string

const (
	// StatusFiring is an active alert.
	StatusFiring Status = "firing"
	// StatusResolved is a cleared alert. Not produced in this phase (no resolve
	// TTL yet); reserved so there is no later type migration.
	StatusResolved Status = "resolved"
)

// Subject identifies what a finding/alert is about, using bounded identifiers
// only — never bodies or raw values.
type Subject struct {
	Domain string `json:"domain,omitempty"`
	Tool   string `json:"tool,omitempty"`
	Agent  string `json:"agent,omitempty"`
	// Worker is an optional fleet dimension; empty in single-node deployments.
	Worker string `json:"worker,omitempty"`
}

// Evidence is masked/bounded supporting detail (e.g. "rate=7.2% window=5m").
// It is bounded by construction (boundEvidence) and MUST never carry raw
// secrets or request/response bodies.
type Evidence string

// Finding is the immutable, value-free fact a detector emits onto the Bus.
type Finding struct {
	RuleID   string
	Category string
	Severity Severity
	Subject  Subject
	Summary  string
	Evidence Evidence
	// DedupKey is the stable key the producer computes, e.g.
	// "egress_blocked:api.foo.com". Its prefix before the first ':' is treated
	// as the rule id for routing (see MatchClause.Rule).
	DedupKey string
	Ts       time.Time
}

// Alert is the stateful, deduped entity the AlertManager derives from Findings.
// It is the persisted system-of-record row and the unit the Router delivers.
type Alert struct {
	// ID is deterministic from DedupKey (first 16 hex of sha256), so re-fires
	// upsert the same store row and sinks can be idempotent on ID.
	ID        string    `json:"id"`
	DedupKey  string    `json:"dedupKey"`
	Category  string    `json:"category"`
	Severity  Severity  `json:"severity"`
	Subject   Subject   `json:"subject"`
	Summary   string    `json:"summary"`
	Evidence  Evidence  `json:"evidence"`
	Status    Status    `json:"status"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Egress-hygiene caps. Summary and Evidence are the two operator-facing strings
// that leave Warden's trust boundary; both are bounded by construction and the
// caps are re-asserted at the delivery boundary.
const (
	maxSummaryBytes  = 512
	maxEvidenceBytes = 256
	// truncationMarker is appended when a string is truncated. It is a single
	// U+2026 (3 UTF-8 bytes) so the bounded result stays within the cap.
	truncationMarker = "…"
)

// boundString truncates s to at most max bytes, appending truncationMarker when
// it truncates and never splitting a UTF-8 rune. The returned string is
// guaranteed to be <= max bytes.
func boundString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	limit := max - len(truncationMarker)
	if limit < 0 {
		// Cap smaller than the marker itself: return a hard byte cut, rune-safe.
		limit = max
	}
	b := s[:limit]
	for len(b) > 0 && !utf8.ValidString(b) {
		b = b[:len(b)-1]
	}
	if limit == max {
		return b
	}
	return b + truncationMarker
}

// boundedSummary caps an Alert/Finding summary to maxSummaryBytes.
func boundedSummary(s string) string { return boundString(s, maxSummaryBytes) }

// boundEvidence caps Evidence to maxEvidenceBytes.
func boundEvidence(e Evidence) Evidence { return Evidence(boundString(string(e), maxEvidenceBytes)) }

// assertEgressSafe is the single choke point at the router boundary: it returns
// an error if a would-be-delivered Alert exceeds the egress caps. The router
// logs and DROPS such an alert rather than leaking it — a bug that produced an
// oversized field must not become an egress channel.
func assertEgressSafe(a Alert) error {
	if len(a.Summary) > maxSummaryBytes {
		return fmt.Errorf("integration: alert %s summary %d bytes exceeds cap %d", a.ID, len(a.Summary), maxSummaryBytes)
	}
	if len(a.Evidence) > maxEvidenceBytes {
		return fmt.Errorf("integration: alert %s evidence %d bytes exceeds cap %d", a.ID, len(a.Evidence), maxEvidenceBytes)
	}
	return nil
}

// alertID derives a stable, deterministic ID from a DedupKey: the first 16 hex
// characters of sha256(DedupKey). Re-fires of the same key produce the same ID.
func alertID(dedupKey string) string {
	sum := sha256.Sum256([]byte(dedupKey))
	return hex.EncodeToString(sum[:])[:16]
}

// ruleIDFromDedupKey returns the rule id carried by a DedupKey: the prefix
// before the first ':'. This is how MatchClause.Rule matches without adding an
// exported field to Alert (the DedupKey already carries the rule id by
// producer convention, e.g. "error_rate:api.foo.com" -> "error_rate").
func ruleIDFromDedupKey(k string) string {
	if i := strings.IndexByte(k, ':'); i >= 0 {
		return k[:i]
	}
	return k
}

// firstLine returns s truncated at the first newline, so multi-line error text
// never bloats an integration_down Evidence string.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
