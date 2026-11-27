package offboard

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Finding rule ids the refresh job publishes.
const (
	// RuleReauthRequired: a user must sign in to the portal again (the link
	// is expiring, reached its absolute lifetime, or its token was lost).
	RuleReauthRequired = "offboarding_reauth_required"
	// RuleRefreshFailing: one user's refresh failed maxFailures times in a
	// row while the issuer was otherwise healthy.
	RuleRefreshFailing = "idp_refresh_failing"
	// RuleRefreshUnavailable: more than half of a run's refreshes against one
	// issuer were transient failures.
	RuleRefreshUnavailable = "idp_refresh_unavailable"
	// RuleConfigError: the IdP rejected the warden-portal client (401
	// invalid_client); the job pauses until restart.
	RuleConfigError = "offboarding_config_error"
)

// Severity of a Finding; the control plane maps it to the alert pipeline's.
type Severity int

// Severities used here.
const (
	SeverityMedium Severity = iota + 1
	SeverityHigh
	SeverityCritical
)

// Finding is what the job publishes. It never carries a token, a Reference,
// an email or IdP error text: Sub is the opaque subject, the DedupKey holds
// only a sha256 prefix, and Evidence holds counts and class codes.
type Finding struct {
	RuleID   string
	Severity Severity
	// Sub is the user the Finding is about ("" for an issuer-wide one).
	Sub      string
	Summary  string
	Evidence string
	DedupKey string
	Ts       time.Time
}

// FindingPublisher delivers Findings (the control plane's publishFinding).
type FindingPublisher interface {
	PublishFinding(f Finding)
}

// SubHash is the log- and dedup-safe name of a subject or issuer: the first
// 16 hex characters of its sha256.
func SubHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
