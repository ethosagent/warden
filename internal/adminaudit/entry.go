// Package adminaudit is the control plane's admin audit log: every admin
// change is one hash-chained, Ed25519-signed row in the cpstate SQLite
// database, so editing a row, deleting a middle row or swapping the signing
// key is detectable by Verify.
//
// Each Entry is encoded canonically (a fixed-order JSON object), its
// entry_hash is sha256 of those bytes (prev_hash is inside them, which links
// the chain) and its signature is audit.Signer.SignBytes(entry_hash). Seq 1 is
// an audit.genesis entry whose details carry the signing public key; a later
// audit.segment_start entry carries the next key, so verification never needs
// a key file. Recorder.Record is the single write API; the plaintext actor sub
// and email live only in a side table outside the signed bytes.
package adminaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"unicode/utf8"
)

// EntryVersion is the canonical encoding version stamped in every entry.
const EntryVersion = 1

// Reserved actions. Only audit.genesis is written by this package today; the
// others are reserved for the tickets named next to them.
const (
	ActionGenesis      = "audit.genesis"       // seq 1, carries the first public key
	ActionSegmentStart = "audit.segment_start" // manual key change (W-P1-AAUD-05)
	ActionKeyRotated   = "audit.key_rotated"   // signed key rotation (W-P2-KEYS-06)
	ActionPruned       = "audit.pruned"        // retention checkpoint (P5)
)

// Auth methods an entry may carry.
const (
	AuthMethodOIDC       = "oidc"
	AuthMethodBreakglass = "breakglass"
	AuthMethodCLI        = "cli"
	AuthMethodBearer     = "bearer"
	AuthMethodNone       = "none"
	AuthMethodSystem     = "system"
)

// Outcomes an entry may carry.
const (
	OutcomeOK       = "ok"
	OutcomeDenied   = "denied"
	OutcomeRejected = "rejected"
	OutcomeError    = "error"
)

// Field limits enforced by validation.
const (
	maxActionLen     = 64
	maxTargetLen     = 64
	maxTargetRefLen  = 256
	maxRequestIDLen  = 64
	maxStateHashLen  = 128
	maxActorRoleLen  = 64
	maxDetails       = 16
	maxDetailKeyLen  = 32
	maxDetailValLen  = 256
	maxHTTPStatus    = 599
	prevHashLen      = sha256.Size
	actorIDAnonymous = "anonymous"
	actorIDSystem    = "system"
)

// ErrInvalidEntry is returned (wrapped, naming the field but never its value)
// when an entry fails validation. Nothing is written.
var ErrInvalidEntry = errors.New("adminaudit: invalid entry")

var (
	actionRE    = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)
	requestIDRE = regexp.MustCompile(`^[A-Za-z0-9-]*$`)

	authMethods = map[string]bool{
		AuthMethodOIDC: true, AuthMethodBreakglass: true, AuthMethodCLI: true,
		AuthMethodBearer: true, AuthMethodNone: true, AuthMethodSystem: true,
	}
	outcomes = map[string]bool{
		OutcomeOK: true, OutcomeDenied: true, OutcomeRejected: true, OutcomeError: true,
	}
)

// Entry is one admin audit row. The fields up to PrevHash are the signed
// content, in canonical order; EntryHash and Signature are derived from them.
type Entry struct {
	V          int               `json:"v"`
	Seq        int64             `json:"seq"`
	TSUnixNano int64             `json:"ts_unix_nano"`
	ActorID    string            `json:"actor_id"`
	ActorRole  string            `json:"actor_role"`
	AuthMethod string            `json:"auth_method"`
	Action     string            `json:"action"`
	Target     string            `json:"target"`
	TargetRef  string            `json:"target_ref"`
	Details    map[string]string `json:"details"`
	Outcome    string            `json:"outcome"`
	HTTPStatus int               `json:"http_status"`
	BeforeHash string            `json:"before_hash"`
	AfterHash  string            `json:"after_hash"`
	ClientIP   string            `json:"client_ip"`
	RequestID  string            `json:"request_id"`
	KeyID      string            `json:"key_id"`
	PrevHash   []byte            `json:"prev_hash"`

	EntryHash []byte `json:"entry_hash"`
	Signature []byte `json:"signature"`
}

// canonicalEntry fixes the signed field order and encoding. prev_hash is
// lowercase hex; details is always an object (encoding/json sorts its keys).
type canonicalEntry struct {
	V          int               `json:"v"`
	Seq        int64             `json:"seq"`
	TSUnixNano int64             `json:"ts_unix_nano"`
	ActorID    string            `json:"actor_id"`
	ActorRole  string            `json:"actor_role"`
	AuthMethod string            `json:"auth_method"`
	Action     string            `json:"action"`
	Target     string            `json:"target"`
	TargetRef  string            `json:"target_ref"`
	Details    map[string]string `json:"details"`
	Outcome    string            `json:"outcome"`
	HTTPStatus int               `json:"http_status"`
	BeforeHash string            `json:"before_hash"`
	AfterHash  string            `json:"after_hash"`
	ClientIP   string            `json:"client_ip"`
	RequestID  string            `json:"request_id"`
	KeyID      string            `json:"key_id"`
	PrevHash   string            `json:"prev_hash"`
}

// canonical returns the bytes entry_hash covers.
func (e *Entry) canonical() ([]byte, error) {
	details := e.Details
	if details == nil {
		details = map[string]string{}
	}
	b, err := json.Marshal(canonicalEntry{
		V: e.V, Seq: e.Seq, TSUnixNano: e.TSUnixNano,
		ActorID: e.ActorID, ActorRole: e.ActorRole, AuthMethod: e.AuthMethod,
		Action: e.Action, Target: e.Target, TargetRef: e.TargetRef,
		Details: details, Outcome: e.Outcome, HTTPStatus: e.HTTPStatus,
		BeforeHash: e.BeforeHash, AfterHash: e.AfterHash,
		ClientIP: e.ClientIP, RequestID: e.RequestID, KeyID: e.KeyID,
		PrevHash: hex.EncodeToString(e.PrevHash),
	})
	if err != nil {
		return nil, fmt.Errorf("adminaudit: encode entry %d: %w", e.Seq, err)
	}
	return b, nil
}

// entryHash returns sha256 of the canonical bytes.
func (e *Entry) entryHash() ([]byte, error) {
	b, err := e.canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// detailsJSON is the stored form of Details (always an object).
func detailsJSON(d map[string]string) (string, error) {
	if d == nil {
		d = map[string]string{}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("adminaudit: encode details: %w", err)
	}
	return string(b), nil
}

// invalid builds an ErrInvalidEntry that names field and why, never the value.
func invalid(field, why string) error {
	return fmt.Errorf("%w: field %s %s", ErrInvalidEntry, field, why)
}

// validate checks the caller-supplied fields of e. Store-stamped fields (v,
// seq, ts, actor_id, key_id, prev_hash) are not the caller's and are not
// checked here.
func (e *Entry) validate() error {
	if !authMethods[e.AuthMethod] {
		return invalid("auth_method", "is not one of oidc, breakglass, cli, bearer, none, system")
	}
	if !outcomes[e.Outcome] {
		return invalid("outcome", "is not one of ok, denied, rejected, error")
	}
	if len(e.Action) > maxActionLen || !actionRE.MatchString(e.Action) {
		return invalid("action", "must match ^[a-z0-9_]+(\\.[a-z0-9_]+)*$ and be at most 64 bytes")
	}
	if len(e.ActorRole) > maxActorRoleLen || !printableASCII(e.ActorRole) {
		return invalid("actor_role", "must be at most 64 bytes of printable ASCII")
	}
	if len(e.Target) > maxTargetLen || !utf8.ValidString(e.Target) {
		return invalid("target", "must be at most 64 bytes of valid UTF-8")
	}
	if len(e.TargetRef) > maxTargetRefLen || !printableASCII(e.TargetRef) {
		return invalid("target_ref", "must be at most 256 bytes of printable ASCII")
	}
	if len(e.RequestID) > maxRequestIDLen || !requestIDRE.MatchString(e.RequestID) {
		return invalid("request_id", "must be at most 64 bytes of [A-Za-z0-9-]")
	}
	if len(e.BeforeHash) > maxStateHashLen || !printableASCII(e.BeforeHash) {
		return invalid("before_hash", "must be at most 128 bytes of printable ASCII")
	}
	if len(e.AfterHash) > maxStateHashLen || !printableASCII(e.AfterHash) {
		return invalid("after_hash", "must be at most 128 bytes of printable ASCII")
	}
	if e.HTTPStatus < 0 || e.HTTPStatus > maxHTTPStatus {
		return invalid("http_status", "must be between 0 and 599")
	}
	if e.ClientIP != "" {
		if _, err := netip.ParseAddr(e.ClientIP); err != nil {
			return invalid("client_ip", "must be empty or an IP address")
		}
	}
	return validateDetails(e.Details)
}

func validateDetails(d map[string]string) error {
	if len(d) > maxDetails {
		return invalid("details", "must have at most 16 keys")
	}
	for k, v := range d {
		if k == "" || len(k) > maxDetailKeyLen || !utf8.ValidString(k) {
			return invalid("details", "keys must be 1 to 32 bytes of valid UTF-8")
		}
		if len(v) > maxDetailValLen || !utf8.ValidString(v) {
			return invalid("details", "values must be at most 256 bytes of valid UTF-8")
		}
	}
	return nil
}

// printableASCII reports whether s holds only bytes 0x20..0x7e.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
