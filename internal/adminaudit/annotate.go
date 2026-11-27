package adminaudit

import (
	"context"
	"sync"
)

// Annotation detail keys a handler may attach through Annotate. The list is
// closed: any other key is dropped, so a handler cannot widen what a row
// carries by accident (and never a value, a token or a body).
const (
	DetailOp   = "op"   // the operation, for example put or delete
	DetailEtag = "etag" // the resulting version of the target, for example a policy ETag
	// DetailHasSub and DetailHasEmail say which identifiers a block list entry
	// holds ("true" or "false"), never the identifiers themselves.
	DetailHasSub   = "has_sub"
	DetailHasEmail = "has_email"
	// DetailHasIss says a token session revoke filter named an IdP issuer.
	DetailHasIss = "has_iss"
	// DetailWorkerID and DetailCount describe a worker certificate revocation:
	// the worker id and how many certificates it revoked.
	DetailWorkerID = "worker_id"
	DetailCount    = "count"
	// DetailEnrollTokens is how many unused id-bound enrollment tokens the
	// revocation revoked with the certificates.
	DetailEnrollTokens = "enroll_tokens_revoked"
	// DetailAPIKeyID is the id (never the secret or its hash) of the API key a
	// request authenticated with (W-P2-APIK-02).
	DetailAPIKeyID = "api_key_id"
	// DetailScopes (comma-separated scope names) and DetailExpiresAt (RFC 3339)
	// describe a key an API key create or revoke row is about (W-P2-APIK-03).
	DetailScopes    = "scopes"
	DetailExpiresAt = "expires_at"
	// DetailAPIKeysRevoked is how many API keys a session revoke-by-subject also
	// revoked.
	DetailAPIKeysRevoked = "api_keys_revoked"
	// The change draft details (W-P2-APPR-04): versions and codes only, never
	// doc content.
	DetailBaseVersion    = "base_version"
	DetailAppliedVersion = "applied_version"
	DetailWidening       = "widening"
	DetailReasons        = "reasons" // reason codes, comma separated
	DetailReplayStatus   = "replay_status"
	DetailAckNoReplay    = "acknowledge_no_replay"
)

// The agent registry's keys (W-P2-AREG-02), camelCase like the JSON API.
// changed lists the edited fields; the *Added and *Removed lists name key ids,
// RFC 7638 thumbprints and groups, each element percent-encoded and the list
// cut at an element when it would not fit one value. Every list also has a
// <key>Count (the full number of elements) and, when it was cut, a
// <key>Sha256 (of the full list, sorted by raw value before encoding, then percent-encoded and comma-joined) and
// DetailTruncated "true". They name fields, ids and groups; never key material.
const (
	DetailChanged       = "changed"
	DetailKidsAdded     = "kidsAdded"
	DetailKidsRemoved   = "kidsRemoved"
	DetailJktsAdded     = "jktsAdded"
	DetailJktsRemoved   = "jktsRemoved"
	DetailGroupsAdded   = "groupsAdded"
	DetailGroupsRemoved = "groupsRemoved"
	DetailStatusFrom    = "statusFrom"
	DetailStatusTo      = "statusTo"
	DetailTruncated     = "truncated"

	// DetailCountSuffix and DetailSha256Suffix are appended to a list key.
	DetailCountSuffix  = "Count"
	DetailSha256Suffix = "Sha256"
)

// The require-mode rollout guard's keys (W-P2-WBND-07): force is "true" when an
// admin overrode the refusal, and workersLacking lists (with workersLackingCount,
// like the agent lists above) the proxy ids that lacked identity/require-v1.
const (
	DetailForce          = "force"
	DetailWorkersLacking = "workersLacking"
	// DetailCapability names the capability a forced guard found missing
	// (usercost/v1 for the cost-cap guard, W-P3-PUL-08). The require guard,
	// which predates it, records none.
	DetailCapability = "capability"
)

// DetailSource is where a change came from (for example approval).
const DetailSource = "source"

// annotationKeys is the closed set of keys Annotate keeps.
var annotationKeys = func() map[string]bool {
	m := map[string]bool{
		DetailOp: true, DetailEtag: true, DetailHasSub: true, DetailHasEmail: true, DetailHasIss: true,
		DetailAPIKeyID: true, DetailScopes: true, DetailExpiresAt: true, DetailAPIKeysRevoked: true,
		DetailWorkerID: true, DetailCount: true, DetailEnrollTokens: true,
		DetailBaseVersion: true, DetailAppliedVersion: true, DetailWidening: true,
		DetailReasons: true, DetailReplayStatus: true, DetailAckNoReplay: true, DetailSource: true,
		DetailForce: true, DetailCapability: true, DetailChanged: true, DetailStatusFrom: true, DetailStatusTo: true, DetailTruncated: true,
	}
	for _, k := range []string{DetailWorkersLacking, DetailKidsAdded, DetailKidsRemoved, DetailJktsAdded, DetailJktsRemoved, DetailGroupsAdded, DetailGroupsRemoved} {
		m[k] = true
		m[k+DetailCountSuffix] = true
		m[k+DetailSha256Suffix] = true
	}
	return m
}()

// FilterDetails returns the entries of d whose key is in the closed detail set
// and whose value is printable ASCII within the value cap. Everything else is
// dropped.
func FilterDetails(d map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range d {
		if annotationKeys[k] && len(v) <= maxDetailValLen && printableASCII(v) {
			out[k] = v
		}
	}
	return out
}

// Annotation is the per-request carrier the admin audit middleware puts in
// the request context. Handlers fill it through Annotate; the middleware reads
// it once the handler returns. It is safe for concurrent use.
type Annotation struct {
	mu        sync.Mutex
	targetRef string
	details   map[string]string
	skip      bool
}

type annotationKey struct{}

// WithAnnotation returns ctx carrying a fresh Annotation, and the Annotation.
func WithAnnotation(ctx context.Context) (context.Context, *Annotation) {
	a := &Annotation{}
	return context.WithValue(ctx, annotationKey{}, a), a
}

// Annotate attaches a non-secret target_ref (for example secret:OPENAI_KEY or
// policy@<etag>) and details to the audit entry of the request ctx belongs
// to. It is a no-op when the request is not audited. A later call replaces
// the target_ref when it is non-empty and merges details. Only the closed
// detail keys (the Detail* constants above) are kept, and a target_ref or value that
// would fail entry validation is dropped rather than failing the row.
func Annotate(ctx context.Context, targetRef string, details map[string]string) {
	a, ok := ctx.Value(annotationKey{}).(*Annotation)
	if !ok || a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if targetRef != "" && len(targetRef) <= maxTargetRefLen && printableASCII(targetRef) {
		a.targetRef = targetRef
	}
	for k, v := range FilterDetails(details) {
		if a.details == nil {
			a.details = map[string]string{}
		}
		a.details[k] = v
	}
}

// Snapshot returns the target_ref and a copy of the details attached so far.
func (a *Annotation) Snapshot() (string, map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.targetRef, copyDetails(a.details)
}

// NoChange tells the middleware the request changed nothing worth recording, so it
// writes no row for it (a repeated, idempotent revoke). It is a no-op when the
// request is not audited. A refusal or a failure must not call it: only a
// request that succeeded without effect may be skipped. The middleware verifies
// the claim against the route's own target only (its state hash must not
// move); a handler that also writes another target must not call NoChange.
func NoChange(ctx context.Context) {
	a, ok := ctx.Value(annotationKey{}).(*Annotation)
	if !ok || a == nil {
		return
	}
	a.mu.Lock()
	a.skip = true
	a.mu.Unlock()
}

// NoChangeClaimed reports whether the handler called NoChange.
func (a *Annotation) NoChangeClaimed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.skip
}
