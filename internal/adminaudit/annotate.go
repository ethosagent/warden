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
)

var annotationKeys = map[string]bool{DetailOp: true, DetailEtag: true, DetailHasSub: true, DetailHasEmail: true, DetailAPIKeyID: true, DetailScopes: true, DetailExpiresAt: true, DetailAPIKeysRevoked: true}

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
// detail keys (DetailOp, DetailEtag, DetailHasSub, DetailHasEmail, DetailAPIKeyID) are kept, and a target_ref or value that
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
	for k, v := range details {
		if !annotationKeys[k] || len(v) > maxDetailValLen || !printableASCII(v) {
			continue
		}
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

// Skip tells the middleware the request changed nothing worth recording, so it
// writes no row for it (a repeated, idempotent revoke). It is a no-op when the
// request is not audited. A refusal or a failure must not call it: only a
// request that succeeded without effect may be skipped. The middleware verifies
// the claim against the route's own target only (its state hash must not
// move); a handler that also writes another target must not call Skip.
func Skip(ctx context.Context) {
	a, ok := ctx.Value(annotationKey{}).(*Annotation)
	if !ok || a == nil {
		return
	}
	a.mu.Lock()
	a.skip = true
	a.mu.Unlock()
}

// Skipped reports whether the handler called Skip.
func (a *Annotation) Skipped() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.skip
}
