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
)

// The agent registry's keys (W-P2-AREG-02): which fields a write changed, the
// key ids and groups it added and removed (comma separated) and the status
// before and after. They name fields, key ids and groups; never key material.
const (
	DetailChanged       = "changed"
	DetailKidsAdded     = "kids_added"
	DetailKidsRemoved   = "kids_removed"
	DetailGroupsAdded   = "groups_added"
	DetailGroupsRemoved = "groups_removed"
	DetailStatusFrom    = "status_from"
	DetailStatusTo      = "status_to"
)

var annotationKeys = map[string]bool{
	DetailOp: true, DetailEtag: true, DetailHasSub: true, DetailHasEmail: true,
	DetailChanged: true, DetailKidsAdded: true, DetailKidsRemoved: true,
	DetailGroupsAdded: true, DetailGroupsRemoved: true,
	DetailStatusFrom: true, DetailStatusTo: true,
}

// Annotation is the per-request carrier the admin audit middleware puts in
// the request context. Handlers fill it through Annotate; the middleware reads
// it once the handler returns. It is safe for concurrent use.
type Annotation struct {
	mu        sync.Mutex
	targetRef string
	details   map[string]string
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
// detail keys (DetailOp, DetailEtag, DetailHasSub, DetailHasEmail) are kept, and a target_ref or value that
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
