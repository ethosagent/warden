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

// annotationKeys is the closed set of keys Annotate keeps.
var annotationKeys = func() map[string]bool {
	m := map[string]bool{
		DetailOp: true, DetailEtag: true, DetailHasSub: true, DetailHasEmail: true,
		DetailChanged: true, DetailStatusFrom: true, DetailStatusTo: true, DetailTruncated: true,
	}
	for _, k := range []string{DetailKidsAdded, DetailKidsRemoved, DetailJktsAdded, DetailJktsRemoved, DetailGroupsAdded, DetailGroupsRemoved} {
		m[k] = true
		m[k+DetailCountSuffix] = true
		m[k+DetailSha256Suffix] = true
	}
	return m
}()

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
// Detail* keys are kept, and a target_ref or value that would fail entry
// validation is dropped rather than failing the row.
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
