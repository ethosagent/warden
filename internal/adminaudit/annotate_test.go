package adminaudit

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestAnnotate(t *testing.T) {
	// Without a carrier it is a no-op.
	Annotate(context.Background(), "secret:K", map[string]string{DetailOp: "put"})

	ctx, a := WithAnnotation(context.Background())
	Annotate(ctx, "secret:K", map[string]string{DetailOp: "put", "value": "s3cr3t", "authorization": "Bearer x"})
	ref, d := a.Snapshot()
	if ref != "secret:K" || len(d) != 1 || d[DetailOp] != "put" {
		t.Fatalf("Snapshot = %q %v, want secret:K and only op", ref, d)
	}
	// A later call merges details and replaces a non-empty ref; an empty ref keeps the old one.
	Annotate(ctx, "", map[string]string{DetailEtag: "abc"})
	Annotate(ctx, "policy@abc", nil)
	if ref, d = a.Snapshot(); ref != "policy@abc" || d[DetailEtag] != "abc" || d[DetailOp] != "put" {
		t.Fatalf("after merge = %q %v", ref, d)
	}
	// Invalid refs and values are dropped, not stored.
	Annotate(ctx, "secret:bad\nref", map[string]string{DetailOp: strings.Repeat("x", maxDetailValLen+1)})
	Annotate(ctx, strings.Repeat("r", maxTargetRefLen+1), map[string]string{DetailEtag: "café"})
	if ref, d = a.Snapshot(); ref != "policy@abc" || d[DetailOp] != "put" || d[DetailEtag] != "abc" {
		t.Fatalf("invalid input changed the annotation: %q %v", ref, d)
	}
	// Snapshot returns a copy.
	d[DetailOp] = "mutated"
	if _, d2 := a.Snapshot(); d2[DetailOp] != "put" {
		t.Fatal("Snapshot shares its map")
	}
	// An annotated entry passes validation.
	e := Entry{AuthMethod: AuthMethodOIDC, Outcome: OutcomeOK, Action: "policy.write", TargetRef: ref, Details: d}
	if err := e.validate(); err != nil {
		t.Fatalf("annotated entry invalid: %v", err)
	}
}

func TestAnnotateConcurrent(t *testing.T) {
	ctx, a := WithAnnotation(context.Background())
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Annotate(ctx, "secret:K", map[string]string{DetailOp: "put"})
			_, _ = a.Snapshot()
		}()
	}
	wg.Wait()
	if ref, _ := a.Snapshot(); ref != "secret:K" {
		t.Fatalf("ref = %q", ref)
	}
}
