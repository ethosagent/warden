package agentregtest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/config"
)

const actor = "admin:suite"

// Run exercises a Store against the registry contract. The store must be
// empty and exclusively the suite's. Subtests use disjoint ids and keys, so
// they do not depend on each other, except the last: it fills the store to
// config.MaxRegisteredAgents and must run after the rest.
func Run(t *testing.T, s agentreg.Store) {
	t.Helper()
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		fn   func(*testing.T, context.Context, agentreg.Store)
	}{
		{"RoundTrip", roundTrip},
		{"NormalizesAndDefaults", normalizes},
		{"InvalidWritesNothing", invalidWritesNothing},
		{"DuplicateID", duplicateID},
		{"KeyInUse", keyInUse},
		{"StaleRevisionConflicts", staleRevision},
		{"UpdateReplacesKeys", updateReplacesKeys},
		{"DisableKeepsRow", disableKeepsRow},
		{"NotFound", notFound},
		{"ResultsAreCopies", resultsAreCopies},
		{"RegistryCap", registryCap}, // last: it fills the store
	} {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, ctx, s) })
	}
}

func base(t *testing.T, id string) agentreg.Agent {
	t.Helper()
	return agentreg.Agent{
		ID:            id,
		AllowedGroups: []string{"eng"},
		Keys:          []agentreg.Key{{JWK: Ed25519JWK(t, id)}},
	}
}

func mustCreate(t *testing.T, ctx context.Context, s agentreg.Store, a agentreg.Agent) agentreg.Agent {
	t.Helper()
	got, err := s.Create(ctx, a, actor)
	if err != nil {
		t.Fatalf("Create(%s): %v", a.ID, err)
	}
	return got
}

func roundTrip(t *testing.T, ctx context.Context, s agentreg.Store) {
	a := agentreg.Agent{
		ID:            "rt:agent-1",
		DisplayName:   "Round Trip",
		OwnerIss:      "https://idp.example",
		OwnerSub:      "sub-1",
		OwnerEmail:    "owner@example.com",
		AllowedGroups: []string{"eng", "ops"},
		AllowedScopes: []string{"repo:read", "tickets.write"},
		Keys: []agentreg.Key{
			{KID: "primary", JWK: Ed25519JWK(t, "rt-a")},
			{JWK: ES256JWK(t)},
		},
	}
	created := mustCreate(t, ctx, s, a)
	if created.Revision != 1 || created.Status != agentreg.StatusActive {
		t.Fatalf("created revision/status = %d/%s, want 1/active", created.Revision, created.Status)
	}
	got, err := s.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got, created) {
		t.Fatalf("Get != Create result:\n got %+v\nwant %+v", got, created)
	}
	if got.CreatedBy != actor || got.UpdatedBy != actor || got.CreatedAt.IsZero() || !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Fatalf("audit fields wrong: %+v", got)
	}
	if got.DisplayName != a.DisplayName || got.OwnerIss != a.OwnerIss || got.OwnerSub != a.OwnerSub ||
		got.OwnerEmail != a.OwnerEmail || !reflect.DeepEqual(got.AllowedGroups, a.AllowedGroups) ||
		!reflect.DeepEqual(got.AllowedScopes, a.AllowedScopes) {
		t.Fatalf("fields did not round-trip: %+v", got)
	}
	if len(got.Keys) != 2 || got.Keys[0].KID != "primary" || got.Keys[0].Alg != "EdDSA" ||
		got.Keys[1].Alg != "ES256" || got.Keys[1].KID != got.Keys[1].JKT {
		t.Fatalf("keys wrong (kid must default to the thumbprint): %+v", got.Keys)
	}
	if tp := agentreg.Thumbprints(got); len(tp) != 2 || tp[0] == tp[1] {
		t.Fatalf("Thumbprints = %v", tp)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !contains(list, a.ID) {
		t.Fatalf("List lacks %s", a.ID)
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].ID >= list[i].ID {
			t.Fatalf("List not ordered by id: %s then %s", list[i-1].ID, list[i].ID)
		}
	}
}

func normalizes(t *testing.T, ctx context.Context, s agentreg.Store) {
	a := base(t, "norm-1")
	a.AllowedGroups = []string{" ops ", "eng", "ops", "eng"}
	a.AllowedScopes = []string{"b", "a", "b"}
	got := mustCreate(t, ctx, s, a)
	if !reflect.DeepEqual(got.AllowedGroups, []string{"eng", "ops"}) || !reflect.DeepEqual(got.AllowedScopes, []string{"a", "b"}) {
		t.Fatalf("not normalized: groups=%v scopes=%v", got.AllowedGroups, got.AllowedScopes)
	}
}

func invalidWritesNothing(t *testing.T, ctx context.Context, s agentreg.Store) {
	a := base(t, "inv-1")
	a.Keys[0].JWK = []byte(strings.Replace(string(a.Keys[0].JWK), `{`, `{"d":"AAAA",`, 1))
	_, err := s.Create(ctx, a, actor)
	var ie *agentreg.InvalidError
	if !errors.Is(err, agentreg.ErrInvalid) || !errors.As(err, &ie) || ie.Field != "keys[0].d" {
		t.Fatalf("Create with d = %v, want ErrInvalid at keys[0].d", err)
	}
	if _, err := s.Get(ctx, a.ID); !errors.Is(err, agentreg.ErrNotFound) {
		t.Fatalf("a rejected Create left a row: %v", err)
	}
}

func duplicateID(t *testing.T, ctx context.Context, s agentreg.Store) {
	mustCreate(t, ctx, s, base(t, "dup-1"))
	other := base(t, "dup-1")
	other.Keys[0].JWK = Ed25519JWK(t, "dup-other")
	if _, err := s.Create(ctx, other, actor); !errors.Is(err, agentreg.ErrAlreadyExists) {
		t.Fatalf("second Create(dup-1) = %v, want ErrAlreadyExists", err)
	}
}

func keyInUse(t *testing.T, ctx context.Context, s agentreg.Store) {
	a := mustCreate(t, ctx, s, base(t, "kiu-a"))
	b := base(t, "kiu-b")
	b.Keys[0].JWK = a.Keys[0].JWK
	if _, err := s.Create(ctx, b, actor); !errors.Is(err, agentreg.ErrKeyInUse) {
		t.Fatalf("Create with A's key = %v, want ErrKeyInUse", err)
	}
	if _, err := s.Get(ctx, "kiu-b"); !errors.Is(err, agentreg.ErrNotFound) {
		t.Fatalf("a refused Create left a row: %v", err)
	}
	gotB := mustCreate(t, ctx, s, func() agentreg.Agent { x := base(t, "kiu-b"); return x }())
	gotB.Keys = append(gotB.Keys, a.Keys[0])
	if _, err := s.Update(ctx, gotB, actor); !errors.Is(err, agentreg.ErrKeyInUse) {
		t.Fatalf("Update adding A's key = %v, want ErrKeyInUse", err)
	}
	// The failed update changed nothing, not even the revision.
	after, err := s.Get(ctx, "kiu-b")
	if err != nil || after.Revision != 1 || len(after.Keys) != 1 {
		t.Fatalf("failed update leaked: %+v, %v", after, err)
	}
	// An agent may keep its own key across an update.
	after.DisplayName = "still mine"
	if _, err := s.Update(ctx, after, actor); err != nil {
		t.Fatalf("Update keeping own key: %v", err)
	}
}

func staleRevision(t *testing.T, ctx context.Context, s agentreg.Store) {
	a := mustCreate(t, ctx, s, base(t, "stale-1"))
	a.DisplayName = "first"
	updated, err := s.Update(ctx, a, actor)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Revision != 2 || updated.DisplayName != "first" {
		t.Fatalf("updated = %+v", updated)
	}
	a.DisplayName = "second" // a still carries revision 1
	if _, err := s.Update(ctx, a, actor); !errors.Is(err, agentreg.ErrConflict) {
		t.Fatalf("stale Update = %v, want ErrConflict", err)
	}
	if _, err := s.SetStatus(ctx, a.ID, agentreg.StatusDisabled, 1, actor); !errors.Is(err, agentreg.ErrConflict) {
		t.Fatalf("stale SetStatus = %v, want ErrConflict", err)
	}
	got, _ := s.Get(ctx, a.ID)
	if got.DisplayName != "first" || got.Status != agentreg.StatusActive || got.Revision != 2 {
		t.Fatalf("a conflicting write changed the agent: %+v", got)
	}
}

func updateReplacesKeys(t *testing.T, ctx context.Context, s agentreg.Store) {
	a := mustCreate(t, ctx, s, base(t, "rot-a"))
	old := a.Keys[0]
	a.Keys = []agentreg.Key{{JWK: Ed25519JWK(t, "rot-new")}}
	a, err := s.Update(ctx, a, actor)
	if err != nil {
		t.Fatalf("Update (rotate): %v", err)
	}
	if len(a.Keys) != 1 || a.Keys[0].JKT == old.JKT {
		t.Fatalf("keys not replaced: %+v", a.Keys)
	}
	// The released key can now belong to a different agent.
	b := base(t, "rot-b")
	b.Keys[0].JWK = old.JWK
	if _, err := s.Create(ctx, b, actor); err != nil {
		t.Fatalf("Create with the released key: %v", err)
	}
}

func disableKeepsRow(t *testing.T, ctx context.Context, s agentreg.Store) {
	a := mustCreate(t, ctx, s, base(t, "dis-1"))
	d, err := s.SetStatus(ctx, a.ID, agentreg.StatusDisabled, a.Revision, "admin:other")
	if err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if d.Status != agentreg.StatusDisabled || d.Revision != 2 || d.UpdatedBy != "admin:other" || d.CreatedBy != actor {
		t.Fatalf("disabled = %+v", d)
	}
	got, err := s.Get(ctx, a.ID)
	if err != nil || got.Status != agentreg.StatusDisabled || len(got.Keys) != 1 {
		t.Fatalf("Get after disable = %+v, %v", got, err)
	}
	list, err := s.List(ctx)
	if err != nil || !contains(list, a.ID) {
		t.Fatalf("List after disable lacks the agent: %v", err)
	}
	// A disabled agent's key stays bound: ids and keys are never recycled.
	b := base(t, "dis-2")
	b.Keys[0].JWK = a.Keys[0].JWK
	if _, err := s.Create(ctx, b, actor); !errors.Is(err, agentreg.ErrKeyInUse) {
		t.Fatalf("a disabled agent's key was reusable: %v", err)
	}
	// Enabling is a status change like any other, but needs groups.
	back, err := s.SetStatus(ctx, a.ID, agentreg.StatusActive, d.Revision, actor)
	if err != nil || back.Status != agentreg.StatusActive || back.Revision != 3 {
		t.Fatalf("re-enable = %+v, %v", back, err)
	}
	empty := base(t, "dis-3")
	empty.Status = agentreg.StatusDisabled
	empty.AllowedGroups = nil
	e := mustCreate(t, ctx, s, empty)
	if _, err := s.SetStatus(ctx, e.ID, agentreg.StatusActive, e.Revision, actor); !errors.Is(err, agentreg.ErrInvalid) {
		t.Fatalf("enabling an agent with no groups = %v, want ErrInvalid", err)
	}
	if _, err := s.SetStatus(ctx, a.ID, "paused", back.Revision, actor); !errors.Is(err, agentreg.ErrInvalid) {
		t.Fatalf("unknown status = %v, want ErrInvalid", err)
	}
}

func notFound(t *testing.T, ctx context.Context, s agentreg.Store) {
	if _, err := s.Get(ctx, "nf-missing"); !errors.Is(err, agentreg.ErrNotFound) {
		t.Fatalf("Get = %v", err)
	}
	a := base(t, "nf-missing")
	a.Revision = 1
	if _, err := s.Update(ctx, a, actor); !errors.Is(err, agentreg.ErrNotFound) {
		t.Fatalf("Update = %v", err)
	}
	if _, err := s.SetStatus(ctx, "nf-missing", agentreg.StatusDisabled, 1, actor); !errors.Is(err, agentreg.ErrNotFound) {
		t.Fatalf("SetStatus = %v", err)
	}
}

func resultsAreCopies(t *testing.T, ctx context.Context, s agentreg.Store) {
	a := mustCreate(t, ctx, s, base(t, "copy-1"))
	a.AllowedGroups[0] = "tampered"
	a.Keys[0].JWK[0] = 'X'
	got, err := s.Get(ctx, "copy-1")
	if err != nil {
		t.Fatal(err)
	}
	got.AllowedGroups[0] = "tampered"
	got.Keys[0].KID = "tampered"
	again, _ := s.Get(ctx, "copy-1")
	if again.AllowedGroups[0] != "eng" || again.Keys[0].KID == "tampered" || again.Keys[0].JWK[0] != '{' {
		t.Fatalf("a caller's mutation reached the store: %+v", again)
	}
}

func registryCap(t *testing.T, ctx context.Context, s agentreg.Store) {
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(list); i < config.MaxRegisteredAgents; i++ {
		mustCreate(t, ctx, s, base(t, fmt.Sprintf("cap-%04d", i)))
	}
	over := base(t, "cap-over")
	if _, err := s.Create(ctx, over, actor); !errors.Is(err, agentreg.ErrRegistryFull) {
		t.Fatalf("Create past the cap = %v, want ErrRegistryFull", err)
	}
	if _, err := s.Get(ctx, "cap-over"); !errors.Is(err, agentreg.ErrNotFound) {
		t.Fatalf("a refused Create left a row: %v", err)
	}
	all, _ := s.List(ctx)
	if len(all) != config.MaxRegisteredAgents {
		t.Fatalf("List has %d agents, want %d", len(all), config.MaxRegisteredAgents)
	}
	// The cap blocks new ids only; existing agents still update.
	first := all[0]
	first.DisplayName = "at the cap"
	if _, err := s.Update(ctx, first, actor); err != nil {
		t.Fatalf("Update at the cap: %v", err)
	}
}

func contains(list []agentreg.Agent, id string) bool {
	for _, a := range list {
		if a.ID == id {
			return true
		}
	}
	return false
}
