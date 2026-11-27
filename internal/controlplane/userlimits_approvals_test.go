package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// W-P3-PUL-09 lifts the not-yet-enforced guard for rate limits, so the
// per-user limit keys can now reach a policy version. These tests pin that
// every versioned path carries them: the approvals doc and its digest, the
// gate's classification, publish, rebase merge and the admin audit hash.

func engLimit(rate string) config.UserLimit {
	return config.UserLimit{Name: "eng", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: rate}
}

// The approvals doc carries the three keys in the version doc's shape, so a
// draft's digest equals the version's; without them the digest is unchanged.
func TestUserLimits_DraftDocShape(t *testing.T) {
	w := policyWire{
		Allowlist:        []config.AllowlistEntry{{Domain: "a.com"}},
		Denylist:         []config.DenylistEntry{},
		UserLimits:       []config.UserLimit{engLimit("60/minute")},
		DefaultUserLimit: &config.UserLimit{Name: "default", RateLimit: "600/hour"},
		AnonymousLimit:   &config.UserLimit{Name: "anonymous", RateLimit: "5/minute"},
	}
	got, err := json.Marshal(draftDoc(w))
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("draft doc\n%s\n!= version doc\n%s", got, want)
	}
	if r := redactDraftDoc(draftDoc(w)); len(r.UserLimits) != 1 || r.DefaultUserLimit == nil || r.AnonymousLimit == nil {
		t.Fatalf("redaction dropped the limits: %+v", r)
	}
	plain, _ := json.Marshal(draftDoc(policyWire{Allowlist: w.Allowlist, Denylist: w.Denylist}))
	if string(plain) != `{"allowlist":[{"domain":"a.com","port":0}],"denylist":[]}` {
		t.Errorf("doc without limits = %s", plain)
	}
}

// A save that adds a per-user limit is widening (a rule can move a user to a
// looser budget through precedence), so with approvals on it is held, never
// published unreviewed; applying the held draft publishes the rules.
func TestUserLimits_SaveIsHeldAndApplies(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	ctx := sessionCtx("ada", "ada@example.com")
	head := headVersion(t, srv)
	p := policyOfWire(head.Doc)
	p.UserLimits = []config.UserLimit{engLimit("60/minute")}
	err := srv.WritePolicy(ctx, p, dashboard.WriteMeta{Message: "limit eng"})
	var held *dashboard.HeldForApproval
	if !errors.As(err, &held) {
		t.Fatalf("WritePolicy = %v, want held for approval", err)
	}
	if !held.Widening || !slices.ContainsFunc(held.Reasons, func(r dashboard.ChangeReason) bool {
		return r.Code == approvals.CodeUserLimitsChanged && r.Path == "userLimits"
	}) {
		t.Errorf("held = %+v, want a user_limits.changed reason on userLimits", held)
	}
	if v := headVersion(t, srv); v.Version != head.Version {
		t.Fatalf("head moved to v%d while the change is held", v.Version)
	}
	// The reviewer's diff shows the limit change.
	cd, err := changeDraftAPI{s: srv}.Diff(ctx, held.DraftID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cd.Diff)
	if !strings.Contains(string(raw), `"userLimits":[{"path":"userLimits","kind":"added","after":[{"name":"eng"`) {
		t.Errorf("draft diff does not show the limit change: %s", raw)
	}
	applied, err := srv.Approvals().Apply(sessionCtx("bob", "bob@example.com"), held.DraftID, held.Revision, "bob")
	if err != nil {
		t.Fatal(err)
	}
	v := headVersion(t, srv)
	if v.Version != applied.AppliedVersion || len(v.Doc.UserLimits) != 1 || v.Doc.UserLimits[0].Name != "eng" {
		t.Fatalf("head v%d doc limits = %+v", v.Version, v.Doc.UserLimits)
	}
	if v.DocSHA256 != applied.DocSHA256 {
		t.Errorf("version digest %s != draft digest %s", v.DocSHA256, applied.DocSHA256)
	}
	// The served wire carries the rule.
	w, _, _, _ := srv.policy.snapshot()
	if len(w.UserLimits) != 1 {
		t.Errorf("served wire limits = %+v", w.UserLimits)
	}
}

func TestClassify_UserLimitsChanged(t *testing.T) {
	base := approvals.Doc{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}}
	if c := approvals.Classify(base, base); c.Widening {
		t.Fatalf("no change classified widening: %+v", c)
	}
	// An empty list is the same as an absent one.
	empty := base
	empty.UserLimits = []config.UserLimit{}
	if c := approvals.Classify(base, empty); c.Widening {
		t.Errorf("empty list classified widening: %+v", c)
	}
	draft := base
	draft.UserLimits = []config.UserLimit{engLimit("60/minute")}
	draft.AnonymousLimit = &config.UserLimit{Name: "anonymous", RateLimit: "5/minute"}
	c := approvals.Classify(base, draft)
	var paths []string
	for _, r := range c.Reasons {
		if r.Code == approvals.CodeUserLimitsChanged {
			paths = append(paths, r.Path)
		}
		if strings.Contains(r.Detail, "eng") || strings.Contains(r.Detail, "60") {
			t.Errorf("reason detail carries a rule value: %+v", r)
		}
	}
	if !c.Widening || !slices.Equal(paths, []string{"anonymousLimit", "userLimits"}) {
		t.Errorf("classification = %+v", c)
	}
	// Removing or relaxing a limit is a change too.
	if c := approvals.Classify(draft, base); !c.Widening {
		t.Errorf("removing limits not widening: %+v", c)
	}
}

func TestMergeDocs_UserLimits(t *testing.T) {
	base := approvals.Doc{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}, Denylist: []config.DenylistEntry{}}
	withRule := func(d approvals.Doc, rate string) approvals.Doc {
		d.UserLimits = []config.UserLimit{engLimit(rate)}
		return d
	}
	t.Run("draft only", func(t *testing.T) {
		m, c, err := mergeDocs(base, withRule(base, "1/second"), base)
		if err != nil || len(c) != 0 || len(m.UserLimits) != 1 || m.UserLimits[0].RateLimit != "1/second" {
			t.Fatalf("merged %+v conflicts %v err %v", m.UserLimits, c, err)
		}
	})
	t.Run("head only", func(t *testing.T) {
		head := base
		head.DefaultUserLimit = &config.UserLimit{Name: "default", RateLimit: "9/hour"}
		draft := base
		draft.Allowlist = append(slices.Clone(base.Allowlist), config.AllowlistEntry{Domain: "b.com"})
		m, c, err := mergeDocs(base, draft, head)
		if err != nil || len(c) != 0 || m.DefaultUserLimit == nil || len(m.Allowlist) != 2 {
			t.Fatalf("merged %+v conflicts %v err %v", m, c, err)
		}
	})
	t.Run("same change", func(t *testing.T) {
		m, c, err := mergeDocs(base, withRule(base, "1/second"), withRule(base, "1/second"))
		if err != nil || len(c) != 0 || len(m.UserLimits) != 1 {
			t.Fatalf("merged %+v conflicts %v err %v", m.UserLimits, c, err)
		}
	})
	t.Run("both changed", func(t *testing.T) {
		_, c, err := mergeDocs(base, withRule(base, "1/second"), withRule(base, "2/second"))
		if err != nil || !slices.Equal(c, []string{"userLimits"}) {
			t.Fatalf("conflicts %v err %v, want [userLimits]", c, err)
		}
	})
}

// The admin audit "policy" state hash covers the limit keys, and a policy
// without them hashes exactly as before (the config.Policy encoding).
func TestPolicyStateHash_UserLimits(t *testing.T) {
	w := policyWire{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}, Denylist: []config.DenylistEntry{{Domain: "b.com"}}}
	got, _ := json.Marshal(policyStateOf(w))
	old, _ := json.Marshal(config.Policy{Allowlist: w.Allowlist, Denylist: w.Denylist})
	if !bytes.Equal(got, old) {
		t.Fatalf("state without limits = %s, want the pre-limits encoding %s", got, old)
	}
	e := newOIDCAuditEnv(t)
	ctx := context.Background()
	h1, err := e.srv.audit.stateHash(ctx, "policy")
	if err != nil {
		t.Fatal(err)
	}
	cur, _, _, _ := e.srv.policy.snapshot()
	p := policyOfWire(cur)
	p.UserLimits = []config.UserLimit{engLimit("60/minute")}
	if err := e.srv.WritePolicy(sessionCtx("ada", "ada@example.com"), p, dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	h2, err := e.srv.audit.stateHash(ctx, "policy")
	if err != nil {
		t.Fatal(err)
	}
	p.UserLimits[0].RateLimit = "61/minute"
	if err := e.srv.WritePolicy(sessionCtx("ada", "ada@example.com"), p, dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	h3, _ := e.srv.audit.stateHash(ctx, "policy")
	if h1 == h2 || h2 == h3 {
		t.Errorf("policy hash ignores the limits: %s %s %s", h1, h2, h3)
	}
}

// A versioned head is linted when it is applied (the file is linted on load),
// each warning once, without the per-worker CA warning.
func TestUserLimits_LintServedVersionedHead(t *testing.T) {
	var logs lockedBuffer
	srv := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), &logs)
	ctx := sessionCtx("ada", "ada@example.com")
	if err := srv.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	head := headVersion(t, srv)
	p := policyOfWire(head.Doc)
	p.UserLimits = []config.UserLimit{engLimit("60/minute"), {Name: "eng2", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "10/minute"}}
	if err := srv.WritePolicy(ctx, p, dashboard.WriteMeta{Message: "limits"}); err != nil {
		t.Fatal(err)
	}
	srv.policy.Refresh()
	out := logs.String()
	if n := strings.Count(out, `\"eng\" and \"eng2\" overlap`); n != 1 {
		t.Errorf("overlap warning logged %d times, want 1:\n%s", n, out)
	}
	if strings.Contains(out, "no CA is configured") {
		t.Errorf("CA warning raised on the control plane:\n%s", out)
	}
}

func TestLintPolicyOfWire_IdentityModes(t *testing.T) {
	w := policyWire{
		UserLimits: []config.UserLimit{{Name: "a", Match: config.UserLimitMatch{Agents: []string{"bot"}}, RateLimit: "1/second", DailyCostUSD: 1}},
		Settings: &config.SettingsWire{
			Identity: &config.IdentitySettings{DefaultMode: config.IdentityModeAttribute},
			Agents:   []config.AgentSettings{{ID: "strict", Identity: config.IdentityModeRequire}},
		},
	}
	msgs := config.LintUserLimits(lintPolicyOfWire(w))
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined, `agent "bot" has identity mode "attribute"`) {
		t.Errorf("lint = %v, want the bot identity-mode warning", msgs)
	}
	if strings.Contains(joined, `agent "strict"`) || strings.Contains(joined, "no CA") {
		t.Errorf("lint = %v", msgs)
	}
}

// DiffDocs reports each limit key whole; a diff without limit changes has no
// userLimits section, so its JSON is what it was before the keys existed.
func TestDiffDocs_UserLimits(t *testing.T) {
	base := policyWire{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}}
	d, err := DiffDocs(base, base)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(d); strings.Contains(string(raw), "userLimits") {
		t.Errorf("no-change diff carries userLimits: %s", raw)
	}
	next := base
	next.UserLimits = []config.UserLimit{engLimit("60/minute")}
	next.AnonymousLimit = &config.UserLimit{Name: "anonymous", RateLimit: "5/minute"}
	d, err = DiffDocs(base, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.UserLimits) != 2 || d.UserLimits[0].Path != "anonymousLimit" || d.UserLimits[0].Kind != ChangeAdded ||
		d.UserLimits[1].Path != "userLimits" || d.UserLimits[1].Kind != ChangeAdded {
		t.Fatalf("diff = %+v", d.UserLimits)
	}
	changed := next
	changed.UserLimits = []config.UserLimit{engLimit("61/minute")}
	changed.AnonymousLimit = nil
	d, _ = DiffDocs(next, changed)
	if len(d.UserLimits) != 2 || d.UserLimits[0].Kind != ChangeRemoved || d.UserLimits[1].Kind != ChangeChanged {
		t.Fatalf("diff = %+v", d.UserLimits)
	}
}
