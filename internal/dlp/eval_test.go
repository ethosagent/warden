package dlp

import (
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/scan"
)

// d2Config is the D2 example from the plan, built as a typed config so the
// precedence tests exercise exactly what an operator would write.
func d2Config() config.DLPConfig {
	return config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Classes: map[string]config.DLPClassDefault{
			"pii.contact": {Action: config.DLPActionRedact},
		},
		Rules: []config.DLPRule{
			{Class: "pii.*", To: []string{"*.zendesk.com"}, Action: config.DLPActionAllow},
			{Class: "pii.*", To: []string{"api.openai.com", "api.anthropic.com", "openrouter.ai"}, Action: config.DLPActionBlock},
			{Class: "source_code", To: []string{"github.com", "*.githubusercontent.com"}, Action: config.DLPActionAllow},
			{Class: "source_code", Action: config.DLPActionBlock},
		},
	}
}

func TestEvaluate_PrecedenceMatrix(t *testing.T) {
	cfg := d2Config()
	tests := []struct {
		name    string
		classes []scan.DataClass
		dest    string
		want    string
	}{
		{"pii to openai blocks", []scan.DataClass{scan.ClassPIIContact}, "api.openai.com", config.DLPActionBlock},
		{"pii to anthropic blocks", []scan.DataClass{scan.ClassPIIFinancial}, "api.anthropic.com", config.DLPActionBlock},
		{"pii to zendesk allows (wildcard dest)", []scan.DataClass{scan.ClassPIIContact}, "foo.zendesk.com", config.DLPActionAllow},
		{"source_code to github allows", []scan.DataClass{scan.ClassSourceCode}, "github.com", config.DLPActionAllow},
		{"source_code to githubusercontent allows (wildcard)", []scan.DataClass{scan.ClassSourceCode}, "raw.githubusercontent.com", config.DLPActionAllow},
		{"source_code elsewhere blocks (class-default rule)", []scan.DataClass{scan.ClassSourceCode}, "evil.example.com", config.DLPActionBlock},
		// pii to a dest no rule mentions: no pii.* rule matches; the dlp.classes
		// default only covers pii.contact. pii.identity → mode default allow.
		{"pii.identity to unlisted dest → mode default allow", []scan.DataClass{scan.ClassPIIIdentity}, "other.example.com", config.DLPActionAllow},
		// pii.contact to a dest no rule mentions → dlp.classes default (redact).
		{"pii.contact to unlisted dest → class default redact", []scan.DataClass{scan.ClassPIIContact}, "other.example.com", config.DLPActionRedact},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.classes, tt.dest, cfg)
			if got.Action != tt.want {
				t.Fatalf("Evaluate(%v, %q) action = %q, want %q (rule %q)", tt.classes, tt.dest, got.Action, tt.want, got.Rule)
			}
		})
	}
}

// Exact destination beats a wildcard destination for the same class.
func TestEvaluate_ExactDestBeatsWildcard(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Rules: []config.DLPRule{
			{Class: "pii.*", To: []string{"*.example.com"}, Action: config.DLPActionBlock},
			{Class: "pii.*", To: []string{"safe.example.com"}, Action: config.DLPActionAllow},
		},
	}
	// safe.example.com matches BOTH: the exact rule (allow) is more specific and wins,
	// even though block is more restrictive — specificity precedes deny-wins.
	if got := Evaluate([]scan.DataClass{scan.ClassPIIContact}, "safe.example.com", cfg); got.Action != config.DLPActionAllow {
		t.Fatalf("exact dest must beat wildcard: got %q (rule %q)", got.Action, got.Rule)
	}
	// other.example.com matches only the wildcard rule → block.
	if got := Evaluate([]scan.DataClass{scan.ClassPIIContact}, "other.example.com", cfg); got.Action != config.DLPActionBlock {
		t.Fatalf("wildcard-only dest should block: got %q", got.Action)
	}
}

// Exact class (pii.contact) beats a class glob (pii.*) at the same destination tier.
func TestEvaluate_ExactClassBeatsGlob(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Rules: []config.DLPRule{
			{Class: "pii.*", Action: config.DLPActionBlock},       // class-default tier, glob class
			{Class: "pii.contact", Action: config.DLPActionAllow}, // class-default tier, exact class
		},
	}
	// Both are class-default (tier 1). Exact class wins over glob → allow, despite
	// block being more restrictive (class specificity breaks the tie before deny-wins).
	if got := Evaluate([]scan.DataClass{scan.ClassPIIContact}, "anywhere.example.com", cfg); got.Action != config.DLPActionAllow {
		t.Fatalf("exact class must beat glob: got %q (rule %q)", got.Action, got.Rule)
	}
	// pii.financial only matches the glob → block.
	if got := Evaluate([]scan.DataClass{scan.ClassPIIFinancial}, "anywhere.example.com", cfg); got.Action != config.DLPActionBlock {
		t.Fatalf("glob applies to pii.financial: got %q", got.Action)
	}
}

// Deny wins on equal specificity (two rules at the same tier, one block one allow).
func TestEvaluate_DenyWinsEqualSpecificity(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Rules: []config.DLPRule{
			{Class: "pii.*", To: []string{"api.openai.com"}, Action: config.DLPActionAllow},
			{Class: "pii.*", To: []string{"api.openai.com"}, Action: config.DLPActionBlock},
		},
	}
	// Same class tier, same exact-dest tier → deny wins regardless of file order.
	if got := Evaluate([]scan.DataClass{scan.ClassPIIContact}, "api.openai.com", cfg); got.Action != config.DLPActionBlock {
		t.Fatalf("deny must win an equal-specificity tie: got %q", got.Action)
	}
}

// Deny wins ACROSS classes: a multi-class body takes the most restrictive action
// among its classes.
func TestEvaluate_DenyWinsAcrossClasses(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Rules: []config.DLPRule{
			{Class: "pii.*", To: []string{"webhook.example.com"}, Action: config.DLPActionAllow},
			{Class: "source_code", Action: config.DLPActionBlock},
		},
	}
	// A body carrying BOTH pii.contact (allow) and source_code (block) to the same
	// dest → block (most restrictive across classes).
	body := []scan.DataClass{scan.ClassPIIContact, scan.ClassSourceCode}
	if got := Evaluate(body, "webhook.example.com", cfg); got.Action != config.DLPActionBlock {
		t.Fatalf("deny must win across classes: got %q (rule %q)", got.Action, got.Rule)
	}
	// Order-independence: reversing the class order yields the same action.
	rev := []scan.DataClass{scan.ClassSourceCode, scan.ClassPIIContact}
	if got := Evaluate(rev, "webhook.example.com", cfg); got.Action != config.DLPActionBlock {
		t.Fatalf("deny-across-classes must be order-independent: got %q", got.Action)
	}
}

// File order of rules does not change the outcome (specificity, not position).
func TestEvaluate_OrderIndependent(t *testing.T) {
	forward := d2Config()
	reversed := d2Config()
	// Reverse the rule slice.
	for i, j := 0, len(reversed.Rules)-1; i < j; i, j = i+1, j-1 {
		reversed.Rules[i], reversed.Rules[j] = reversed.Rules[j], reversed.Rules[i]
	}
	cases := []struct {
		classes []scan.DataClass
		dest    string
	}{
		{[]scan.DataClass{scan.ClassPIIContact}, "api.openai.com"},
		{[]scan.DataClass{scan.ClassPIIContact}, "foo.zendesk.com"},
		{[]scan.DataClass{scan.ClassSourceCode}, "github.com"},
		{[]scan.DataClass{scan.ClassSourceCode}, "evil.example.com"},
	}
	for _, c := range cases {
		a := Evaluate(c.classes, c.dest, forward)
		b := Evaluate(c.classes, c.dest, reversed)
		if a.Action != b.Action {
			t.Fatalf("order changed outcome for %v→%s: %q vs %q", c.classes, c.dest, a.Action, b.Action)
		}
	}
}

// A custom class flows through the same evaluation as built-ins.
func TestEvaluate_CustomClass(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: config.DLPModeEnforce,
		Rules: []config.DLPRule{
			{Class: "custom.project_codename", To: []string{"api.openai.com"}, Action: config.DLPActionBlock},
			{Class: "custom.*", Action: config.DLPActionMonitor},
		},
	}
	if got := Evaluate([]scan.DataClass{"custom.project_codename"}, "api.openai.com", cfg); got.Action != config.DLPActionBlock {
		t.Fatalf("custom class exact dest rule should block: got %q", got.Action)
	}
	if got := Evaluate([]scan.DataClass{"custom.project_codename"}, "elsewhere.example.com", cfg); got.Action != config.DLPActionMonitor {
		t.Fatalf("custom.* class-default should monitor elsewhere: got %q", got.Action)
	}
}

// No classes, or no matching policy, resolves to the allow/default floor.
func TestEvaluate_DefaultFloor(t *testing.T) {
	cfg := d2Config()
	if got := Evaluate(nil, "api.openai.com", cfg); got.Action != config.DLPActionAllow || got.Rule != "default" {
		t.Fatalf("no classes → allow/default, got %q/%q", got.Action, got.Rule)
	}
	// A class no rule addresses → mode default allow.
	if got := Evaluate([]scan.DataClass{scan.ClassInfrastructure}, "api.openai.com", cfg); got.Action != config.DLPActionAllow {
		t.Fatalf("unaddressed class → allow, got %q", got.Action)
	}
}

// The reported Rule id is bounded and points at the winning rule.
func TestEvaluate_RuleIdentifier(t *testing.T) {
	cfg := d2Config()
	// pii.contact to openai: matched by rule[1] (pii.* → block openai).
	got := Evaluate([]scan.DataClass{scan.ClassPIIContact}, "api.openai.com", cfg)
	if got.Rule != "rule[1]" {
		t.Fatalf("expected rule[1], got %q (action %q)", got.Rule, got.Action)
	}
	// pii.contact to an unlisted dest: the dlp.classes default fires.
	got = Evaluate([]scan.DataClass{scan.ClassPIIContact}, "nowhere.example.com", cfg)
	if got.Rule != `classes[pii.contact]` {
		t.Fatalf("expected classes[pii.contact], got %q (action %q)", got.Rule, got.Action)
	}
}
