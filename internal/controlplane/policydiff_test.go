package controlplane

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// Credential fingerprints in the redacted-doc form (sha256:<16 hex>). The raw
// value is an obvious canary that must never reach a diff or an error.
const (
	fpOld        = "sha256:0123456789abcdef"
	fpNew        = "sha256:fedcba9876543210"
	rawCanaryKey = "CANARY-raw-secret-access-key-DO-NOT-LEAK"
)

func mustDiff(t *testing.T, a, b policyWire) PolicyDiff {
	t.Helper()
	d, err := DiffDocs(a, b)
	if err != nil {
		t.Fatalf("DiffDocs: %v", err)
	}
	return d
}

func TestPolicyDiffEmpty(t *testing.T) {
	doc := policyWire{
		Allowlist: []config.AllowlistEntry{{Domain: "api.example.com", Port: 443}},
		Denylist:  []config.DenylistEntry{{Domain: "evil.example.com"}},
		Settings:  &config.SettingsWire{Judge: &config.JudgeSettings{Enabled: true, Model: "m1"}},
	}
	d := mustDiff(t, doc, doc)
	if len(d.Allow) != 0 || len(d.Deny) != 0 || len(d.Settings) != 0 {
		t.Fatalf("identical docs: want empty diff, got %+v", d)
	}
	if d := mustDiff(t, policyWire{}, policyWire{}); len(d.Allow)+len(d.Deny)+len(d.Settings) != 0 {
		t.Fatalf("zero docs: want empty diff, got %+v", d)
	}
}

func TestPolicyDiffAllowAddedRemovedChanged(t *testing.T) {
	a := policyWire{Allowlist: []config.AllowlistEntry{
		{Domain: "keep.example.com", Port: 443},
		{Domain: "gone.example.com", Port: 443},
		{Domain: "rl.example.com", Port: 443, RateLimit: "10/m"},
	}}
	b := policyWire{Allowlist: []config.AllowlistEntry{
		{Domain: "rl.example.com", Port: 443, RateLimit: "100/m"},
		{Domain: "keep.example.com", Port: 443},
		{Domain: "new.example.com", Port: 8443},
	}}
	got := mustDiff(t, a, b).Allow
	want := []EntryChange{
		{Key: "gone.example.com|443", Kind: ChangeRemoved, Before: config.AllowlistEntry{Domain: "gone.example.com", Port: 443}, CountBefore: 1, CountAfter: 0},
		{Key: "new.example.com|8443", Kind: ChangeAdded, After: config.AllowlistEntry{Domain: "new.example.com", Port: 8443}, CountBefore: 0, CountAfter: 1},
		{
			Key: "rl.example.com|443", Kind: ChangeChanged,
			Before:      config.AllowlistEntry{Domain: "rl.example.com", Port: 443, RateLimit: "10/m"},
			After:       config.AllowlistEntry{Domain: "rl.example.com", Port: 443, RateLimit: "100/m"},
			CountBefore: 1, CountAfter: 1,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allow diff:\n got %+v\nwant %+v", got, want)
	}
}

func TestPolicyDiffAllowTimeWindowAndConstraintsChanged(t *testing.T) {
	a := policyWire{Allowlist: []config.AllowlistEntry{{Domain: "x.example.com", TimeWindow: "09:00-17:00"}}}
	b := policyWire{Allowlist: []config.AllowlistEntry{{Domain: "x.example.com", TimeWindow: "00:00-23:59"}}}
	got := mustDiff(t, a, b).Allow
	if len(got) != 1 || got[0].Kind != ChangeChanged || got[0].Key != "x.example.com|0" {
		t.Fatalf("timeWindow: want one changed on x.example.com|0, got %+v", got)
	}
	// Methods/paths are compared attributes too: narrowing or widening them on
	// the same domain|port is a change, never a silent no-op.
	c := policyWire{Allowlist: []config.AllowlistEntry{{Domain: "x.example.com", TimeWindow: "09:00-17:00", Methods: []string{"GET"}}}}
	got = mustDiff(t, a, c).Allow
	if len(got) != 1 || got[0].Kind != ChangeChanged {
		t.Fatalf("methods: want one changed, got %+v", got)
	}
}

func TestPolicyDiffDuplicateCounts(t *testing.T) {
	e := config.AllowlistEntry{Domain: "dup.example.com", Port: 443}
	one := policyWire{Allowlist: []config.AllowlistEntry{e}}
	three := policyWire{Allowlist: []config.AllowlistEntry{e, e, e}}

	got := mustDiff(t, one, three).Allow
	want := []EntryChange{
		{Key: "dup.example.com|443", Kind: ChangeAdded, After: e, CountBefore: 1, CountAfter: 3},
		{Key: "dup.example.com|443", Kind: ChangeAdded, After: e, CountBefore: 1, CountAfter: 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("1->3 duplicates:\n got %+v\nwant %+v", got, want)
	}

	got = mustDiff(t, three, one).Allow
	want = []EntryChange{
		{Key: "dup.example.com|443", Kind: ChangeRemoved, Before: e, CountBefore: 3, CountAfter: 1},
		{Key: "dup.example.com|443", Kind: ChangeRemoved, Before: e, CountBefore: 3, CountAfter: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("3->1 duplicates:\n got %+v\nwant %+v", got, want)
	}

	// One of two duplicates gets a rate limit: one changed, the identical copy
	// is matched as unchanged.
	rl := e
	rl.RateLimit = "5/s"
	got = mustDiff(t, policyWire{Allowlist: []config.AllowlistEntry{e, e}}, policyWire{Allowlist: []config.AllowlistEntry{e, rl}}).Allow
	want = []EntryChange{{Key: "dup.example.com|443", Kind: ChangeChanged, Before: e, After: rl, CountBefore: 2, CountAfter: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("one duplicate changed:\n got %+v\nwant %+v", got, want)
	}
}

func TestPolicyDiffDeny(t *testing.T) {
	a := policyWire{Denylist: []config.DenylistEntry{{Domain: "evil.example.com"}, {Domain: "old.example.com", Port: 25}}}
	b := policyWire{Denylist: []config.DenylistEntry{{Domain: "evil.example.com"}, {Domain: "bad.example.com", Port: 443}}}
	got := mustDiff(t, a, b).Deny
	want := []EntryChange{
		{Key: "bad.example.com|443", Kind: ChangeAdded, After: config.DenylistEntry{Domain: "bad.example.com", Port: 443}, CountAfter: 1},
		{Key: "old.example.com|25", Kind: ChangeRemoved, Before: config.DenylistEntry{Domain: "old.example.com", Port: 25}, CountBefore: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("deny diff:\n got %+v\nwant %+v", got, want)
	}
}

func TestPolicyDiffSettingsNested(t *testing.T) {
	ttl := 60
	a := policyWire{Settings: &config.SettingsWire{
		Judge:    &config.JudgeSettings{Enabled: true, Model: "small-model", BaseURL: "https://llm.example.com"},
		Advisory: &config.ToggleSetting{Enabled: true},
		LLMProviders: []config.LLMProviderSettings{
			{Name: "p1", Model: "m"},
		},
	}}
	b := policyWire{Settings: &config.SettingsWire{
		Judge:           &config.JudgeSettings{Enabled: true, Model: "large-model"},
		CacheTTLSeconds: &ttl,
		LLMProviders: []config.LLMProviderSettings{
			{Name: "p1", Model: "m2"},
		},
	}}
	got := mustDiff(t, a, b).Settings
	paths := make([]string, 0, len(got))
	byPath := map[string]PathChange{}
	for _, c := range got {
		paths = append(paths, c.Path+":"+string(c.Kind))
		byPath[c.Path] = c
	}
	wantPaths := []string{
		"settings.advisory:removed",
		"settings.cacheTTLSeconds:added",
		"settings.judge.baseURL:removed",
		"settings.judge.model:changed",
		"settings.llmProviders:changed",
	}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("settings paths:\n got %v\nwant %v", paths, wantPaths)
	}
	if m := byPath["settings.judge.model"]; m.Before != "small-model" || m.After != "large-model" {
		t.Fatalf("judge.model change: got before=%v after=%v", m.Before, m.After)
	}
	if adv := byPath["settings.advisory"]; adv.After != nil || !reflect.DeepEqual(adv.Before, map[string]any{"enabled": true}) {
		t.Fatalf("advisory removed: got %+v", adv)
	}
	// Arrays are compared as one value at their path, not element-wise.
	if lp := byPath["settings.llmProviders"]; reflect.TypeOf(lp.Before).Kind() != reflect.Slice || reflect.TypeOf(lp.After).Kind() != reflect.Slice {
		t.Fatalf("llmProviders should carry whole arrays, got %+v", lp)
	}
}

func TestPolicyDiffSettingsNilToSet(t *testing.T) {
	b := policyWire{Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "m"}}}
	got := mustDiff(t, policyWire{}, b).Settings
	if len(got) != 1 || got[0].Path != "settings.judge" || got[0].Kind != ChangeAdded {
		t.Fatalf("nil->set settings: want one added settings.judge, got %+v", got)
	}
	got = mustDiff(t, b, policyWire{}).Settings
	if len(got) != 1 || got[0].Path != "settings.judge" || got[0].Kind != ChangeRemoved {
		t.Fatalf("set->nil settings: want one removed settings.judge, got %+v", got)
	}
}

func TestPolicyDiffSettingsMapKeyWithDot(t *testing.T) {
	a := policyWire{Settings: &config.SettingsWire{MCP: &config.MCPSettings{Tools: &config.MCPToolsSettings{RateLimit: map[string]string{"files.read": "1/s"}}}}}
	b := policyWire{Settings: &config.SettingsWire{MCP: &config.MCPSettings{Tools: &config.MCPToolsSettings{RateLimit: map[string]string{"files.read": "2/s"}}}}}
	got := mustDiff(t, a, b).Settings
	if len(got) != 1 || got[0].Path != `settings.mcp.tools.rateLimit["files.read"]` || got[0].Kind != ChangeChanged {
		t.Fatalf("dotted map key: got %+v", got)
	}
}

func TestPolicyDiffSecretAccessKeyFingerprint(t *testing.T) {
	sec := func(fp string) policyWire {
		return policyWire{Settings: &config.SettingsWire{Secrets: &config.SecretsSettings{
			Backend: "aws", Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: fp,
		}}}
	}
	got := mustDiff(t, sec(fpOld), sec(fpNew)).Settings
	want := []PathChange{{Path: "settings.secrets.secretAccessKey", Kind: ChangeChanged, Before: fpOld, After: fpNew}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credential rotation:\n got %+v\nwant %+v", got, want)
	}
	// Set and unset are also fingerprint-only.
	got = mustDiff(t, sec(""), sec(fpNew)).Settings
	want = []PathChange{{Path: "settings.secrets.secretAccessKey", Kind: ChangeAdded, After: fpNew}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credential set:\n got %+v\nwant %+v", got, want)
	}
}

func TestPolicyDiffRefusesRawCredential(t *testing.T) {
	raw := policyWire{Settings: &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: rawCanaryKey}}}
	redacted := policyWire{Settings: &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: fpOld}}}
	nearMiss := func(v string) policyWire {
		return policyWire{Settings: &config.SettingsWire{Secrets: &config.SecretsSettings{SecretAccessKey: v}}}
	}
	cases := map[string][2]policyWire{
		"raw in a":         {raw, redacted},
		"raw in b":         {redacted, raw},
		"raw in both":      {raw, raw},
		"raw a, empty b":   {raw, {}},
		"uppercase hex":    {nearMiss("sha256:0123456789ABCDEF"), redacted},
		"short digest":     {redacted, nearMiss("sha256:0123456789abcde")},
		"long digest":      {redacted, nearMiss("sha256:0123456789abcdef0")},
		"wrong prefix":     {nearMiss("sha1:0123456789abcdef"), redacted},
		"non-hex digest":   {nearMiss("sha256:0123456789abcdeg"), redacted},
		"bare hex no algo": {nearMiss("0123456789abcdef"), redacted},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d, err := DiffDocs(c[0], c[1])
			if err == nil {
				t.Fatalf("want error for non-fingerprint credential, got diff %+v", d)
			}
			if strings.Contains(err.Error(), rawCanaryKey) {
				t.Fatalf("error leaks the raw credential: %q", err.Error())
			}
			if !strings.Contains(err.Error(), "settings.secrets.secretAccessKey") {
				t.Fatalf("error should name the credential path, got %q", err.Error())
			}
			if len(d.Allow)+len(d.Deny)+len(d.Settings) != 0 {
				t.Fatalf("a refused diff must be empty, got %+v", d)
			}
		})
	}
}

func TestPolicyDiffDeterministic(t *testing.T) {
	a := policyWire{
		Allowlist: []config.AllowlistEntry{
			{Domain: "a.example.com", Port: 443},
			{Domain: "b.example.com", Port: 443, RateLimit: "1/s"},
			{Domain: "b.example.com", Port: 443, RateLimit: "2/s"},
			{Domain: "c.example.com"},
			{Domain: "c.example.com"},
			{Domain: "d.example.com", Methods: []string{"GET"}},
		},
		Denylist: []config.DenylistEntry{{Domain: "x.example.com"}, {Domain: "y.example.com", Port: 1}, {Domain: "y.example.com", Port: 1}},
		Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "m1"}, DLP: &config.DLPSettings{Classes: map[string]config.DLPClassDefaultSettings{"a": {}, "b": {}}}},
	}
	b := policyWire{
		Allowlist: []config.AllowlistEntry{
			{Domain: "b.example.com", Port: 443, RateLimit: "3/s"},
			{Domain: "b.example.com", Port: 443, RateLimit: "4/s"},
			{Domain: "b.example.com", Port: 443, RateLimit: "5/s"},
			{Domain: "c.example.com"},
			{Domain: "d.example.com", Methods: []string{"POST"}},
			{Domain: "e.example.com", Port: 8080},
		},
		Denylist: []config.DenylistEntry{{Domain: "z.example.com"}, {Domain: "y.example.com", Port: 1}},
		Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "m2"}, DLP: &config.DLPSettings{Classes: map[string]config.DLPClassDefaultSettings{"b": {}, "c": {}}}},
	}
	baseline, err := json.Marshal(mustDiff(t, a, b))
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(457)) // fixed seed: reproducible shuffles
	for i := 0; i < 100; i++ {
		sa, sb := a, b
		sa.Allowlist = shuffled(rng, a.Allowlist)
		sb.Allowlist = shuffled(rng, b.Allowlist)
		sa.Denylist = shuffled(rng, a.Denylist)
		sb.Denylist = shuffled(rng, b.Denylist)
		got, err := json.Marshal(mustDiff(t, sa, sb))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(baseline) {
			t.Fatalf("run %d: output order changed on shuffled input:\n got %s\nwant %s", i, got, baseline)
		}
	}
	// Keys come out sorted.
	d := mustDiff(t, a, b)
	for i := 1; i < len(d.Allow); i++ {
		if d.Allow[i-1].Key > d.Allow[i].Key {
			t.Fatalf("allow not sorted by key: %q before %q", d.Allow[i-1].Key, d.Allow[i].Key)
		}
	}
	for i := 1; i < len(d.Settings); i++ {
		if d.Settings[i-1].Path > d.Settings[i].Path {
			t.Fatalf("settings not sorted by path: %q before %q", d.Settings[i-1].Path, d.Settings[i].Path)
		}
	}
}

func TestPolicyDiffConcurrent(t *testing.T) {
	a := policyWire{Allowlist: []config.AllowlistEntry{{Domain: "a.example.com"}}, Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "m1"}}}
	b := policyWire{Allowlist: []config.AllowlistEntry{{Domain: "b.example.com"}}, Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "m2"}}}
	want := mustDiff(t, a, b)
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := DiffDocs(a, b)
			if err != nil || !reflect.DeepEqual(got, want) {
				errs <- "concurrent diff differs"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func shuffled[T any](rng *rand.Rand, in []T) []T {
	out := append([]T(nil), in...)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// TestPolicyDiffJSONShape pins the serialized shape W-P1-PVER-03 serves, so a
// renamed field or a changed omitempty fails here rather than in a client.
func TestPolicyDiffJSONShape(t *testing.T) {
	a := policyWire{
		Allowlist: []config.AllowlistEntry{{Domain: "a.example.com", Port: 443, RateLimit: "1/s"}},
		Settings:  &config.SettingsWire{Judge: &config.JudgeSettings{Enabled: true, Model: "m1"}},
	}
	b := policyWire{
		Allowlist: []config.AllowlistEntry{{Domain: "a.example.com", Port: 443, RateLimit: "2/s"}},
		Denylist:  []config.DenylistEntry{{Domain: "d.example.com"}},
		Settings:  &config.SettingsWire{Judge: &config.JudgeSettings{Enabled: false, Model: "m1"}},
	}
	got, err := json.Marshal(mustDiff(t, a, b))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"allow":[{"key":"a.example.com|443","kind":"changed",` +
		`"before":{"domain":"a.example.com","port":443,"rateLimit":"1/s"},` +
		`"after":{"domain":"a.example.com","port":443,"rateLimit":"2/s"},"countBefore":1,"countAfter":1}],` +
		`"deny":[{"key":"d.example.com|0","kind":"added","after":{"domain":"d.example.com","port":0},"countBefore":0,"countAfter":1}],` +
		`"settings":[{"path":"settings.judge.enabled","kind":"changed","before":true,"after":false}]}`
	if string(got) != want {
		t.Fatalf("JSON shape:\n got %s\nwant %s", got, want)
	}
	// An empty diff serializes as empty lists, never null.
	empty, err := json.Marshal(mustDiff(t, policyWire{}, policyWire{}))
	if err != nil {
		t.Fatal(err)
	}
	if string(empty) != `{"allow":[],"deny":[],"settings":[]}` {
		t.Fatalf("empty diff JSON: %s", empty)
	}
}

// A scoped entry is a different rule from the global one on the same
// destination (W-P1-GPOL-01): narrowing/widening shows as removed+added keyed
// by scope, not as an in-place "changed", and group order is irrelevant.
func TestPolicyDiffScopedEntryIdentity(t *testing.T) {
	global := config.AllowlistEntry{Domain: "a.example.com", Port: 443}
	scoped := config.AllowlistEntry{Domain: "a.example.com", Port: 443, Groups: []string{"eng", "ops"}}
	reordered := config.AllowlistEntry{Domain: "a.example.com", Port: 443, Groups: []string{"ops", "eng"}}

	got := mustDiff(t, policyWire{Allowlist: []config.AllowlistEntry{global}}, policyWire{Allowlist: []config.AllowlistEntry{scoped}}).Allow
	if len(got) != 2 || got[0].Kind == ChangeChanged || got[1].Kind == ChangeChanged {
		t.Fatalf("global->scoped: want removed+added, got %+v", got)
	}
	kinds := map[ChangeKind]string{}
	for _, c := range got {
		kinds[c.Kind] = c.Key
	}
	if kinds[ChangeRemoved] != "a.example.com|443" || kinds[ChangeAdded] != `a.example.com|443|groups="eng","ops"` {
		t.Fatalf("keys: %+v", kinds)
	}
	if d := mustDiff(t, policyWire{Allowlist: []config.AllowlistEntry{scoped}}, policyWire{Allowlist: []config.AllowlistEntry{reordered}}).Allow; len(d) != 1 || d[0].Kind != ChangeChanged {
		t.Fatalf("reordered groups share a key; the encoded difference is a change, got %+v", d)
	}
}
