package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// snapshot renders a policy for comparison. It is deliberately blind to nil vs
// empty slices (DeepCopy turns an empty list into nil), which are the same
// policy; reflect.DeepEqual would report that as a difference.
func snapshot(t *testing.T, p Policy) string {
	t.Helper()
	b, err := yaml.Marshal(p)
	if err != nil {
		t.Fatalf("cannot render policy: %v", err)
	}
	return string(b)
}

// FuzzConfigLoad feeds arbitrary bytes to the YAML config loader. Properties:
//   - it never panics and never hangs (aliases, deep nesting, huge scalars);
//   - it is deterministic: the same bytes give the same verdict and policy;
//   - a config it accepts hands out a policy that survives a deep copy intact and
//     whose copy shares no memory with the original (so a later caller cannot
//     widen the live allowlist by mutating a copy).
func FuzzConfigLoad(f *testing.F) {
	// Seeds live in testdata/fuzz/FuzzConfigLoad: valid configs, near-misses
	// (bad ports, regexes, windows, unknown fields) and hostile YAML (alias
	// bombs, tags, multi-document streams, tabs, BOM).
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parse(data)
		p2, err2 := parse(data)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("parse is not deterministic (%v vs %v) for %q", err, err2, data)
		}
		if err != nil {
			return
		}
		pol, perr := p.GetPolicy()
		if perr != nil {
			t.Fatalf("accepted config but GetPolicy failed: %v", perr)
		}
		pol2, _ := p2.GetPolicy()
		want := snapshot(t, pol)
		if want != snapshot(t, pol2) {
			t.Fatalf("parse is not deterministic for %q", data)
		}
		cp := pol.DeepCopy()
		if want != snapshot(t, cp) {
			t.Fatalf("DeepCopy changed the policy for %q", data)
		}
		for i := range cp.Allowlist {
			cp.Allowlist[i].Domain = "mutated.test"
		}
		for i := range cp.Denylist {
			cp.Denylist[i].Domain = "mutated.test"
		}
		after, _ := p.GetPolicy()
		if want != snapshot(t, after) {
			t.Fatalf("mutating a copy changed the live policy for %q", data)
		}
	})
}
