package controlplane

// Structural policy diff (W-P1-PVER-09). DiffDocs says what a policy change did
// in terms of entries and settings paths, not lines of text, so the history API
// (W-P1-PVER-03), the history panel (W-P1-PVER-04) and approvals' widening
// classification (W-P2-APPR-02) share one definition of "what changed".
//
// It is a pure function: no I/O, no clock, no logging, no shared state, so it is
// safe for concurrent use and its work is bounded by the size of the two docs.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/internal/config"
)

// ChangeKind classifies one entry or settings-path change.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"   // only in the newer doc (b)
	ChangeRemoved ChangeKind = "removed" // only in the older doc (a)
	ChangeChanged ChangeKind = "changed" // in both, with different attributes or value
)

// PolicyDiff is the structural difference between two policy docs. Every list
// is sorted (entries by DiffKey, settings by path) so the output is stable.
type PolicyDiff struct {
	Allow    []EntryChange `json:"allow"`
	Deny     []EntryChange `json:"deny"`
	Settings []PathChange  `json:"settings"`
}

// EntryChange is one allow or deny entry occurrence that differs. Lists are
// multisets keyed by DiffKey: an extra duplicate is one "added" change and
// CountBefore/CountAfter give the key's occurrence count in each doc, so a
// duplicate shows as a count change. Before/After hold the entry
// (config.AllowlistEntry or config.DenylistEntry); Before is nil for "added"
// and After is nil for "removed".
type EntryChange struct {
	Key         string     `json:"key"`
	Kind        ChangeKind `json:"kind"`
	Before      any        `json:"before,omitempty"`
	After       any        `json:"after,omitempty"`
	CountBefore int        `json:"countBefore"`
	CountAfter  int        `json:"countAfter"`
}

// PathChange is one settings value that differs, addressed by its JSON path
// (e.g. "settings.judge.model"). Arrays are compared as one value at their
// path. Before is nil for "added" and After is nil for "removed".
type PathChange struct {
	Path   string     `json:"path"`
	Kind   ChangeKind `json:"kind"`
	Before any        `json:"before,omitempty"`
	After  any        `json:"after,omitempty"`
}

// credentialPaths are the settings paths (relative to "settings") that hold a
// credential. In a redacted doc they carry only a fingerprint (see
// isRedactedCredential), and DiffDocs refuses a doc where they do not.
var credentialPaths = [][]string{{"secrets", "secretAccessKey"}}

// DiffDocs returns the structural diff from a (older) to b (newer). Both docs
// must be redacted: a non-fingerprint value at a credential path in either doc
// returns an error that names the path but never the value.
func DiffDocs(a, b policyWire) (PolicyDiff, error) {
	sa, err := settingsTree(a.Settings)
	if err != nil {
		return PolicyDiff{}, err
	}
	sb, err := settingsTree(b.Settings)
	if err != nil {
		return PolicyDiff{}, err
	}
	if err := checkRedacted("a", sa); err != nil {
		return PolicyDiff{}, err
	}
	if err := checkRedacted("b", sb); err != nil {
		return PolicyDiff{}, err
	}

	allow, err := diffEntries(a.Allowlist, b.Allowlist)
	if err != nil {
		return PolicyDiff{}, err
	}
	deny, err := diffEntries(a.Denylist, b.Denylist)
	if err != nil {
		return PolicyDiff{}, err
	}
	settings := []PathChange{}
	walkSettings("settings", sa, sb, &settings)
	sort.Slice(settings, func(i, j int) bool { return settings[i].Path < settings[j].Path })
	return PolicyDiff{Allow: allow, Deny: deny, Settings: settings}, nil
}

// diffKeyed is an allow or deny entry type.
type diffKeyed interface {
	config.AllowlistEntry | config.DenylistEntry
	DiffKey() string
}

// keyedEntry is an entry with its canonical encoding, used for equality and
// for a deterministic order among entries that share a key.
type keyedEntry[E diffKeyed] struct {
	entry E
	enc   string
}

// diffEntries compares two entry lists as multisets keyed by DiffKey. Within a
// key, identical entries cancel out; the unmatched rest pair up as "changed"
// and any surplus is "added" (only in b) or "removed" (only in a).
func diffEntries[E diffKeyed](a, b []E) ([]EntryChange, error) {
	type side struct{ a, b []keyedEntry[E] }
	groups := map[string]*side{}
	add := func(list []E, inA bool) error {
		for _, e := range list {
			enc, err := json.Marshal(e)
			if err != nil {
				return fmt.Errorf("policy diff: encode entry: %w", err)
			}
			k := e.DiffKey()
			g := groups[k]
			if g == nil {
				g = &side{}
				groups[k] = g
			}
			if inA {
				g.a = append(g.a, keyedEntry[E]{e, string(enc)})
			} else {
				g.b = append(g.b, keyedEntry[E]{e, string(enc)})
			}
		}
		return nil
	}
	if err := add(a, true); err != nil {
		return nil, err
	}
	if err := add(b, false); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := []EntryChange{}
	for _, k := range keys {
		g := groups[k]
		byEnc := func(s []keyedEntry[E]) {
			sort.SliceStable(s, func(i, j int) bool { return s[i].enc < s[j].enc })
		}
		byEnc(g.a)
		byEnc(g.b)
		// Cancel identical entries (sorted merge), keeping the unmatched rest.
		var ra, rb []keyedEntry[E]
		i, j := 0, 0
		for i < len(g.a) && j < len(g.b) {
			switch {
			case g.a[i].enc == g.b[j].enc:
				i++
				j++
			case g.a[i].enc < g.b[j].enc:
				ra = append(ra, g.a[i])
				i++
			default:
				rb = append(rb, g.b[j])
				j++
			}
		}
		ra = append(ra, g.a[i:]...)
		rb = append(rb, g.b[j:]...)

		ca, cb := len(g.a), len(g.b)
		n := min(len(ra), len(rb))
		for _, r := range ra[n:] {
			out = append(out, EntryChange{Key: k, Kind: ChangeRemoved, Before: r.entry, CountBefore: ca, CountAfter: cb})
		}
		for x := 0; x < n; x++ {
			out = append(out, EntryChange{Key: k, Kind: ChangeChanged, Before: ra[x].entry, After: rb[x].entry, CountBefore: ca, CountAfter: cb})
		}
		for _, r := range rb[n:] {
			out = append(out, EntryChange{Key: k, Kind: ChangeAdded, After: r.entry, CountBefore: ca, CountAfter: cb})
		}
	}
	return out, nil
}

// settingsTree turns the settings document into a generic JSON map (numbers
// kept as json.Number) so it can be walked by path. Absent settings are an
// empty map, so a block appearing shows as per-block additions.
func settingsTree(s *config.SettingsWire) (map[string]any, error) {
	if s == nil {
		return map[string]any{}, nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("policy diff: encode settings: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("policy diff: decode settings: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// checkRedacted refuses a doc whose credential paths hold anything but a
// fingerprint. The error names the path and the doc, never the value.
func checkRedacted(which string, tree map[string]any) error {
	for _, p := range credentialPaths {
		v, ok := lookupPath(tree, p)
		if !ok {
			continue
		}
		if s, isStr := v.(string); isStr && isRedactedCredential(s) {
			continue
		}
		return fmt.Errorf("policy diff: settings.%s in doc %s is not a credential fingerprint; only redacted docs can be diffed",
			strings.Join(p, "."), which)
	}
	return nil
}

func lookupPath(tree map[string]any, path []string) (any, bool) {
	var cur any = tree
	for _, seg := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// walkSettings compares two JSON objects key by key, recursing into nested
// objects. Any other value (string, number, bool, array, null) is compared as a
// whole at its path.
func walkSettings(path string, a, b map[string]any, out *[]PathChange) {
	for k, av := range a {
		p := path + pathSegment(k)
		bv, inB := b[k]
		if !inB {
			*out = append(*out, PathChange{Path: p, Kind: ChangeRemoved, Before: av})
			continue
		}
		am, aIsMap := av.(map[string]any)
		bm, bIsMap := bv.(map[string]any)
		switch {
		case aIsMap && bIsMap:
			walkSettings(p, am, bm, out)
		case !reflect.DeepEqual(av, bv):
			*out = append(*out, PathChange{Path: p, Kind: ChangeChanged, Before: av, After: bv})
		}
	}
	for k, bv := range b {
		if _, inA := a[k]; !inA {
			*out = append(*out, PathChange{Path: path + pathSegment(k), Kind: ChangeAdded, After: bv})
		}
	}
}

// pathSegment renders one key of a settings path: ".key" for a plain
// identifier, otherwise a quoted `["key"]` so map keys containing dots (an MCP
// tool name, a DLP class) cannot be confused with nesting.
func pathSegment(k string) string {
	plain := k != ""
	for _, c := range k {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			plain = false
			break
		}
	}
	if plain {
		return "." + k
	}
	return "[" + strconv.Quote(k) + "]"
}
