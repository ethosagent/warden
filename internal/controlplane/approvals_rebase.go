package controlplane

// approvals_rebase.go is the three-way merge behind POST .../rebase
// (W-P2-APPR-04): the draft's change (the W-P1-PVER-09 difference between its
// base version and its doc) replayed onto the live head. Entries are keyed by
// DiffKey and settings by path, exactly as DiffDocs sees them, so "a key
// changed on both sides" means what the diff view shows.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
)

// mergeDocs applies the change from base to draft onto head. It returns the
// merged doc, or the keys and paths that changed on both sides to different
// results (empty conflicts when the merge is clean). All three docs must be
// credential-redacted.
func mergeDocs(base, draft, head approvals.Doc) (approvals.Doc, []string, error) {
	var conflicts []string
	allow, c, err := mergeEntries(base.Allowlist, draft.Allowlist, head.Allowlist, "allow")
	if err != nil {
		return approvals.Doc{}, nil, err
	}
	conflicts = append(conflicts, c...)
	deny, c, err := mergeEntries(base.Denylist, draft.Denylist, head.Denylist, "deny")
	if err != nil {
		return approvals.Doc{}, nil, err
	}
	conflicts = append(conflicts, c...)
	settings, c, err := mergeSettings(base.Settings, draft.Settings, head.Settings)
	if err != nil {
		return approvals.Doc{}, nil, err
	}
	conflicts = append(conflicts, c...)
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return approvals.Doc{}, slices.Compact(conflicts), nil
	}
	return approvals.Doc{Allowlist: allow, Denylist: deny, Settings: settings}, nil, nil
}

// entryGroup is the entries of one DiffKey in the three docs, as sorted
// canonical encodings (a multiset) plus the entries themselves.
type entryGroup[E diffKeyed] struct {
	base, draft, head []string
	draftEntries      []E
}

func encodeEntries[E diffKeyed](es []E) ([]string, error) {
	out := make([]string, len(es))
	for i, e := range es {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, fmt.Errorf("rebase: encode entry: %w", err)
		}
		out[i] = string(b)
	}
	sort.Strings(out)
	return out, nil
}

func mergeEntries[E diffKeyed](base, draft, head []E, list string) ([]E, []string, error) {
	groups := map[string]*entryGroup[E]{}
	group := func(k string) *entryGroup[E] {
		g := groups[k]
		if g == nil {
			g = &entryGroup[E]{}
			groups[k] = g
		}
		return g
	}
	byKey := func(es []E) map[string][]E {
		m := map[string][]E{}
		for _, e := range es {
			m[e.DiffKey()] = append(m[e.DiffKey()], e)
		}
		return m
	}
	bk, dk, hk := byKey(base), byKey(draft), byKey(head)
	for _, m := range []map[string][]E{bk, dk, hk} {
		for k := range m {
			group(k)
		}
	}
	var err error
	for k, g := range groups {
		if g.base, err = encodeEntries(bk[k]); err != nil {
			return nil, nil, err
		}
		if g.draft, err = encodeEntries(dk[k]); err != nil {
			return nil, nil, err
		}
		if g.head, err = encodeEntries(hk[k]); err != nil {
			return nil, nil, err
		}
		g.draftEntries = dk[k]
	}

	replace := map[string]bool{}
	var conflicts []string
	for k, g := range groups {
		switch {
		case slices.Equal(g.base, g.draft):
			// The draft left this key alone: head's entries stand.
		case slices.Equal(g.base, g.head):
			replace[k] = true
		case slices.Equal(g.draft, g.head):
			// Both sides made the same change.
		default:
			conflicts = append(conflicts, list+":"+k)
		}
	}

	var out []E
	emitted := map[string]bool{}
	for _, e := range head {
		k := e.DiffKey()
		if !replace[k] {
			out = append(out, e)
			continue
		}
		if !emitted[k] {
			emitted[k] = true
			out = append(out, groups[k].draftEntries...)
		}
	}
	for _, e := range draft {
		if k := e.DiffKey(); replace[k] && !emitted[k] {
			emitted[k] = true
			out = append(out, groups[k].draftEntries...)
		}
	}
	return out, conflicts, nil
}

// mergeSettings is a three-way merge of the settings trees by path. Arrays
// and scalars are compared whole at their path, as DiffDocs does.
func mergeSettings(base, draft, head *config.SettingsWire) (*config.SettingsWire, []string, error) {
	bt, err := settingsTree(base)
	if err != nil {
		return nil, nil, err
	}
	dt, err := settingsTree(draft)
	if err != nil {
		return nil, nil, err
	}
	ht, err := settingsTree(head)
	if err != nil {
		return nil, nil, err
	}
	var conflicts []string
	merged := mergeTree("settings", bt, dt, ht, &conflicts)
	if len(conflicts) > 0 {
		return nil, conflicts, nil
	}
	if len(merged) == 0 {
		return nil, nil, nil
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return nil, nil, fmt.Errorf("rebase: encode merged settings: %w", err)
	}
	var out config.SettingsWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("rebase: decode merged settings: %w", err)
	}
	return &out, nil, nil
}

// mergeTree merges three JSON objects key by key. A key the draft left alone
// keeps head's value; a key only the draft changed takes the draft's; a key
// changed on both sides to different results is a conflict at its path.
func mergeTree(path string, base, draft, head map[string]any, conflicts *[]string) map[string]any {
	out := map[string]any{}
	keys := map[string]struct{}{}
	for _, m := range []map[string]any{base, draft, head} {
		for k := range m {
			keys[k] = struct{}{}
		}
	}
	for k := range keys {
		bv, bok := base[k]
		dv, dok := draft[k]
		hv, hok := head[k]
		set := func(v any, ok bool) {
			if ok {
				out[k] = v
			}
		}
		same := func(av any, aok bool, cv any, cok bool) bool {
			return aok == cok && (!aok || reflect.DeepEqual(av, cv))
		}
		switch {
		case same(bv, bok, dv, dok):
			set(hv, hok)
		case same(bv, bok, hv, hok):
			set(dv, dok)
		case same(dv, dok, hv, hok):
			set(hv, hok)
		default:
			dm, dIsMap := dv.(map[string]any)
			hm, hIsMap := hv.(map[string]any)
			bm, bIsMap := bv.(map[string]any)
			if dIsMap && hIsMap && (bIsMap || !bok) {
				if merged := mergeTree(path+pathSegment(k), bm, dm, hm, conflicts); len(merged) > 0 {
					out[k] = merged
				}
				continue
			}
			*conflicts = append(*conflicts, path+pathSegment(k))
		}
	}
	return out
}

// conflictList is a conflict path list for a response, capped so a wide
// conflict cannot make a large body.
func conflictList(c []string) []string {
	const maxListed = 50
	if len(c) > maxListed {
		c = c[:maxListed]
	}
	for i, p := range c {
		c[i] = strings.TrimSpace(p)
	}
	return c
}
