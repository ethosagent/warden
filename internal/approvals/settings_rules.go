package approvals

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/ethosagent/warden/internal/config"
)

// The settings rule table: the ONLY settings changes that are not widening.
// Everything else (judge, llmProviders, secrets, explore, observability, mcp,
// identity, agents, dlp.mode and any field added later) is widening with code
// settings.changed, so a new field can never slip through as narrowing.

// enabledToggles are the settings blocks whose "enabled" flag going from
// false (or absent) to true only turns a protection on.
var enabledToggles = []string{"advisory", "compliance", "dlp"}

// isNeutralPath reports whether any change at path is neutral: the logging
// knobs and the secret cache TTL do not change what agents can reach or where
// credentials go.
func isNeutralPath(path string) bool {
	return path == "logging" || strings.HasPrefix(path, "logging.") || path == "cacheTTLSeconds"
}

// isNarrowingToggle reports whether the change at path switches an enabled
// toggle from false (or absent) to true.
func isNarrowingToggle(path string, base, draft any, baseHas bool) bool {
	for _, t := range enabledToggles {
		if path != t+".enabled" {
			continue
		}
		on, ok := draft.(bool)
		if !ok || !on {
			return false
		}
		if !baseHas {
			return true
		}
		was, ok := base.(bool)
		return ok && !was
	}
	return false
}

// settingsChange is one settings path that differs between two docs.
type settingsChange struct {
	Path string
	Kind string // "added", "removed" or "changed"
}

// settingsMap marshals settings to the generic JSON map the walker compares.
// A nil settings is the empty map.
func settingsMap(s *config.SettingsWire) (map[string]any, error) {
	m := map[string]any{}
	if s == nil {
		return m, nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// flatten records every leaf of v under prefix. Objects recurse; arrays,
// scalars and empty objects are leaves compared whole at their path.
func flatten(prefix string, v any, out map[string]any) {
	if m, ok := v.(map[string]any); ok && len(m) > 0 {
		for k, c := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, c, out)
		}
		return
	}
	out[prefix] = v
}

// diffSettings returns the changed leaf paths between two settings maps,
// sorted, excluding those the rule table allows. admin reports whether any
// change needs an admin approver.
func diffSettings(base, draft map[string]any) (changes []settingsChange, admin bool) {
	bf, df := map[string]any{}, map[string]any{}
	for k, v := range base {
		flatten(k, v, bf)
	}
	for k, v := range draft {
		flatten(k, v, df)
	}
	paths := make([]string, 0, len(bf)+len(df))
	for p := range bf {
		paths = append(paths, p)
	}
	for p := range df {
		if _, ok := bf[p]; !ok {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		bv, bok := bf[p]
		dv, dok := df[p]
		if bok && dok && reflect.DeepEqual(bv, dv) {
			continue
		}
		// A role is needed for every changed path, even a neutral one: an
		// editor field never raises it, an unknown field raises it to admin.
		// (a nested path is judged by its top-level field; agents[].identity
		// is handled per element below).
		top, _, _ := strings.Cut(p, ".")
		if config.SettingsFieldMinRole(top) == config.RoleAdmin {
			admin = true
		}
		if isNeutralPath(p) || isNarrowingToggle(p, bv, dv, bok) {
			continue
		}
		kind := "changed"
		switch {
		case !bok:
			kind = "added"
		case !dok:
			kind = "removed"
		}
		changes = append(changes, settingsChange{Path: p, Kind: kind})
	}
	if !admin {
		admin = adminSubfieldChanged(base, draft)
	}
	return changes, admin
}

// adminSubfieldChanged reports whether an element of a settings list changed
// in a field only an admin may change (agents[].identity today). Elements are
// matched by "id", as the settings authz does, so reordering cannot hide a
// change. A list whose elements lack a usable id fails closed when it differs.
func adminSubfieldChanged(base, draft map[string]any) bool {
	for _, list := range config.SettingsListsByID() {
		bl, _ := base[list].([]any)
		dl, _ := draft[list].([]any)
		if reflect.DeepEqual(bl, dl) {
			continue
		}
		var fields []string
		for _, p := range config.AdminSettingsSubfields() {
			if l, f, ok := strings.Cut(p, "[]."); ok && l == list {
				fields = append(fields, f)
			}
		}
		bi, ok1 := elementsByID(bl)
		di, ok2 := elementsByID(dl)
		if !ok1 || !ok2 {
			return true
		}
		for id, be := range bi {
			de, ok := di[id]
			if !ok {
				de = nil
			}
			if subfieldsDiffer(be, de, fields) {
				return true
			}
		}
		for id, de := range di {
			if _, ok := bi[id]; !ok && subfieldsDiffer(nil, de, fields) {
				return true
			}
		}
	}
	return false
}

func elementsByID(l []any) (map[string]map[string]any, bool) {
	out := make(map[string]map[string]any, len(l))
	for _, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		id, ok := m["id"].(string)
		if !ok || id == "" {
			return nil, false
		}
		if _, dup := out[id]; dup {
			return nil, false
		}
		out[id] = m
	}
	return out, true
}

func subfieldsDiffer(a, b map[string]any, fields []string) bool {
	for _, f := range fields {
		av, aok := a[f]
		bv, bok := b[f]
		if aok != bok || !reflect.DeepEqual(av, bv) {
			return true
		}
	}
	return false
}
