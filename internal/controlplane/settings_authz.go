package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// writeSettingsAs is the dashboard's context-aware settings writer.
//
// In console.auth none it is WriteSettings unchanged: the bearer write guard
// already ran. In oidc mode the caller's role is recomputed from the current
// console config: below editor is refused, admin writes anything, and an editor
// write is applied only when every field it changes is an editor field
// (config.SettingsFieldMinRole). The check runs under writeMu against the
// settings on disk, so a concurrent admin edit cannot slip between the check
// and the write. A refusal is a *dashboard.RoleRequiredError naming the fields.
func (s *Server) writeSettingsAs(ctx context.Context, in config.SettingsWire, meta dashboard.WriteMeta) error {
	if s.cfg.Console.Auth != config.ConsoleAuthOIDC {
		return s.WriteSettings(ctx, in, meta)
	}
	var role config.Role
	p, ok := PrincipalFrom(ctx)
	if ok {
		role = principalRole(s.cfg.Console, p)
	}
	if role < config.RoleEditor {
		return &dashboard.RoleRequiredError{Need: config.RoleEditor.String()}
	}
	if role >= config.RoleAdmin {
		return s.WriteSettings(ctx, in, meta)
	}
	return s.writeSettingsChecked(ctx, in, meta, func(live *config.SettingsWire) error {
		changed, err := settingsWireFieldsChanged(live, in)
		if err != nil {
			return fmt.Errorf("controlplane: compare settings: %w", err)
		}
		var need config.Role
		var denied []string
		for _, f := range changed {
			if minRole := config.SettingsFieldMinRole(f); minRole > role {
				denied = append(denied, f)
				need = max(need, minRole)
			}
		}
		if len(denied) == 0 {
			return nil
		}
		// Field names only: never a value.
		s.cfg.Logger.Warn("console_settings_field_denied", "role", role.String(), "need", need.String(),
			"sub", p.Sub, "fields", denied)
		return &dashboard.RoleRequiredError{Need: need.String(), Fields: denied}
	})
}

// settingsWireFieldsChanged reports the fields in differs from live in, after
// putting both into the form WriteSettings would persist: a document the
// dashboard read and posts back unchanged reports nothing.
func settingsWireFieldsChanged(live *config.SettingsWire, in config.SettingsWire) ([]string, error) {
	var l config.SettingsWire
	if live != nil {
		l = *live
	}
	l, in = normalizeSettingsForDiff(l, l), normalizeSettingsForDiff(in, l)
	a, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	return settingsFieldsChanged(a, b)
}

// normalizeSettingsForDiff mirrors WriteSettings' persistence rules so two
// documents that write the same config compare equal. live supplies the values
// a nil field keeps and the aws secret an empty secretAccessKey preserves. It
// copies before it changes anything, so neither input is modified.
func normalizeSettingsForDiff(w, live config.SettingsWire) config.SettingsWire {
	// A disabled mcp, judge or observability block is deleted on disk.
	if w.MCP != nil && !w.MCP.Enabled {
		w.MCP = nil
	}
	if w.Judge != nil && !w.Judge.Enabled {
		w.Judge = nil
	}
	if w.Observability != nil && !w.Observability.Enabled {
		w.Observability = nil
	}
	if w.Explore != nil && w.Explore.LLMProvider == "" {
		w.Explore = nil
	}
	// The env selector deletes secretStore; an access key id with an empty secret
	// keeps the secret on disk (the dashboard never echoes it).
	if w.Secrets != nil {
		if config.SecretStoreConfigFromSettings(w.Secrets).ResolvedBackend() == config.SecretBackendEnv {
			w.Secrets = nil
		} else if w.Secrets.AccessKeyID != "" && w.Secrets.SecretAccessKey == "" && live.Secrets != nil {
			sec := *w.Secrets
			sec.SecretAccessKey = live.Secrets.SecretAccessKey
			w.Secrets = &sec
		}
	}
	// A nil logging, cache TTL or compliance leaves that block untouched.
	if w.Logging == nil {
		w.Logging = live.Logging
	}
	if w.CacheTTLSeconds == nil {
		w.CacheTTLSeconds = live.CacheTTLSeconds
	}
	if w.Compliance == nil {
		w.Compliance = live.Compliance
	}
	return w
}

// settingsFieldsChanged compares two settings documents (SettingsWire JSON) and
// returns the sorted field paths whose values differ. A top-level key is
// reported by name ("dlp", "llmProviders", or a key added later); any key
// present on only one side counts. The lists in config.SettingsListsByID are
// compared element field by element field, matching elements by "id", and
// reported as "<list>[<i>].<field>" with i the element's index in in (or in
// live when in no longer has it). Matching by id means a reorder is no change
// but swapping ids moves each admin-only value to another element and is
// reported. Elements sharing an id are compared in order.
func settingsFieldsChanged(live, in []byte) ([]string, error) {
	l, err := topLevel(live)
	if err != nil {
		return nil, fmt.Errorf("live settings: %w", err)
	}
	n, err := topLevel(in)
	if err != nil {
		return nil, fmt.Errorf("new settings: %w", err)
	}
	byID := config.SettingsListsByID()
	var out []string
	for _, key := range unionKeys(l, n) {
		if slices.Contains(byID, key) {
			fields, err := listFieldsChanged(key, l[key], n[key])
			if err != nil {
				return nil, err
			}
			out = append(out, fields...)
			continue
		}
		eq, err := jsonEqual(l[key], n[key])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if !eq {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out, nil
}

// topLevel decodes a settings document into its top-level keys. JSON null (no
// settings) is an empty document.
func topLevel(doc []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// listElem is one element of a list compared by id, with its index.
type listElem struct {
	idx    int
	fields map[string]json.RawMessage
}

// listFieldsChanged diffs the list key element field by element field, with
// elements grouped by id.
func listFieldsChanged(key string, live, in json.RawMessage) ([]string, error) {
	lg, lorder, err := groupByID(live)
	if err != nil {
		return nil, fmt.Errorf("live %s: %w", key, err)
	}
	ng, norder, err := groupByID(in)
	if err != nil {
		return nil, fmt.Errorf("new %s: %w", key, err)
	}
	ids := slices.Clone(norder)
	for _, id := range lorder {
		if _, ok := ng[id]; !ok {
			ids = append(ids, id)
		}
	}
	var out []string
	for _, id := range ids {
		le, ne := lg[id], ng[id]
		// Report at the first index the id has in the new list, else in the old.
		at := ne
		if len(at) == 0 {
			at = le
		}
		prefix := key + "[" + strconv.Itoa(at[0].idx) + "]."
		var names []map[string]json.RawMessage
		for _, e := range append(slices.Clone(le), ne...) {
			names = append(names, e.fields)
		}
		for _, field := range unionKeys(names...) {
			changed := len(le) != len(ne)
			for i := 0; !changed && i < len(le); i++ {
				eq, err := jsonEqual(le[i].fields[field], ne[i].fields[field])
				if err != nil {
					return nil, fmt.Errorf("%s%s: %w", prefix, field, err)
				}
				changed = !eq
			}
			// An element present on one side only differs in every field it has.
			if changed {
				out = append(out, prefix+field)
			}
		}
	}
	return out, nil
}

// groupByID decodes a JSON array of objects and groups its elements by their
// "id" value (raw JSON, so a missing id groups as ""), returning the ids in
// first-seen order.
func groupByID(raw json.RawMessage) (map[string][]listElem, []string, error) {
	groups := map[string][]listElem{}
	var order []string
	if len(raw) == 0 {
		return groups, nil, nil
	}
	var elems []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, nil, err
	}
	for i, e := range elems {
		id := string(e["id"])
		if _, seen := groups[id]; !seen {
			order = append(order, id)
		}
		groups[id] = append(groups[id], listElem{idx: i, fields: e})
	}
	return groups, order, nil
}

// unionKeys returns the sorted union of the maps' keys.
func unionKeys(ms ...map[string]json.RawMessage) []string {
	var keys []string
	for _, m := range ms {
		for k := range m {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	slices.Sort(keys)
	return keys
}

// jsonEqual compares two JSON values semantically (object key order and
// spacing do not matter). An absent value equals only another absent value.
func jsonEqual(a, b json.RawMessage) (bool, error) {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b), nil
	}
	ca, err := canonicalJSON(a)
	if err != nil {
		return false, err
	}
	cb, err := canonicalJSON(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ca, cb), nil
}

func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
