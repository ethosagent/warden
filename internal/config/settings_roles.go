package config

import (
	"slices"
	"strings"
)

// Per-field console roles for settings writes (W-P1-SSO-10). A settings write
// in oidc mode needs at least editor; an editor may change only the fields
// below. Every other SettingsWire field (llmProviders, secrets, explore, judge,
// observability, mcp, identity, and any field added later) needs admin, because
// those decide where workers send real credentials. Later features add
// admin-only fields by appending to settingsAdminSubfields; a new top-level
// field is admin-only without any change here.

// settingsEditorFields are the top-level SettingsWire JSON keys an editor may
// change.
var settingsEditorFields = []string{"advisory", "agents", "cacheTTLSeconds", "compliance", "dlp", "logging"}

// settingsAdminSubfields are fields inside an editor list that still need
// admin, written "<list>[].<field>". The list's elements are matched by their
// "id" field when deciding what changed.
var settingsAdminSubfields = []string{"agents[].identity"}

// EditorSettingsFields returns the top-level settings fields an editor may
// change, sorted.
func EditorSettingsFields() []string {
	out := slices.Clone(settingsEditorFields)
	slices.Sort(out)
	return out
}

// AdminSettingsSubfields returns the "<list>[].<field>" paths inside editor
// fields that need admin, sorted.
func AdminSettingsSubfields() []string {
	out := slices.Clone(settingsAdminSubfields)
	slices.Sort(out)
	return out
}

// SettingsListsByID returns the top-level settings lists that hold an
// admin-only subfield. A change diff compares their elements by "id" so that
// moving or renaming an element cannot carry an admin-only value to another
// element unnoticed.
func SettingsListsByID() []string {
	var out []string
	for _, p := range settingsAdminSubfields {
		list, _, _ := strings.Cut(p, "[].")
		if !slices.Contains(out, list) {
			out = append(out, list)
		}
	}
	slices.Sort(out)
	return out
}

// SettingsFieldMinRole returns the lowest role that may change the settings
// field at path. path is a top-level JSON key ("dlp") or an element field of a
// list ("agents[2].identity"). Anything not granted to editor needs admin.
func SettingsFieldMinRole(path string) Role {
	top, rest := path, ""
	if i := strings.IndexAny(path, "[."); i >= 0 {
		top, rest = path[:i], path[i:]
	}
	if !slices.Contains(settingsEditorFields, top) {
		return RoleAdmin
	}
	if rest == "" {
		return RoleEditor
	}
	// rest is "[<n>].<field>" for a list element field; anything else is not a
	// shape the diff produces, so it fails closed.
	if !strings.HasPrefix(rest, "[") {
		return RoleAdmin
	}
	idx, field, ok := strings.Cut(rest[1:], "].")
	if !ok || idx == "" || strings.Trim(idx, "0123456789") != "" ||
		field == "" || strings.ContainsAny(field, ".[") {
		return RoleAdmin
	}
	if slices.Contains(settingsAdminSubfields, top+"[]."+field) {
		return RoleAdmin
	}
	return RoleEditor
}
