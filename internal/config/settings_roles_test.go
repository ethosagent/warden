package config

import (
	"slices"
	"testing"
)

func TestSettingsFieldMinRole(t *testing.T) {
	cases := map[string]Role{
		"advisory":                  RoleEditor,
		"agents":                    RoleEditor,
		"cacheTTLSeconds":           RoleEditor,
		"compliance":                RoleEditor,
		"dlp":                       RoleEditor,
		"logging":                   RoleEditor,
		"agents[0].policy":          RoleEditor,
		"agents[12].id":             RoleEditor,
		"agents[0].identity":        RoleAdmin,
		"llmProviders":              RoleAdmin,
		"secrets":                   RoleAdmin,
		"explore":                   RoleAdmin,
		"judge":                     RoleAdmin,
		"observability":             RoleAdmin,
		"mcp":                       RoleAdmin,
		"identity":                  RoleAdmin,
		"someFieldAddedLater":       RoleAdmin,
		"llmProviders[0].baseURL":   RoleAdmin,
		"dlp.mode":                  RoleAdmin, // not a shape the diff emits: fail closed
		"agents[].policy":           RoleAdmin,
		"agents[x].policy":          RoleAdmin,
		"agents[0]":                 RoleAdmin,
		"agents[0].":                RoleAdmin,
		"":                          RoleAdmin,
		"Agents":                    RoleAdmin, // exact, case-sensitive
		"agents[0].identity.nested": RoleAdmin,
	}
	for path, want := range cases {
		if got := SettingsFieldMinRole(path); got != want {
			t.Errorf("SettingsFieldMinRole(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestSettingsFieldSets(t *testing.T) {
	if got, want := EditorSettingsFields(), []string{"advisory", "agents", "cacheTTLSeconds", "compliance", "dlp", "logging"}; !slices.Equal(got, want) {
		t.Errorf("EditorSettingsFields() = %v, want %v", got, want)
	}
	if got, want := AdminSettingsSubfields(), []string{"agents[].identity"}; !slices.Equal(got, want) {
		t.Errorf("AdminSettingsSubfields() = %v, want %v", got, want)
	}
	if got, want := SettingsListsByID(), []string{"agents"}; !slices.Equal(got, want) {
		t.Errorf("SettingsListsByID() = %v, want %v", got, want)
	}
	// The returned slices are copies: a caller cannot widen the editor set.
	EditorSettingsFields()[0] = "secrets"
	if SettingsFieldMinRole("secrets") != RoleAdmin {
		t.Fatal("mutating the returned slice changed the editor set")
	}
}
