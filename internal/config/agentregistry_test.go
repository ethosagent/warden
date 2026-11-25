package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeGroups(t *testing.T) {
	got, err := NormalizeGroups([]string{" eng ", "Eng", "eng", "ops"})
	if err != nil {
		t.Fatalf("NormalizeGroups: %v", err)
	}
	if want := []string{"Eng", "eng", "ops"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, err := NormalizeGroups(nil); err != nil || got != nil {
		t.Fatalf("nil in = %v, %v", got, err)
	}
	for name, in := range map[string][]string{
		"empty value": {"a", "  "},
		"too long":    {strings.Repeat("g", 257)},
	} {
		if _, err := NormalizeGroups(in); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
