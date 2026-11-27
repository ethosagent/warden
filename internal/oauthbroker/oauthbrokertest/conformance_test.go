package oauthbrokertest

import (
	"reflect"
	"testing"

	"github.com/ethosagent/warden/internal/oauthbroker"
)

func TestNamesValue(t *testing.T) {
	for name, want := range map[string]bool{
		"AccessToken": true, "refresh_token": true, "ClientSecret": true, "value_json": true,
		"Password": true, "credentials": true,
		"Verifier": false, "StateHash": false, "grant_id": false, "scopes_json": false, "provider_account_login": false,
	} {
		if got := NamesValue(name); got != want {
			t.Errorf("NamesValue(%q) = %v, want %v", name, got, want)
		}
	}
}

type leaky struct{ RefreshToken string }

type SecretBox struct{}

type holder struct {
	Inner []leaky
	Box   *SecretBox
	When  struct{ ClientSecret string }
}

// TestValueFieldsCatchesNested proves the reflect walk flags nested fields and
// type names, so NoValueFields is not vacuous.
func TestValueFieldsCatchesNested(t *testing.T) {
	typ := reflect.TypeOf(holder{})
	got := ValueFields(typ, typ.PkgPath())
	want := []string{"holder.Inner.RefreshToken", "holder.Box (oauthbrokertest.SecretBox)", "holder.When.ClientSecret"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ValueFields = %q, want %q", got, want)
	}
	if got := ValueFields(reflect.TypeOf(oauthbroker.Grant{}), reflect.TypeOf(oauthbroker.Grant{}).PkgPath()); len(got) != 0 {
		t.Fatalf("Grant has value fields: %v", got)
	}
}

func TestInputsAreValid(t *testing.T) {
	if err := oauthbroker.ValidatePending(NewPending("alice", "google", "email"), ttl); err != nil {
		t.Fatalf("NewPending is invalid: %v", err)
	}
	if err := oauthbroker.ValidateAttempt(NewAttempt("alice", "google", "p", 1)); err != nil {
		t.Fatalf("NewAttempt is invalid: %v", err)
	}
	if UserKey("alice") == UserKey("bob") || len(UserKey("alice")) != 32 {
		t.Fatal("UserKey is not a distinct 32-hex key")
	}
	if got := Received(t, oauthbroker.Closed(oauthbroker.StatusDenied)); got != oauthbroker.StatusDenied {
		t.Fatalf("Received = %q", got)
	}
}
