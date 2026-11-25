package agentregtest

import (
	"bytes"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
)

func TestFixtureKeys(t *testing.T) {
	a, b := Ed25519JWK(t, "same"), Ed25519JWK(t, "same")
	if !bytes.Equal(a, b) {
		t.Fatal("the same name must give the same key")
	}
	if bytes.Equal(a, Ed25519JWK(t, "other")) {
		t.Fatal("different names must give different keys")
	}
	for name, doc := range map[string][]byte{"ed25519": a, "es256": ES256JWK(t)} {
		if _, err := keys.ParseJWK(doc); err != nil {
			t.Errorf("%s fixture is not a valid public jwk: %v", name, err)
		}
	}
}
