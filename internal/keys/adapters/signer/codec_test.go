package signer

import (
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
)

func TestCodecRoundTrip(t *testing.T) {
	var c Codec
	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
		priv, err := c.Generate(alg)
		if err != nil {
			t.Fatalf("%s: Generate: %v", alg, err)
		}
		want, err := c.NewSigner(priv)
		if err != nil {
			t.Fatal(err)
		}
		pem, err := c.Marshal(priv)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Parse(pem)
		if err != nil {
			t.Fatal(err)
		}
		if got.KID() != want.KID() || got.Alg() != alg {
			t.Errorf("%s: parsed %s/%s, want %s/%s", alg, got.KID(), got.Alg(), want.KID(), alg)
		}
	}
	if _, err := c.Generate("RS256"); !errors.Is(err, keys.ErrUnsupportedAlg) {
		t.Errorf("Generate(RS256) = %v", err)
	}
}

// TestCodecErrorsAreTrueNil: a failing Parse or NewSigner returns a nil
// interface, not a typed-nil *LocalSigner that would pass a != nil check.
func TestCodecErrorsAreTrueNil(t *testing.T) {
	var c Codec
	if s, err := c.Parse([]byte("garbage")); err == nil || s != nil {
		t.Errorf("Parse(garbage) = %v, %v", s, err)
	}
	if s, err := c.NewSigner(nil); err == nil || s != nil {
		t.Errorf("NewSigner(nil) = %v, %v", s, err)
	}
}
