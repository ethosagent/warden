package fakes_test

import (
	"context"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/identitytest"
	"github.com/ethosagent/warden/test/fakes"
)

func TestVerifierSuite(t *testing.T) {
	identitytest.RunVerifierSuite(t, func(*testing.T) identitytest.Fixture {
		return fakes.VerifierSuiteFixture(fakes.NewVerifier())
	})
}

func TestFakeVerifierConcurrent(t *testing.T) {
	v := fakes.NewVerifier()
	v.Set("t", identity.Claims{Sub: "u"}, identity.StatusValid, "")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v.Set("x", identity.Claims{}, identity.StatusExpired, "")
			if c, st, _ := v.Verify(context.Background(), "t"); st != identity.StatusValid || c.Sub != "u" {
				t.Error("wrong result")
			}
		}()
	}
	wg.Wait()
	if v.Calls() != 50 {
		t.Errorf("calls = %d", v.Calls())
	}
	if _, st, r := v.Verify(context.Background(), "nope"); st != identity.StatusInvalid || r != identity.ReasonMalformed {
		t.Errorf("unknown token: %s/%s", st, r)
	}
}
