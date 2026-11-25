package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/harness"
)

// The CP half of agent binding (W-P2-WBND-06). The signed bundle names the
// issuer of the Warden tokens the control plane mints, so a worker verifies
// them against the signed value and never against cpID; the same bundle carries
// the registered agents' key thumbprints, which equal the cnf.jkt of the
// tokens minted for those keys, and a registry change reaches workers as a new
// bundle.

func bundleTokenBindingOpts() []harness.Option {
	return tokenServiceOpts(harness.WithBundles(controlplane.BundlesOffer))
}

// bundleTokenBinding: tokenIssuer is signed and differs from cpID, the served
// jkt matches the minted token's cnf.jkt, and disabling the agent moves the
// served bundle.
func bundleTokenBinding(t *testing.T, h *harness.H) {
	cp := h.CP()
	agent := h.RegisterTokenAgent("bound-agent", []string{"eng"}, []string{"read"})

	first := bundleSeqOf(t, h, cp.FetchBundle(""), bundle.State{})
	if first.Bundle.TokenIssuer != harness.TokenServiceIssuer {
		t.Fatalf("signed tokenIssuer = %q, want %q", first.Bundle.TokenIssuer, harness.TokenServiceIssuer)
	}
	if first.Bundle.TokenIssuer == first.Bundle.CPID {
		t.Fatal("the token issuer must not be the cpID")
	}

	waitTokenKeyPublished(h)
	tr := decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, "user-1", "eng"), nil)))
	hdr, claims := verifyWardenToken(t, h, tr.AccessToken)
	if hdr["typ"] != "wt+jwt" || claims.Iss != first.Bundle.TokenIssuer {
		t.Fatalf("token typ %v iss %q, want wt+jwt and the signed issuer %q", hdr["typ"], claims.Iss, first.Bundle.TokenIssuer)
	}
	if !claims.EmailVerified || claims.Email != "user-1@example.com" {
		t.Errorf("email claims = %q verified=%v", claims.Email, claims.EmailVerified)
	}

	served := servedJKT(t, h, "bound-agent")
	if len(served) != 1 || served[0] != claims.Cnf.JKT {
		t.Fatalf("served jkt %v, minted cnf.jkt %q: they must be the same thumbprint", served, claims.Cnf.JKT)
	}

	// The key thumbprint is the only key material in the envelope.
	raw := string(cp.FetchBundle("").Body)
	if strings.Contains(raw, "PRIVATE") || strings.Contains(raw, `"d":`) {
		t.Error("private key material in the bundle")
	}

	// Replacing the key of the (still enabled) agent moves the signed bundle:
	// the old thumbprint is gone from the signed registeredAgents and the new
	// one is there, so a token bound to the old key no longer matches.
	oldJKT := served[0]
	etag := cp.FetchBundle("").Header.Get("ETag")
	h.RotateTokenAgentKey("bound-agent")
	var rotated bundle.Verified
	h.Eventually("the served bundle moves after the agent key is replaced", func() bool {
		h.Clock().Advance(3 * time.Second)
		r := cp.FetchBundle(etag)
		if r.Status != http.StatusOK {
			return false
		}
		rotated = bundleSeqOf(t, h, r, bundleApplied(first))
		return rotated.Seq > first.Seq
	})
	now := servedJKT(t, h, "bound-agent")
	if len(now) != 1 || now[0] == oldJKT {
		t.Fatalf("signed jkt after the key replacement = %v, the old thumbprint %s must be gone", now, oldJKT)
	}
	first = rotated

	// A disable moves it again.
	etag = cp.FetchBundle("").Header.Get("ETag")
	h.DisableTokenAgent("bound-agent")
	var after bundle.Verified
	h.Eventually("the served bundle moves after the agent is disabled", func() bool {
		h.Clock().Advance(3 * time.Second)
		r := cp.FetchBundle(etag)
		if r.Status != http.StatusOK {
			return false
		}
		after = bundleSeqOf(t, h, r, bundleApplied(first))
		return after.Seq > first.Seq
	})
	if after.Bundle.TokenIssuer != first.Bundle.TokenIssuer {
		t.Errorf("tokenIssuer changed with the registry: %q", after.Bundle.TokenIssuer)
	}
	var wire struct {
		Agents []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"registeredAgents"`
	}
	if err := json.Unmarshal(after.Bundle.Policy, &wire); err != nil || len(wire.Agents) != 1 || wire.Agents[0].Status != "disabled" {
		t.Errorf("registeredAgents after the disable = %+v (%v)", wire.Agents, err)
	}
}

// servedJKT returns the thumbprints the signed bundle lists for agent id.
func servedJKT(t *testing.T, h *harness.H, id string) []string {
	t.Helper()
	v := bundleSeqOf(t, h, h.CP().FetchBundle(""), bundle.State{})
	var wire struct {
		Agents []struct {
			ID  string   `json:"id"`
			JKT []string `json:"jkt"`
		} `json:"registeredAgents"`
	}
	if err := json.Unmarshal(v.Bundle.Policy, &wire); err != nil {
		t.Fatal(err)
	}
	for _, a := range wire.Agents {
		if a.ID == id {
			return a.JKT
		}
	}
	t.Fatalf("agent %s is not in the signed bundle", id)
	return nil
}

// bundleNoTokenIssuerWithoutService: with no token service the bundle has no
// tokenIssuer (the member is omitted), and a worker has nothing to verify
// Warden tokens against.
func bundleNoTokenIssuerWithoutService(t *testing.T, h *harness.H) {
	v := bundleSeqOf(t, h, h.CP().FetchBundle(""), bundle.State{})
	if v.Bundle.TokenIssuer != "" || strings.Contains(string(h.CP().FetchBundle("").Body), "tokenIssuer") {
		t.Fatalf("tokenIssuer = %q without a token service", v.Bundle.TokenIssuer)
	}
}
