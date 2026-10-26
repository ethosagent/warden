package harness

import (
	"net/http"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
)

// TestWithIdentity: the option boots a worker that verifies against the issuer
// fake, so a token from MintUserToken is attributed (event and signed receipt),
// one for another audience is not, and the same block is what the control plane
// distributes.
func TestWithIdentity(t *testing.T) {
	h := New(t, WithIdentity(config.IdentityModeAttribute))
	h.Upstream("api.example.com")
	if h.Issuer() == nil {
		t.Fatal("WithIdentity does not imply the issuer fake")
	}

	get := func(path, tok string) {
		t.Helper()
		resp, err := h.AgentWithProxyToken(tok).Get("https://api.example.com" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}
	get("/ok", h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng")))
	get("/other", h.MintUserToken(fakes.WrongAudience()))

	evs := h.Events()
	if len(evs) != 2 {
		t.Fatalf("%d events, want 2", len(evs))
	}
	for _, e := range evs {
		switch e.URL {
		case "https://api.example.com/ok":
			if e.IdentityStatus != "valid" || e.UserSub != "alice" || e.UserEmail != "alice@example.com" {
				t.Errorf("valid token: status %q sub %q email %q", e.IdentityStatus, e.UserSub, e.UserEmail)
			}
		case "https://api.example.com/other":
			if e.IdentityStatus != "invalid" || e.IdentityReason != "wrong_aud" || e.UserSub != "" {
				t.Errorf("wrong audience: status %q reason %q sub %q", e.IdentityStatus, e.IdentityReason, e.UserSub)
			}
		}
	}
	if rs := h.Receipts(); len(rs) != 2 {
		t.Errorf("%d signed receipts, want 2", len(rs))
	}

	var cur struct {
		Settings *config.SettingsWire `json:"settings"`
	}
	if err := h.CP().GetJSON("/dashboard/api/settings", &cur); err != nil {
		t.Fatal(err)
	}
	id := cur.Settings.Identity
	if id == nil || id.DefaultMode != config.IdentityModeAttribute || id.Issuer != h.Issuer().Issuer() ||
		id.InternalIssuerURL != h.Issuer().Issuer() || id.Audience != IdentityAudience {
		t.Errorf("distributed identity block = %+v, want attribute mode against the fake issuer", id)
	}
}
