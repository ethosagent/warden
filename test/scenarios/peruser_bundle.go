package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/harness"
)

// perUserBundleSections (W-P3-PUS-08): with perUserSecrets enabled the signed
// bundle carries the value-free perUserSecrets section (the mapping and the
// worker cache TTL) and a userGrantEpochs section that starts empty, both under
// the bundle signature; the legacy wire carries neither. A revoke bump parked
// behind a held long poll wakes it with a bundle whose userGrantEpochs holds the
// user key (never the sub) at the new publish-log seq, and a second bump of the
// same user is larger.
func perUserBundleSections(t *testing.T, h *harness.H) {
	cp := h.CP()
	first := bundleSeqOf(t, h, cp.FetchBundle(""), bundle.State{})

	section, err := bundle.ParsePerUserSecrets(first.Bundle.Sections[bundle.SectionPerUserSecrets])
	if err != nil || section == nil {
		t.Fatalf("perUserSecrets section = %v, %v", section, err)
	}
	if section.WorkerCacheTTLSeconds != 300 || len(section.Mappings) != 1 {
		t.Fatalf("perUserSecrets = %+v, want ttl 300 and one mapping", section)
	}
	m := section.Mappings[0]
	if m.Placeholder != harness.PerUserPlaceholder || m.Provider != harness.PerUserProvider ||
		len(m.Domains) != 1 || m.Domains[0] != harness.PerUserDomain ||
		len(m.Agents) != 1 || m.Agents[0] != harness.PerUserAgent ||
		len(m.In) != 1 || m.In[0] != "header" || len(m.Scopes) != 1 {
		t.Errorf("mapping = %+v", m)
	}
	if e, err := bundle.ParseUserGrantEpochs(first.Bundle.Sections[bundle.SectionUserGrantEpochs]); err != nil || e == nil || len(e) != 0 {
		t.Errorf("userGrantEpochs at boot = %v, %v, want present and empty", e, err)
	}
	for _, banned := range []string{h.ConsentVaultToken(), h.ConsentVault().URL(), "client_secret", "refresh"} {
		if strings.Contains(string(first.Bundle.Sections[bundle.SectionPerUserSecrets]), banned) {
			t.Errorf("perUserSecrets section carries %q", banned)
		}
	}

	// The legacy wire never carries them.
	legacy := cp.DoWorker(http.MethodGet, "/policy", cp.Token(), "worker-1", "")
	for _, banned := range []string{"perUserSecrets", "userGrantEpochs", harness.PerUserPlaceholder} {
		if strings.Contains(legacy.Body, banned) {
			t.Errorf("legacy /policy carries %q", banned)
		}
	}

	// A revoke wakes the held long poll with the user's epoch.
	alice, err := secrets.UserKey("https://idp.example.com", "alice-sub")
	if err != nil {
		t.Fatal(err)
	}
	held := cp.HoldBundle(cp.FetchBundle("").Header.Get("ETag"))
	epoch := cp.BumpUserGrant(alice)
	var woke harness.RawResponse
	h.Eventually("the revoke wakes the held long poll", func() bool {
		select {
		case woke = <-held:
			return true
		default:
			return false
		}
	})
	if woke.Status != http.StatusOK {
		t.Fatalf("woken long poll = %d %s", woke.Status, woke.Body)
	}
	got := h.VerifyBundle([]byte(woke.Body), bundleApplied(first))
	epochs, err := bundle.ParseUserGrantEpochs(got.Bundle.Sections[bundle.SectionUserGrantEpochs])
	if err != nil || len(epochs) != 1 || epochs[alice] != epoch || got.Seq != epoch || epoch <= first.Seq {
		t.Fatalf("after the revoke: epochs %v (err %v), bundle seq %d, bump epoch %d, first seq %d", epochs, err, got.Seq, epoch, first.Seq)
	}
	if strings.Contains(woke.Body, "alice-sub") || strings.Contains(string(got.Bundle.Sections[bundle.SectionUserGrantEpochs]), "alice") {
		t.Error("a subject is on the wire")
	}
	if again := cp.BumpUserGrant(alice); again <= epoch {
		t.Errorf("second revoke epoch %d, want above %d", again, epoch)
	}
	if strings.Contains(h.Logs(), alice) {
		t.Error("the user key was logged")
	}
}

// perUserBundleSectionsOff (W-P3-PUS-08): without perUserSecrets the bundle has
// neither section, as before the feature.
func perUserBundleSectionsOff(t *testing.T, h *harness.H) {
	v := bundleSeqOf(t, h, h.CP().FetchBundle(""), bundle.State{})
	for _, name := range []string{bundle.SectionPerUserSecrets, bundle.SectionUserGrantEpochs} {
		if _, ok := v.Bundle.Sections[name]; ok {
			t.Errorf("the bundle has a %s section with per-user secrets off", name)
		}
	}
}
