package controlplane

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

const challengePolicyYAML = "policy:\n  allowlist:\n    - domain: plain.example.com\n" +
	"identity:\n  defaultMode: challenge\n  issuer: https://idp.example.com\n  audience: warden\n"

func challengeRows(t *testing.T, url string) map[string]bool {
	t.Helper()
	resp, err := http.Get(url + "/dashboard/api/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var rows []fleetRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range rows {
		out[r.ProxyID] = r.NoIdentityChallenge
	}
	return out
}

// TestHeartbeat_FlagsWorkersWithoutIdentityChallenge: while challenge mode is
// served, a worker without identity/challenge-v1 (an old one, or one that sends
// no caps) is flagged, a current one is not; with no challenge served nothing is.
func TestHeartbeat_FlagsWorkersWithoutIdentityChallenge(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy string
		want   map[string]bool
	}{
		{"challenge as the default mode", challengePolicyYAML, map[string]bool{"new": false, "other": true, "legacy": true}},
		{"challenge on one agent only", "policy:\n  allowlist:\n    - domain: plain.example.com\nagents:\n  - id: a\n    identity: challenge\n" +
			"identity:\n  issuer: https://idp.example.com\n  audience: warden\n", map[string]bool{"new": false, "other": true, "legacy": true}},
		{"attribute mode", "policy:\n  allowlist:\n    - domain: plain.example.com\nidentity:\n  defaultMode: attribute\n  issuer: https://idp.example.com\n  audience: warden\n",
			map[string]bool{"new": false, "other": false, "legacy": false}},
		{"no identity block", "policy:\n  allowlist:\n    - domain: plain.example.com\n", map[string]bool{"new": false, "other": false, "legacy": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(Config{PolicyPath: writeScopedPolicy(t, tc.policy)})
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()
			postHeartbeat(t, ts.URL, "new", `{"policyETag":"x","caps":["identity/challenge-v1"]}`)
			postHeartbeat(t, ts.URL, "other", `{"policyETag":"x","caps":["blocklist/v1","grouppolicy/v1"]}`)
			postHeartbeat(t, ts.URL, "legacy", `{"policyETag":"x"}`)
			got := challengeRows(t, ts.URL)
			for id, want := range tc.want {
				if got[id] != want {
					t.Errorf("%s noIdentityChallenge = %v, want %v", id, got[id], want)
				}
			}
		})
	}
}

// TestWorkerLacksIdentityChallengeLogOnce: one warning per worker per ETag, with
// the proxy id and nothing else, and a new ETag warns again.
func TestWorkerLacksIdentityChallengeLogOnce(t *testing.T) {
	buf := &lockedBuf{}
	path := writeScopedPolicy(t, challengePolicyYAML)
	srv := New(Config{PolicyPath: path, Logger: slog.New(slog.NewTextHandler(buf, nil))})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	count := func() int { return strings.Count(buf.String(), "msg=worker_lacks_identity_challenge") }

	for range 3 {
		postHeartbeat(t, ts.URL, "old", `{"policyETag":"x"}`)
	}
	postHeartbeat(t, ts.URL, "ok", `{"caps":["identity/challenge-v1"]}`)
	if n := count(); n != 1 {
		t.Fatalf("log lines = %d, want 1\n%s", n, buf.String())
	}
	if out := buf.String(); !strings.Contains(out, "proxy_id=old") || strings.Contains(out, "idp.example.com") {
		t.Errorf("unexpected fields: %s", out)
	}
	more := strings.Replace(challengePolicyYAML, "    - domain: plain.example.com\n", "    - domain: plain.example.com\n    - domain: more.example.com\n", 1)
	if err := os.WriteFile(path, []byte(more), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.policy.Refresh()
	for range 2 {
		postHeartbeat(t, ts.URL, "old", `{"policyETag":"x"}`)
	}
	if n := count(); n != 2 {
		t.Fatalf("after a new etag log lines = %d, want 2\n%s", n, buf.String())
	}
}

// TestServesChallengeMode: the control plane accepts challenge and the signIn
// block in its served settings and passes them to workers unchanged.
func TestServesChallengeMode(t *testing.T) {
	yaml := challengePolicyYAML + "  signIn:\n    clientID: warden-cli\n    maxPending: 5\n    startsPerMinute: 7\n    scopes: [openid, email]\n"
	srv := New(Config{PolicyPath: writeScopedPolicy(t, yaml)})
	wire, _, ok, _ := srv.policy.snapshot()
	if !ok || wire.Settings == nil || wire.Settings.Identity == nil {
		t.Fatalf("no identity settings served: %+v", wire.Settings)
	}
	id := wire.Settings.Identity
	if id.DefaultMode != config.IdentityModeChallenge || id.SignIn == nil || id.SignIn.MaxPending != 5 ||
		id.SignIn.StartsPerMinute != 7 || id.SignIn.ClientID != "warden-cli" || len(id.SignIn.Scopes) != 2 {
		t.Fatalf("served identity = %+v signIn %+v", id, id.SignIn)
	}
	if !challengeServedWire(wire) {
		t.Error("challengeServedWire is false for a served challenge mode")
	}
}

func TestNewIdentityYAMLKeepsSignIn(t *testing.T) {
	in := config.IdentitySettings{DefaultMode: "challenge", Issuer: "https://i.example.com", Audience: "warden",
		SignIn: &config.SignInSettings{ClientID: "c", Scopes: []string{"openid"}, MaxPending: 2, StartsPerMinute: 3}}
	out := newIdentityYAML(in)
	if out.SignIn == nil || out.SignIn.ClientID != "c" || out.SignIn.MaxPending != 2 || out.SignIn.StartsPerMinute != 3 || out.DefaultMode != "challenge" {
		t.Fatalf("newIdentityYAML = %+v signIn %+v", out, out.SignIn)
	}
	if bare := newIdentityYAML(config.IdentitySettings{DefaultMode: "attribute"}); bare.SignIn != nil {
		t.Error("an absent signIn block must stay absent")
	}
}
