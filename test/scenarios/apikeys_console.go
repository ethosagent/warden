package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Console API Keys tab (W-P2-APIK-04): the bootstrap payload the page reads
// (/dashboard/api/setup) carries the scope -> minimum role list and the TTL
// bounds only when console.apiKeys is on, and the tab's markup is served.

type setupAPIKeys struct {
	APIKeys *struct {
		Scopes []struct {
			Name    string `json:"name"`
			MinRole string `json:"minRole"`
		} `json:"scopes"`
		DefaultTTL int64 `json:"defaultTTLSeconds"`
		MaxTTL     int64 `json:"maxTTLSeconds"`
	} `json:"apiKeys"`
}

func consoleGet(t *testing.T, h *harness.H, login fakes.MintOption, path string) string {
	t.Helper()
	b, _ := consoleLogin(t, h, login)
	resp, err := b.DoBody(http.MethodGet, path, nil, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", path, resp.StatusCode)
	}
	return string(data)
}

// apiKeyConsoleBootstrap: with keys on, the setup payload lists every
// registered scope with its minimum role (what the create dialog filters by the
// signed-in role) and the page carries the tab.
func apiKeyConsoleBootstrap(t *testing.T, h *harness.H) {
	for _, login := range []fakes.MintOption{
		fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup),
		fakes.Valid("vic", "vic@example.com", harness.ConsoleViewerGroup),
	} {
		var setup setupAPIKeys
		if err := json.Unmarshal([]byte(consoleGet(t, h, login, "/dashboard/api/setup")), &setup); err != nil || setup.APIKeys == nil {
			t.Fatalf("setup has no apiKeys (err %v)", err)
		}
		roles := map[string]string{}
		for _, s := range setup.APIKeys.Scopes {
			roles[s.Name] = s.MinRole
		}
		if roles["policy:read"] != config.RoleViewer.String() || roles["policy:write"] != config.RoleEditor.String() || roles["workers:admin"] != config.RoleAdmin.String() {
			t.Errorf("scope roles = %v", roles)
		}
		if setup.APIKeys.DefaultTTL <= 0 || setup.APIKeys.MaxTTL < setup.APIKeys.DefaultTTL {
			t.Errorf("ttl bounds = %d / %d", setup.APIKeys.DefaultTTL, setup.APIKeys.MaxTTL)
		}
	}
	if page := consoleGet(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup), "/dashboard/"); !strings.Contains(page, `id="page-apikeys"`) {
		t.Error("the console page has no API Keys tab")
	}
}

// apiKeyConsoleOff: with keys off the bootstrap has no apiKeys, so the page
// keeps the tab hidden, and the management route is 404.
func apiKeyConsoleOff(t *testing.T, h *harness.H) {
	login := fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup)
	if body := consoleGet(t, h, login, "/dashboard/api/setup"); strings.Contains(body, "apiKeys") {
		t.Errorf("setup carries apiKeys with keys off: %s", body)
	}
	b, _ := consoleLogin(t, h, login)
	resp, err := b.DoBody(http.MethodGet, "/dashboard/api/api-keys", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET api-keys with keys off = %d, want 404", resp.StatusCode)
	}
}
