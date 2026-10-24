// Package deploy holds static tests over the files under deploy/ and the gate
// scripts that guard them. Nothing here starts a container.
package deploy

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// wantBindPWForm is the LDAP bindPW form chosen in deploy/compose/dex/README.md,
// section "Secrets and env expansion": Dex v2.41.1 expands $VARS in connector
// config by default (feature flag expand_env), so the config holds a reference.
const wantBindPWForm = "$LDAP_BIND_PW"

const (
	devIssuer  = "http://localhost:5556/dex"
	deviceGrnt = "urn:ietf:params:oauth:grant-type:device_code"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func readDex(t *testing.T, name string) ([]byte, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "dex", name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return raw, m
}

// at walks a path of map keys; missing or non-map steps return nil.
func at(m any, path ...string) any {
	for _, k := range path {
		mm, ok := m.(map[string]any)
		if !ok {
			return nil
		}
		m = mm[k]
	}
	return m
}

func strs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, e := range l {
		out = append(out, fmt.Sprint(e))
	}
	return out
}

func clientsByID(t *testing.T, cfg map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	l, _ := cfg["staticClients"].([]any)
	for _, e := range l {
		c, _ := e.(map[string]any)
		out[fmt.Sprint(c["id"])] = c
	}
	return out
}

func TestDexReferenceConfig(t *testing.T) {
	prodRaw, prod := readDex(t, "config.yaml")
	devRaw, dev := readDex(t, "config.dev.yaml")
	files := []struct {
		name string
		raw  []byte
		cfg  map[string]any
	}{{"config.yaml", prodRaw, prod}, {"config.dev.yaml", devRaw, dev}}

	t.Run("dev_issuer", func(t *testing.T) {
		if got := at(dev, "issuer"); got != devIssuer {
			t.Errorf("config.dev.yaml issuer = %v, want %s", got, devIssuer)
		}
	})
	t.Run("prod_issuer", func(t *testing.T) {
		if got := fmt.Sprint(at(prod, "issuer")); !strings.HasPrefix(got, "https://") {
			t.Errorf("config.yaml issuer = %q, want an https:// placeholder", got)
		}
	})
	t.Run("device_callback", func(t *testing.T) {
		for _, f := range files {
			want := fmt.Sprint(at(f.cfg, "issuer")) + "/device/callback"
			cli := clientsByID(t, f.cfg)["warden-cli"]
			if !contains(strs(cli["redirectURIs"]), want) {
				t.Errorf("%s: warden-cli redirectURIs = %v, want %s", f.name, cli["redirectURIs"], want)
			}
		}
	})
	t.Run("approval_comment", func(t *testing.T) {
		for _, f := range files {
			if !strings.Contains(string(f.raw), "Approval rejected") {
				t.Errorf("%s: missing the skipApprovalScreen comment (Approval rejected)", f.name)
			}
		}
	})
	t.Run("expiry", func(t *testing.T) {
		for _, f := range files {
			for path, want := range map[string]any{
				"idTokens": "1h", "signingKeys": "6h", "deviceRequests": "5m",
			} {
				if got := at(f.cfg, "expiry", path); got != want {
					t.Errorf("%s: expiry.%s = %v, want %v", f.name, path, got, want)
				}
			}
			rt := map[string]any{"validIfNotUsedFor": "168h", "absoluteLifetime": "720h", "reuseInterval": "3s", "disableRotation": false}
			if got := at(f.cfg, "expiry", "refreshTokens"); !reflect.DeepEqual(got, rt) {
				t.Errorf("%s: expiry.refreshTokens = %v, want %v", f.name, got, rt)
			}
		}
	})
	t.Run("clients", func(t *testing.T) {
		for _, f := range files {
			cs := clientsByID(t, f.cfg)
			var ids []string
			for id, c := range cs {
				ids = append(ids, id)
				if _, ok := c["secret"]; ok {
					t.Errorf("%s: client %s has a secret literal", f.name, id)
				}
			}
			sort.Strings(ids)
			if want := []string{"agent-harness", "warden", "warden-cli", "warden-console"}; !reflect.DeepEqual(ids, want) {
				t.Fatalf("%s: client ids = %v, want %v", f.name, ids, want)
			}
			if got := cs["warden-console"]["secretEnv"]; got != "WARDEN_CONSOLE_DEX_CLIENT_SECRET" {
				t.Errorf("%s: warden-console secretEnv = %v", f.name, got)
			}
			if got := strs(cs["warden-console"]["redirectURIs"]); !reflect.DeepEqual(got, []string{"https://localhost:7070/auth/callback"}) {
				t.Errorf("%s: warden-console redirectURIs = %v", f.name, got)
			}
			if got := cs["warden"]["secretEnv"]; got != "WARDEN_DEX_CLIENT_SECRET" {
				t.Errorf("%s: warden secretEnv = %v", f.name, got)
			}
			if _, ok := cs["warden"]["redirectURIs"]; ok {
				t.Errorf("%s: warden must have no redirectURIs", f.name)
			}
			if got := strs(cs["warden"]["trustedPeers"]); !reflect.DeepEqual(got, []string{"agent-harness", "warden-cli"}) {
				t.Errorf("%s: warden trustedPeers = %v", f.name, got)
			}
			if got := cs["agent-harness"]["secretEnv"]; got != "HARNESS_DEX_CLIENT_SECRET" {
				t.Errorf("%s: agent-harness secretEnv = %v", f.name, got)
			}
			if got := cs["warden-cli"]["public"]; got != true {
				t.Errorf("%s: warden-cli public = %v, want true", f.name, got)
			}
			if _, ok := cs["warden-cli"]["secretEnv"]; ok {
				t.Errorf("%s: warden-cli is public and must have no secretEnv", f.name)
			}
		}
	})
	t.Run("grants", func(t *testing.T) {
		base := []string{"authorization_code", "refresh_token", deviceGrnt}
		for _, f := range files {
			if got := strs(at(f.cfg, "oauth2", "responseTypes")); !reflect.DeepEqual(got, []string{"code"}) {
				t.Errorf("%s: oauth2.responseTypes = %v", f.name, got)
			}
			if got := at(f.cfg, "oauth2", "skipApprovalScreen"); got != true {
				t.Errorf("%s: oauth2.skipApprovalScreen = %v, want true", f.name, got)
			}
		}
		if got := strs(at(prod, "oauth2", "grantTypes")); !reflect.DeepEqual(got, base) {
			t.Errorf("config.yaml: oauth2.grantTypes = %v, want %v (no password grant)", got, base)
		}
		if got := at(prod, "oauth2", "passwordConnector"); got != nil {
			t.Errorf("config.yaml: oauth2.passwordConnector = %v, want unset", got)
		}
		if got := strs(at(dev, "oauth2", "grantTypes")); !reflect.DeepEqual(got, append(append([]string{}, base...), "password")) {
			t.Errorf("config.dev.yaml: oauth2.grantTypes = %v", got)
		}
		if got := at(dev, "oauth2", "passwordConnector"); got != "ldap" {
			t.Errorf("config.dev.yaml: oauth2.passwordConnector = %v, want ldap", got)
		}
	})
	t.Run("connector", func(t *testing.T) {
		for _, f := range files {
			cs, _ := f.cfg["connectors"].([]any)
			if len(cs) != 1 {
				t.Fatalf("%s: want one connector, got %d", f.name, len(cs))
			}
			c := cs[0]
			if at(c, "type") != "ldap" || at(c, "id") != "ldap" {
				t.Errorf("%s: connector type/id = %v/%v, want ldap/ldap", f.name, at(c, "type"), at(c, "id"))
			}
			if at(c, "config", "host") != "ldap:389" {
				t.Errorf("%s: connector host = %v", f.name, at(c, "config", "host"))
			}
			us := map[string]any{"username": "uid", "idAttr": "uid", "emailAttr": "mail", "nameAttr": "cn"}
			for k, want := range us {
				if got := at(c, "config", "userSearch", k); got != want {
					t.Errorf("%s: userSearch.%s = %v, want %v", f.name, k, got, want)
				}
			}
			gs := at(c, "config", "groupSearch")
			if at(gs, "nameAttr") != "cn" {
				t.Errorf("%s: groupSearch.nameAttr = %v", f.name, at(gs, "nameAttr"))
			}
			um := []any{map[string]any{"userAttr": "DN", "groupAttr": "member"}}
			if got := at(gs, "userMatchers"); !reflect.DeepEqual(got, any(um)) {
				t.Errorf("%s: groupSearch.userMatchers = %v", f.name, got)
			}
		}
		if at(dev, "connectors") == nil || at(prod, "connectors") == nil {
			return
		}
		devC := cfgConnector(dev)
		prodC := cfgConnector(prod)
		if devC["insecureNoSSL"] != true {
			t.Errorf("config.dev.yaml: connector insecureNoSSL = %v, want true", devC["insecureNoSSL"])
		}
		if _, ok := prodC["insecureNoSSL"]; ok {
			t.Error("config.yaml: connector must not set insecureNoSSL")
		}
		if prodC["startTLS"] != true || prodC["rootCA"] == nil {
			t.Errorf("config.yaml: connector must set startTLS and rootCA (got %v / %v)", prodC["startTLS"], prodC["rootCA"])
		}
	})
	t.Run("bindpw_form", func(t *testing.T) {
		for _, f := range files {
			if got := cfgConnector(f.cfg)["bindPW"]; got != wantBindPWForm {
				t.Errorf("%s: connector bindPW = %v, want %s", f.name, got, wantBindPWForm)
			}
			if _, ok := f.cfg["expandEnv"]; ok {
				t.Errorf("%s: top-level expandEnv is not a v2.41.1 key", f.name)
			}
		}
	})
	t.Run("telemetry_logger", func(t *testing.T) {
		for _, f := range files {
			for path, want := range map[string]any{
				"telemetry.http": "0.0.0.0:5558", "logger.level": "info", "logger.format": "json",
				"web.http": "0.0.0.0:5556", "storage.type": "sqlite3", "storage.config.file": "/var/dex/dex.db",
			} {
				if got := at(f.cfg, strings.Split(path, ".")...); got != want {
					t.Errorf("%s: %s = %v, want %v", f.name, path, got, want)
				}
			}
		}
	})
	t.Run("only_allowed_diffs", func(t *testing.T) {
		a, b := normalise(prod), normalise(dev)
		if p := firstDiff("", a, b); p != "" {
			t.Errorf("config.yaml and config.dev.yaml differ outside the allowed fields at %s", p)
		}
	})
}

// cfgConnector returns the first connector's config map.
func cfgConnector(cfg map[string]any) map[string]any {
	cs, _ := cfg["connectors"].([]any)
	if len(cs) == 0 {
		return map[string]any{}
	}
	m, _ := at(cs[0], "config").(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

// normalise deep-copies cfg without the fields the two files may differ in.
func normalise(cfg map[string]any) map[string]any {
	out := deepCopy(cfg).(map[string]any)
	delete(out, "issuer")
	if o, ok := out["oauth2"].(map[string]any); ok {
		delete(o, "grantTypes")
		delete(o, "passwordConnector")
	}
	if cs, ok := out["staticClients"].([]any); ok {
		for _, c := range cs {
			if m, ok := c.(map[string]any); ok && m["id"] == "warden-cli" {
				delete(m, "redirectURIs")
			}
		}
	}
	if cs, ok := out["connectors"].([]any); ok {
		for _, c := range cs {
			if m, ok := at(c, "config").(map[string]any); ok {
				for _, k := range []string{"insecureNoSSL", "insecureSkipVerify", "startTLS", "rootCA"} {
					delete(m, k)
				}
			}
		}
	}
	return out
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for i, e := range x {
			l[i] = deepCopy(e)
		}
		return l
	}
	return v
}

// firstDiff returns the key path of the first difference; it never prints values.
func firstDiff(path string, a, b any) string {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			return path
		}
		keys := map[string]bool{}
		for k := range x {
			keys[k] = true
		}
		for k := range y {
			keys[k] = true
		}
		var sorted []string
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			if p := firstDiff(path+"."+k, x[k], y[k]); p != "" {
				return p
			}
		}
		return ""
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return path
		}
		for i := range x {
			if p := firstDiff(fmt.Sprintf("%s[%d]", path, i), x[i], y[i]); p != "" {
				return p
			}
		}
		return ""
	}
	if !reflect.DeepEqual(a, b) {
		return path
	}
	return ""
}

func contains(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}
