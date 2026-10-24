package deploy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckSecretsScript runs scripts/check-secrets.sh against small temp trees.
// Literal values live only in the test's own strings, so the real gate (which
// scans only the SECRET_SCAN_PATHS list) never sees them.
func TestCheckSecretsScript(t *testing.T) {
	const dexDir = "deploy/compose/dex/"
	cases := []struct {
		name    string
		files   map[string]string
		env     []string
		wantErr string // "<file>:<line>" expected on stderr; empty means exit 0
		secret  string // value that must never be printed
	}{
		{name: "env_refs_ok", files: map[string]string{dexDir + "a.yaml": "secret: $FOO\nbindPW: ${LDAP_BIND_PW}\nclientSecret: ${X:?}\n"}},
		{name: "seed_ldif_ok", files: map[string]string{dexDir + "seed.ldif": "userPassword: {SSHA}abc\nsecret: abc\n"}},
		{name: "comment_ignored", files: map[string]string{dexDir + "a.yaml": "# secret: abc\nid: x\n"}},
		{name: "secret_literal", files: map[string]string{dexDir + "a.yaml": "id: x\nsecret: abc\n"}, wantErr: dexDir + "a.yaml:2", secret: "abc"},
		{name: "bindpw_literal", files: map[string]string{dexDir + "b.yaml": "bindPW: hunter2\n"}, wantErr: dexDir + "b.yaml:1", secret: "hunter2"},
		{name: "clientsecret_literal", files: map[string]string{"deploy/compose/docker-compose.identity.yml": "services:\n  a:\n    clientSecret: x\n"}, wantErr: "deploy/compose/docker-compose.identity.yml:3", secret: "clientSecret: x"},
		{name: "quoted_literal", files: map[string]string{dexDir + "a.yaml": "secret: \"abc\"\n"}, wantErr: dexDir + "a.yaml:1", secret: "abc"},
		{name: "scan_paths_env", files: map[string]string{"deploy/compose/other/a.yaml": "secret: abc\n"}, env: []string{"SECRET_SCAN_PATHS=deploy/compose/other"}, wantErr: "deploy/compose/other/a.yaml:1", secret: "abc"},
	}
	script := filepath.Join(repoRoot(t), "scripts", "check-secrets.sh")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			for name, body := range tc.files {
				p := filepath.Join(tmp, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", script)
			cmd.Env = append([]string{"ROOT=" + tmp, "PATH=" + os.Getenv("PATH")}, tc.env...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			out := stdout.String() + stderr.String()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want exit 0, got %v: %s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("want non-zero exit; output: %s", out)
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr must name %s, got: %s", tc.wantErr, stderr.String())
			}
			if strings.Contains(out, tc.secret) {
				t.Errorf("output must not contain the literal value %q: %s", tc.secret, out)
			}
		})
	}
}
