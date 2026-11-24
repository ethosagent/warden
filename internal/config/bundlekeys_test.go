package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/keys"
)

const (
	pinEdX = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	pinECX = "GvPmlGmk0aSPkIX4bWgDHifhkA5sbMjCgKgtKWV7oBE"
	pinECY = "-agAFznRqQeutJtbnQJ0hCANiCu0NccTB5FZhwh-MoM"
	pinEdD = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
)

func pinKid(t *testing.T, j keys.JWK) string {
	t.Helper()
	kid, err := keys.Thumbprint(j)
	if err != nil {
		t.Fatal(err)
	}
	return kid
}

func edPin(t *testing.T) keys.JWK {
	j := keys.JWK{Kty: "OKP", Crv: "Ed25519", X: pinEdX}
	j.Kid = pinKid(t, j)
	return j
}

func ecPin(t *testing.T) keys.JWK {
	j := keys.JWK{Kty: "EC", Crv: "P-256", X: pinECX, Y: pinECY, Alg: keys.AlgES256}
	j.Kid = pinKid(t, j)
	return j
}

func edYAML(t *testing.T, indent string) string {
	j := edPin(t)
	return fmt.Sprintf("%s- {kty: OKP, crv: Ed25519, x: %s, kid: %s}\n", indent, j.X, j.Kid)
}

func freshEd(t *testing.T) keys.JWK {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, err := keys.PublicJWK(pub, keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	j.Kid = pinKid(t, j)
	return j
}

func ecYAML(t *testing.T) string {
	j := ecPin(t)
	return fmt.Sprintf("    - {kty: EC, crv: P-256, x: %s, y: %s, kid: %s, alg: ES256}\n", j.X, j.Y, j.Kid)
}

const cpHead = baseAllow + "controlPlane:\n  endpoint: https://cp.example.com/policy\n"

func TestControlPlaneRequireSignedBundles(t *testing.T) {
	_, err := parse([]byte(cpHead + "  requireSignedBundles: true\n"))
	if err == nil || !strings.Contains(err.Error(), "controlPlane.bundleKeys") {
		t.Fatalf("err = %v, want one naming controlPlane.bundleKeys", err)
	}
	if _, err := parse([]byte(cpHead)); err != nil {
		t.Fatalf("without the flag: %v", err)
	}
	// With a pin the flag is satisfied.
	p, err := parse([]byte(cpHead + "  requireSignedBundles: true\n  bundleKeys:\n" + edYAML(t, "    ")))
	if err != nil || !p.policy.ControlPlane.BundleVerification() {
		t.Fatalf("pinned: %v", err)
	}
	// local-only ignores the keys, so the flag is not enforced.
	if _, err := parse([]byte(cpHead + "  localOnly: true\n  requireSignedBundles: true\n")); err != nil {
		t.Fatalf("local-only: %v", err)
	}
}

func TestControlPlaneBundleKeysReject(t *testing.T) {
	ed := edPin(t)
	cases := map[string]string{
		"private d":        fmt.Sprintf("{kty: OKP, crv: Ed25519, x: %s, kid: %s, d: %s}", ed.X, ed.Kid, pinEdD),
		"private d null":   fmt.Sprintf("{kty: OKP, crv: Ed25519, x: %s, kid: %s, d: null}", ed.X, ed.Kid),
		"private k on OKP": fmt.Sprintf("{kty: OKP, crv: Ed25519, x: %s, kid: %s, k: AAAA}", ed.X, ed.Kid),
		"dp on EC":         fmt.Sprintf("{kty: EC, crv: P-256, x: %s, y: %s, kid: x, DP: AAAA}", pinECX, pinECY),
		"oct":              "{kty: oct, k: AAAA, kid: x}",
		"rsa":              "{kty: RSA, n: AQAB, e: AQAB, kid: x}",
		"missing kid":      fmt.Sprintf("{kty: OKP, crv: Ed25519, x: %s}", ed.X),
		"wrong kid":        fmt.Sprintf("{kty: OKP, crv: Ed25519, x: %s, kid: not-the-thumbprint}", ed.X),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parse([]byte(cpHead + "  bundleKeys:\n    - " + key + "\n"))
			if err == nil || !strings.Contains(err.Error(), "controlPlane.bundleKeys[0]") {
				t.Fatalf("err = %v, want one naming controlPlane.bundleKeys[0]", err)
			}
			for _, secret := range []string{pinEdD, "AAAA"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks key material: %v", err)
				}
			}
		})
	}
}

func TestControlPlaneBundleKeysValid(t *testing.T) {
	p, err := parse([]byte(cpHead + "  bundleKeys:\n" + edYAML(t, "    ") + ecYAML(t)))
	if err != nil {
		t.Fatal(err)
	}
	got := p.policy.ControlPlane.BundleKeys
	if len(got) != 2 || got[0] != edPin(t) || got[1] != ecPin(t) {
		t.Fatalf("pins = %+v", got)
	}
	pins := p.policy.ControlPlane.BundlePins()
	pins[0].Kid = "mutated"
	if p.policy.ControlPlane.BundleKeys[0].Kid == "mutated" {
		t.Fatal("BundlePins must return a copy")
	}
}

func TestControlPlaneBundleKeysDuplicateKid(t *testing.T) {
	_, err := parse([]byte(cpHead + "  bundleKeys:\n" + edYAML(t, "    ") + edYAML(t, "    ")))
	if err == nil || !strings.Contains(err.Error(), "controlPlane.bundleKeys[1]") || !strings.Contains(err.Error(), "same kid") {
		t.Fatalf("err = %v", err)
	}
}

func writePinFile(t *testing.T, body string) string {
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestControlPlaneBundleKeysFile(t *testing.T) {
	ed, ec := edPin(t), ecPin(t)
	file := fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q},{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q}]}`,
		ed.X, ed.Kid, ec.X, ec.Y, ec.Kid)
	path := writePinFile(t, file)
	// A third, different key inline.
	ed2 := freshEd(t)
	inline := fmt.Sprintf("    - {kty: OKP, crv: Ed25519, x: %s, kid: %s}\n", ed2.X, ed2.Kid)
	p, err := parse([]byte(cpHead + "  bundleKeysFile: " + path + "\n  bundleKeys:\n" + inline))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(p.policy.ControlPlane.BundleKeys); got != 3 {
		t.Fatalf("pins = %d, want 3", got)
	}

	missing := filepath.Join(t.TempDir(), "absent.json")
	if _, err := parse([]byte(cpHead + "  bundleKeysFile: " + missing + "\n")); err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing file err = %v, want the path", err)
	}
	for name, body := range map[string]string{"not json": "nope", "no keys member": "{}"} {
		bad := writePinFile(t, body)
		if _, err := parse([]byte(cpHead + "  bundleKeysFile: " + bad + "\n")); err == nil || !strings.Contains(err.Error(), "bundleKeysFile") {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	// A bad key in the file is named by file index.
	badKey := writePinFile(t, `{"keys":[{"kty":"oct","k":"AAAA"}]}`)
	if _, err := parse([]byte(cpHead + "  bundleKeysFile: " + badKey + "\n")); err == nil || !strings.Contains(err.Error(), "controlPlane.bundleKeysFile[0]") {
		t.Fatalf("err = %v", err)
	}
	// A kid repeated across inline and file is a duplicate.
	dupInline := fmt.Sprintf("    - {kty: OKP, crv: Ed25519, x: %s, kid: %s}\n", ed.X, ed.Kid)
	if _, err := parse([]byte(cpHead + "  bundleKeysFile: " + path + "\n  bundleKeys:\n" + dupInline)); err == nil || !strings.Contains(err.Error(), "same kid") {
		t.Fatalf("cross-source duplicate err = %v", err)
	}
}

func TestControlPlaneBundleKeysLimit(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(cpHead + "  bundleKeys:\n")
	// Distinct valid Ed25519 keys: the 17th trips the limit.
	for range maxBundleKeys + 1 {
		j := freshEd(t)
		fmt.Fprintf(&sb, "    - {kty: OKP, crv: Ed25519, x: %s, kid: %s}\n", j.X, j.Kid)
	}
	if _, err := parse([]byte(sb.String())); err == nil || !strings.Contains(err.Error(), "maximum is 16") {
		t.Fatalf("err = %v", err)
	}
}

func TestControlPlaneBundleOptions(t *testing.T) {
	p, err := parse([]byte(cpHead))
	if err != nil {
		t.Fatal(err)
	}
	cp := p.policy.ControlPlane
	if cp.BundleVerification() || cp.RequireSignedBundles || cp.BundleIssuer != "" ||
		cp.BundleClockSkew != 5*time.Minute || cp.BundleExpiry != BundleExpiryKeep {
		t.Fatalf("defaults = %+v", cp)
	}
	now := time.Unix(1_700_000_000, 0)
	p, err = parse([]byte(cpHead + "  bundleIssuer: cp-1\n  bundleClockSkew: 1h\n  bundleExpiry: deny\n"))
	if err != nil {
		t.Fatal(err)
	}
	opt := p.policy.ControlPlane.BundleOptions(now)
	if opt.Issuer != "cp-1" || opt.Skew != time.Hour || !opt.Now.Equal(now) || p.policy.ControlPlane.BundleExpiry != BundleExpiryDeny {
		t.Fatalf("options = %+v", opt)
	}
	for _, bad := range []string{"bundleClockSkew: 61m", "bundleClockSkew: -1m", "bundleClockSkew: soon", "bundleExpiry: never"} {
		if _, err := parse([]byte(cpHead + "  " + bad + "\n")); err == nil || !strings.Contains(err.Error(), "controlPlane.bundle") {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
}
