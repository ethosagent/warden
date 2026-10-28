package controlplane

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

const testPassword = "correct horse battery"

func phcWith(m, t, p int, salt, key int, version, alg string) string {
	b := base64.RawStdEncoding
	return fmt.Sprintf("$%s$v=%s$m=%d,t=%d,p=%d$%s$%s", alg, version, m, t, p,
		b.EncodeToString(bytes.Repeat([]byte{1}, salt)), b.EncodeToString(bytes.Repeat([]byte{2}, key)))
}

func TestPHCRoundTrip(t *testing.T) {
	s, err := HashPassword(testPassword, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected prefix: %q", s[:32])
	}
	p, err := ParsePHC(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Salt) != 16 || len(p.Key) != 32 {
		t.Errorf("salt %d key %d", len(p.Salt), len(p.Key))
	}
	if !p.Verify(testPassword) {
		t.Error("right password rejected")
	}
	if p.Verify(testPassword + "x") {
		t.Error("wrong password accepted")
	}
	if p.String() != s {
		t.Error("String does not round-trip")
	}
	// Two hashes of one password differ (random salt).
	s2, _ := HashPassword(testPassword, rand.Reader)
	if s2 == s {
		t.Error("salt not random")
	}
}

func TestPHCRejects(t *testing.T) {
	good := phcWith(65536, 3, 2, 16, 32, "19", "argon2id")
	if _, err := ParsePHC(good); err != nil {
		t.Fatalf("good rejected: %v", err)
	}
	long := good + strings.Repeat("A", 513-len(good))
	tests := map[string]string{
		"m=19455":      phcWith(19455, 3, 2, 16, 32, "19", "argon2id"),
		"m=262145":     phcWith(262145, 3, 2, 16, 32, "19", "argon2id"),
		"t=1":          phcWith(65536, 1, 2, 16, 32, "19", "argon2id"),
		"t=11":         phcWith(65536, 11, 2, 16, 32, "19", "argon2id"),
		"p=0":          phcWith(65536, 3, 0, 16, 32, "19", "argon2id"),
		"p=5":          phcWith(65536, 3, 5, 16, 32, "19", "argon2id"),
		"salt 15":      phcWith(65536, 3, 2, 15, 32, "19", "argon2id"),
		"key 31":       phcWith(65536, 3, 2, 16, 31, "19", "argon2id"),
		"v=18":         phcWith(65536, 3, 2, 16, 32, "18", "argon2id"),
		"argon2i":      phcWith(65536, 3, 2, 16, 32, "19", "argon2i"),
		"513 bytes":    long,
		"empty":        "",
		"no leading $": good[1:],
		"bad b64 salt": strings.Replace(good, "AQEBAQEBAQEBAQEBAQEBAQ", "!!", 1),
		"padded key":   good + "=",
		"signed m":     strings.Replace(good, "m=65536", "m=+65536", 1),
		"extra part":   good + "$x",
		"overflow m":   strings.Replace(good, "m=65536", "m=99999999999", 1),
	}
	if len(long) != 513 {
		t.Fatalf("long fixture is %d bytes", len(long))
	}
	for name, in := range tests {
		_, err := ParsePHC(in)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "phc: ") || len(err.Error()) > 40 {
			t.Errorf("%s: error %q not a bounded phc message", name, err)
		}
		if in != "" && strings.Contains(err.Error(), in) {
			t.Errorf("%s: error echoes input", name)
		}
	}
	if err := func() error { _, err := ParsePHC(tests["m=19455"]); return err }(); err.Error() != "phc: memory out of range" {
		t.Errorf("message = %q", err)
	}
	for _, in := range []string{phcWith(19456, 2, 1, 16, 32, "19", "argon2id"), phcWith(262144, 10, 4, 16, 32, "19", "argon2id")} {
		if _, err := ParsePHC(in); err != nil {
			t.Errorf("boundary rejected: %v", err)
		}
	}
}

func TestPHCPasswordRules(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("a", 15), rand.Reader); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("15 chars: %v", err)
	}
	// 16 runes of 3 bytes each is fine (rune count, not bytes).
	if _, err := HashPassword(strings.Repeat("€", 16), rand.Reader); err != nil {
		t.Errorf("16 runes: %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", 1025), rand.Reader); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("1025 bytes: %v", err)
	}
	if _, err := HashPassword(testPassword, strings.NewReader("short")); err == nil {
		t.Error("short random source accepted")
	}
	if (PHC{}).Verify(testPassword) {
		t.Error("zero PHC verified")
	}
}

func TestPHCDummy(t *testing.T) {
	d := DummyPHC()
	if _, err := ParsePHC(d.String()); err != nil {
		t.Fatalf("dummy does not parse: %v", err)
	}
	if d.Verify(testPassword) || d.String() != DummyPHC().String() {
		t.Error("dummy must be fixed and match no real password")
	}
}

func TestLoadBreakGlassHash(t *testing.T) {
	h1, _ := HashPassword(testPassword, rand.Reader)
	h2, _ := HashPassword("another long password", rand.Reader)

	t.Setenv("BG_TEST_HASH", h1+"\n")
	p, err := LoadBreakGlassHash(config.ConsoleBreakGlass{PasswordHashEnv: "BG_TEST_HASH"})
	if err != nil || !p.Verify(testPassword) {
		t.Fatalf("env load: %v", err)
	}

	_, err = LoadBreakGlassHash(config.ConsoleBreakGlass{PasswordHashEnv: "BG_TEST_UNSET"})
	if err == nil || !strings.Contains(err.Error(), "console.breakGlass.passwordHashEnv is empty") {
		t.Errorf("unset env: %v", err)
	}

	t.Setenv("BG_TEST_BAD", "$argon2id$secretvalue")
	_, err = LoadBreakGlassHash(config.ConsoleBreakGlass{PasswordHashEnv: "BG_TEST_BAD"})
	if err == nil || strings.Contains(err.Error(), "secretvalue") || !strings.Contains(err.Error(), "console.breakGlass.passwordHashEnv") {
		t.Errorf("bad env: %v", err)
	}

	f := filepath.Join(t.TempDir(), "hash")
	if err := os.WriteFile(f, []byte(h1+" \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.ConsoleBreakGlass{PasswordHashFile: f}
	p, err = LoadBreakGlassHash(cfg)
	if err != nil || !p.Verify(testPassword) {
		t.Fatalf("file load: %v", err)
	}
	if err := os.WriteFile(f, []byte(h2), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err = LoadBreakGlassHash(cfg)
	if err != nil || p.Verify(testPassword) || !p.Verify("another long password") {
		t.Fatalf("file not re-read after rewrite: %v", err)
	}

	_, err = LoadBreakGlassHash(config.ConsoleBreakGlass{PasswordHashFile: filepath.Join(t.TempDir(), "missing")})
	if err == nil || !strings.Contains(err.Error(), "console.breakGlass.passwordHashFile: unreadable") {
		t.Errorf("missing file: %v", err)
	}
	if err := os.WriteFile(f, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadBreakGlassHash(cfg); err == nil || !strings.Contains(err.Error(), "passwordHashFile is empty") {
		t.Errorf("empty file: %v", err)
	}
	if _, err = LoadBreakGlassHash(config.ConsoleBreakGlass{}); err == nil {
		t.Error("no source accepted")
	}
	if _, err = LoadBreakGlassHash(config.ConsoleBreakGlass{PasswordHashEnv: "A", PasswordHashFile: f}); err == nil {
		t.Error("both sources accepted")
	}
}
