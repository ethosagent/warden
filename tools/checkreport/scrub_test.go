package main

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestScrubRedactsWardenCredentialPatterns(t *testing.T) {
	s := NewScrubber(nil)
	canaries := []string{
		"AKIAABCDEFGHIJKLMNOP",
		"ghp_" + strings.Repeat("a1B2", 9),
		"sk_live_" + strings.Repeat("Z9", 12),
		"-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl",
	}
	for _, c := range canaries {
		got := s.Clean("before " + c + " after")
		if strings.Contains(got, c) {
			t.Errorf("canary %q survived: %q", c, got)
		}
		if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
			t.Errorf("surrounding text lost: %q", got)
		}
	}
}

func TestScrubRedactsEnvSecretValues(t *testing.T) {
	s := NewScrubber([]string{"HOME=/home/x", "MY_API_TOKEN=hunter2-canary-value", "SHORT_SECRET=ab", "PATH=/usr/bin"})
	got := s.Clean("token is hunter2-canary-value, home /home/x, ab")
	if strings.Contains(got, "hunter2-canary-value") {
		t.Errorf("env secret survived: %q", got)
	}
	if !strings.Contains(got, "/home/x") {
		t.Errorf("non-secret env value must be kept: %q", got)
	}
	if !strings.Contains(got, ", ab") {
		t.Errorf("values under 8 bytes are not scrubbed (too noisy): %q", got)
	}
}

func TestScrubWithholdsEncodedCredential(t *testing.T) {
	// The scanner only decodes base64 blocks of 64+ characters.
	enc := base64.StdEncoding.EncodeToString([]byte("creds: AKIAABCDEFGHIJKLMNOP and some padding to be long enough"))
	got := NewScrubber(nil).Clean("blob " + enc + " end")
	if strings.Contains(got, enc) {
		t.Errorf("encoded credential survived: %q", got)
	}
}

func TestScrubRedactsWholePEMBlock(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdefghijklmnop\n-----END PRIVATE KEY-----"
	got := NewScrubber(nil).Clean("x\n" + pem + "\ny")
	if strings.Contains(got, "MIIEvQ") || strings.Contains(got, "abcdefghijklmnop") {
		t.Errorf("PEM body survived: %q", got)
	}
}

func TestScrubLeavesOrdinaryOutputAlone(t *testing.T) {
	in := "internal/proxy/http_test.go:120: got 127.0.0.1:8080, user a@b.io"
	if got := NewScrubber(nil).Clean(in); got != in {
		t.Errorf("ordinary output changed: %q", got)
	}
}

func TestCapBytes(t *testing.T) {
	in := strings.Repeat("é", 5000) // 10000 bytes
	got := capBytes(in, 4096)
	if len(got) > 4096+len(truncMarker) || !strings.HasSuffix(got, truncMarker) || !utf8.ValidString(got) {
		t.Errorf("bad cap: len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	if capBytes("short", 4096) != "short" {
		t.Error("short strings must pass through")
	}
}

func TestScrubWithholdsBase64BlocksWhateverTheyDecodeTo(t *testing.T) {
	// The reviewer's payload: no credential pattern matches the decoded text.
	payload := "password: Sup3rS3cretCanaryValue99 and padding here"
	for name, enc := range map[string]string{
		"std":    base64.StdEncoding.EncodeToString([]byte(payload)),
		"url":    base64.URLEncoding.EncodeToString([]byte(payload)),
		"rawstd": base64.RawStdEncoding.EncodeToString([]byte(payload)),
		"rawurl": base64.RawURLEncoding.EncodeToString([]byte(payload)),
	} {
		got := NewScrubber(nil).Clean("blob " + enc + " end")
		if strings.Contains(got, enc[:40]) || strings.Contains(got, "Sup3r") {
			t.Errorf("%s: base64 payload survived: %q", name, got)
		}
		if !strings.HasPrefix(got, "blob ") || !strings.HasSuffix(got, " end") {
			t.Errorf("%s: surrounding text lost: %q", name, got)
		}
		if !json.Valid([]byte(strconv.Quote(got))) || strings.ContainsAny(got, `"\`) {
			t.Errorf("%s: marker must be JSON-safe: %q", name, got)
		}
	}
}

func TestScrubBase64Threshold(t *testing.T) {
	text := strings.Repeat("hello world ", 10) // printable, decodes to plain text
	for _, n := range []int{39, 40, 41} {
		enc := base64.RawStdEncoding.EncodeToString([]byte(text))[:n]
		got := NewScrubber(nil).Clean("x " + enc + " y")
		withheld := !strings.Contains(got, enc)
		if want := n >= 40; withheld != want {
			t.Errorf("%d base64 chars: withheld=%v want %v (%q)", n, withheld, want, got)
		}
	}
}

func TestScrubKeepsLongNonTextBlocks(t *testing.T) {
	// A 40-hex git SHA and a long path decode to binary noise: not text, kept.
	for _, in := range []string{
		"commit 0123456789abcdef0123456789abcdef01234567 done",
		"internal/proxy/some-very-long-package-name/handler_test.go:12",
	} {
		if got := NewScrubber(nil).Clean(in); got != in {
			t.Errorf("non-text block altered: %q -> %q", in, got)
		}
	}
}
