package worker

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/keys"
)

func TestLogBundleVerification(t *testing.T) {
	pinned := config.ControlPlaneConfig{BundleKeys: []keys.JWK{{Kty: "OKP"}}}
	cases := []struct {
		name               string
		cp                 config.ControlPlaneConfig
		managed, localOnly bool
		want               string // substring of the single line, "" for none
	}{
		{"managed without pins warns", config.ControlPlaneConfig{}, true, false, "level=WARN msg=\"bundle verification disabled (no controlPlane.bundleKeys, controlPlane.requireSignedBundles: false)"},
		{"managed with pins is silent", pinned, true, false, ""},
		{"local-only with pins informs", pinned, false, true, "level=INFO"},
		{"local-only with the default require flag is silent", config.ControlPlaneConfig{RequireSignedBundles: true}, false, true, ""},
		{"local-only without keys is silent", config.ControlPlaneConfig{}, false, true, ""},
		{"standalone is silent", config.ControlPlaneConfig{}, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logBundleVerification(slog.New(slog.NewTextHandler(&buf, nil)), tc.cp, tc.managed, tc.localOnly)
			out := buf.String()
			if tc.want == "" {
				if out != "" {
					t.Fatalf("want no log, got %q", out)
				}
				return
			}
			if !strings.Contains(out, tc.want) || strings.Count(out, "\n") != 1 {
				t.Fatalf("want one line containing %q, got %q", tc.want, out)
			}
		})
	}
}
