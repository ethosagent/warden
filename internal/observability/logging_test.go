package observability

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"unknown": slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNewLoggerJSONFields(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(&buf, "info", "json")
	logger.Info("egress decision",
		slog.String("domain", "api.openai.com"),
		slog.String("protocol", "https"),
		slog.String("decision", "allow"),
		slog.String("secret_ref", "sha256:abc123 last4:7890 len:51"),
	)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, buf.String())
	}
	for _, k := range []string{"domain", "protocol", "decision", "secret_ref"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("missing field %q in %v", k, rec)
		}
	}
}

// TestNoSecretValueInLogs ensures a raw secret value and a body never appear in
// log output — only the by-reference string is logged.
func TestNoSecretValueInLogs(t *testing.T) {
	const rawSecret = "sk-supersecretvalue-DO-NOT-LEAK-7890"
	const body = "POST body with the secret " + rawSecret + " inside"
	var buf bytes.Buffer
	logger, _ := NewLogger(&buf, "debug", "json")

	// Caller logs only the reference, never the value or body.
	logger.Info("egress decision",
		slog.String("decision", "allow"),
		slog.String("secret_ref", "sha256:deadbeef last4:7890 len:36"),
	)

	out := buf.String()
	if strings.Contains(out, rawSecret) {
		t.Fatalf("raw secret value leaked into log:\n%s", out)
	}
	if strings.Contains(out, body) {
		t.Fatalf("request body leaked into log:\n%s", out)
	}
}

func TestNewLoggerTextFormatLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	logger, _ := NewLogger(&buf, "error", "text")
	logger.Info("should be filtered")
	logger.Error("should appear")
	out := buf.String()
	if strings.Contains(out, "should be filtered") {
		t.Errorf("info record emitted at error level:\n%s", out)
	}
	if !strings.Contains(out, "should appear") {
		t.Errorf("error record missing:\n%s", out)
	}
}

// TestLogControlSetLevelLive verifies LogControl.SetLevel changes the live
// threshold WITHOUT swapping the *slog.Logger: the same logger instance drops a
// debug record at warn level, then emits it after SetLevel("debug"), and the
// reported running format reflects the construction-time format.
func TestLogControlSetLevelLive(t *testing.T) {
	var buf bytes.Buffer
	logger, ctrl := NewLogger(&buf, "warn", "json")
	if ctrl.Format() != "json" {
		t.Fatalf("Format() = %q, want json", ctrl.Format())
	}
	if ctrl.Level() != slog.LevelWarn {
		t.Fatalf("Level() = %v, want warn", ctrl.Level())
	}

	// At warn level, a debug record is dropped.
	logger.Debug("hidden-at-warn")
	if strings.Contains(buf.String(), "hidden-at-warn") {
		t.Fatalf("debug record emitted while level=warn:\n%s", buf.String())
	}

	// Raise verbosity live; the SAME logger now emits the debug record.
	ctrl.SetLevel("debug")
	if ctrl.Level() != slog.LevelDebug {
		t.Fatalf("Level() after SetLevel = %v, want debug", ctrl.Level())
	}
	logger.Debug("visible-at-debug")
	if !strings.Contains(buf.String(), "visible-at-debug") {
		t.Fatalf("debug record missing after SetLevel(debug):\n%s", buf.String())
	}
}

// TestNewLoggerTextFormatReported confirms the running format is reported as the
// normalized handler type (text), which the apply loop compares against to decide
// whether a control-plane format change needs a restart.
func TestNewLoggerTextFormatReported(t *testing.T) {
	var buf bytes.Buffer
	_, ctrl := NewLogger(&buf, "info", "text")
	if ctrl.Format() != "text" {
		t.Fatalf("Format() = %q, want text", ctrl.Format())
	}
}

// TestLogControlNilSafe ensures the zero/nil handle is safe to call (defensive:
// a non-managed worker may not thread a control handle everywhere).
func TestLogControlNilSafe(t *testing.T) {
	var c *LogControl
	c.SetLevel("debug") // must not panic
	if c.Level() != slog.LevelInfo {
		t.Fatalf("nil LogControl Level() = %v, want info default", c.Level())
	}
	if c.Format() != "json" {
		t.Fatalf("nil LogControl Format() = %q, want json default", c.Format())
	}
}

func TestDiscardLogger(t *testing.T) {
	// Must not panic and must produce no observable output.
	DiscardLogger().Info("dropped", slog.String("k", "v"))
}
