package observability

import (
	"io"
	"log/slog"
	"strings"
)

// NewLogger builds a *slog.Logger from the configured level and format. format
// "json" yields a JSON handler, anything else (e.g. "text") a text handler.
// level maps "debug"/"info"/"warn"/"error" (case-insensitive) to slog levels,
// defaulting to info for unknown values. Output is written to w (typically
// stdout/stderr).
//
// Logging hygiene is the caller's responsibility at the record sites: never log
// a raw secret value or a request/response body. This builder only wires the
// handler.
func NewLogger(w io.Writer, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "text") {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h)
}

// DiscardLogger returns a logger that drops all records. It is the safe default
// when no logger is provided, keeping behavior and log volume unchanged.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// parseLevel maps a level string to slog.Level, defaulting to info.
func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
