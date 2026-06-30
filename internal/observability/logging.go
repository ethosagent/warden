package observability

import (
	"io"
	"log/slog"
	"strings"
)

// LogControl is the live-tuning handle for a logger built by NewLogger. It backs
// the handler's minimum level with a *slog.LevelVar so the threshold can change
// at runtime WITHOUT swapping the *slog.Logger instance — every component that
// captured the logger keeps the same pointer and immediately observes the new
// level. The control-plane apply loop calls SetLevel on each settings change.
//
// Format is deliberately NOT live-tunable here: the format (json vs text) is the
// handler TYPE, baked in at construction, and the logger is captured widely
// across the proxy, so swapping the handler under those captures is unsafe. A
// format change therefore applies on RESTART only; the apply loop logs a
// "pending restart" line and Format reports the running format so the caller can
// detect a requested change. Level is live; format is restart.
type LogControl struct {
	level  *slog.LevelVar
	format string
}

// SetLevel updates the live minimum level from a level string ("debug"/"info"/
// "warn"/"error", case-insensitive; unknown → info), reusing parseLevel. It is
// safe to call concurrently with logging (slog.LevelVar.Set is atomic).
func (c *LogControl) SetLevel(level string) {
	if c == nil || c.level == nil {
		return
	}
	c.level.Set(parseLevel(level))
}

// Level returns the current live minimum level.
func (c *LogControl) Level() slog.Level {
	if c == nil || c.level == nil {
		return slog.LevelInfo
	}
	return c.level.Level()
}

// Format returns the running handler format ("json" or "text"). A format change
// distributed by the control plane cannot be applied live (see LogControl); the
// caller compares against this to decide whether to log a pending-restart line.
func (c *LogControl) Format() string {
	if c == nil {
		return "json"
	}
	return c.format
}

// NewLogger builds a *slog.Logger from the configured level and format, plus a
// LogControl handle for live level changes. format "json" yields a JSON handler,
// anything else (e.g. "text") a text handler. level maps "debug"/"info"/"warn"/
// "error" (case-insensitive) to slog levels, defaulting to info for unknown
// values. Output is written to w (typically stdout/stderr).
//
// The handler's level is backed by a *slog.LevelVar so LogControl.SetLevel can
// change the threshold at runtime without replacing the returned *slog.Logger —
// callers that capture the logger keep working and see the new level live.
//
// Logging hygiene is the caller's responsibility at the record sites: never log
// a raw secret value or a request/response body. This builder only wires the
// handler.
func NewLogger(w io.Writer, level, format string) (*slog.Logger, *LogControl) {
	lvl := new(slog.LevelVar)
	lvl.Set(parseLevel(level))
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	normFormat := "json"
	if strings.EqualFold(strings.TrimSpace(format), "text") {
		h = slog.NewTextHandler(w, opts)
		normFormat = "text"
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h), &LogControl{level: lvl, format: normFormat}
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
