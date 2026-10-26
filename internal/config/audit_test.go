package config

import (
	"strings"
	"testing"
)

func parseAuditBlock(t *testing.T, block string) (AuditConfig, error) {
	t.Helper()
	p, err := parse([]byte("policy:\n  allowlist:\n    - domain: api.openai.com\n" + block))
	if err != nil {
		return AuditConfig{}, err
	}
	pol, _ := p.GetPolicy()
	return pol.Audit, nil
}

func TestAuditJSONLogConfig(t *testing.T) {
	t.Run("absent block is disabled with defaults", func(t *testing.T) {
		for _, block := range []string{"", "audit:\n  compliance:\n    enabled: true\n"} {
			a, err := parseAuditBlock(t, block)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			want := JSONLogConfig{
				Output: "stdout", MaxSizeMB: 100, MaxBackups: 10, MaxAgeDays: 30,
				FileMode: 0o600, Query: "drop",
			}
			if a.JSONLog != want {
				t.Fatalf("JSONLog = %+v, want %+v", a.JSONLog, want)
			}
		}
	})

	t.Run("full block parses", func(t *testing.T) {
		a, err := parseAuditBlock(t, `audit:
  jsonLog:
    enabled: true
    output: file
    path: /var/log/warden/decisions.jsonl
    maxSizeMB: 5
    maxBackups: 0
    maxAgeDays: 0
    compress: true
    fileMode: 0640
    query: keys
`)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		want := JSONLogConfig{
			Enabled: true, Output: "file", Path: "/var/log/warden/decisions.jsonl",
			MaxSizeMB: 5, MaxBackups: 0, MaxAgeDays: 0, Compress: true,
			FileMode: 0o640, Query: "keys",
		}
		if a.JSONLog != want {
			t.Fatalf("JSONLog = %+v, want %+v", a.JSONLog, want)
		}
	})

	t.Run("output stderr and a bare enabled block are valid", func(t *testing.T) {
		for _, block := range []string{
			"audit:\n  jsonLog:\n    enabled: true\n",
			"audit:\n  jsonLog:\n    enabled: true\n    output: stderr\n",
		} {
			if _, err := parseAuditBlock(t, block); err != nil {
				t.Fatalf("parse %q: %v", block, err)
			}
		}
	})

	bad := map[string]string{
		"file without path":   "enabled: true\n    output: file",
		"unknown output":      "enabled: true\n    output: syslog",
		"unknown query":       "query: values",
		"zero maxSizeMB":      "maxSizeMB: 0",
		"negative maxSizeMB":  "maxSizeMB: -1",
		"negative maxBackups": "maxBackups: -1",
		"negative maxAgeDays": "maxAgeDays: -1",
		"world-writable mode": "fileMode: 0666",
		"group-write mode":    "fileMode: 0660",
		"read-only mode":      "fileMode: 0400",
		"negative mode":       "fileMode: -1",
		"typo'd key":          "enabeld: true",
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := parseAuditBlock(t, "audit:\n  jsonLog:\n    "+body+"\n")
			if err == nil {
				t.Fatalf("expected an error for %q", body)
			}
			if !strings.Contains(err.Error(), "audit.jsonLog") && name != "typo'd key" {
				t.Fatalf("error %q does not name audit.jsonLog", err)
			}
		})
	}
}
