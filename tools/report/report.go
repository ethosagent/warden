// Package report is the warden.check.v1 document (docs/check-report.schema.json)
// for the developer tools that are not tools/checkreport: riskmap and gatecheck.
// It is developer tooling; no Warden package may import it.
package report

import (
	"encoding/json"
	"io"
)

// SchemaID is the value of the document's "schema" property.
const SchemaID = "warden.check.v1"

// Severities a finding can carry.
const (
	SevError   = "error"
	SevWarning = "warning"
)

// Report is the whole warden.check.v1 document.
type Report struct {
	Schema     string  `json:"schema"`
	OK         bool    `json:"ok"`
	DurationMs int64   `json:"durationMs"`
	Stages     []Stage `json:"stages"`
}

// Stage is one tool run. It is ok when it has no error finding.
type Stage struct {
	Name       string         `json:"name"`
	Tool       string         `json:"tool"`
	OK         bool           `json:"ok"`
	DurationMs int64          `json:"durationMs"`
	Findings   []Finding      `json:"findings"`
	Metrics    map[string]any `json:"metrics,omitempty"`
}

// Finding is the one shape every stage reports.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
}

// New returns a one-stage report whose verdicts are derived from the findings.
func New(name, tool string, findings []Finding, metrics map[string]any) *Report {
	if findings == nil {
		findings = []Finding{}
	}
	ok := true
	for i := range findings {
		if findings[i].Severity == "" {
			findings[i].Severity = SevError
		}
		if findings[i].Severity == SevError {
			ok = false
		}
	}
	return &Report{
		Schema: SchemaID,
		OK:     ok,
		Stages: []Stage{{Name: name, Tool: tool, OK: ok, Findings: findings, Metrics: metrics}},
	}
}

// Write encodes the report as indented JSON.
func (r *Report) Write(w io.Writer) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
