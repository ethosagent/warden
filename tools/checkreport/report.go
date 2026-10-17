// Command checkreport runs Warden's check stages and writes one machine-readable
// report (schema warden.check.v1, docs/check-report.schema.json) so an agent can
// act on a failure without parsing mixed tool logs. scripts/check.sh calls it
// for --json, --json-out and --keep-going.
//
// This is developer tooling: no Warden package may import it, and it is not part
// of the shipped binary (cmd/proxy does not depend on it).
package main

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	schemaID = "warden.check.v1"

	// outputCap bounds the tool output excerpt in one finding.
	outputCap = 4096
	// textCap bounds the other free-text fields of a finding.
	textCap = 2048

	sevError   = "error"
	sevWarning = "warning"
)

// Report is the whole warden.check.v1 document.
type Report struct {
	Schema     string  `json:"schema"`
	OK         bool    `json:"ok"`
	DurationMs int64   `json:"durationMs"`
	Stages     []Stage `json:"stages"`
}

// Stage is one check.sh stage. A stage is ok when it ran and has no error finding.
type Stage struct {
	Name       string         `json:"name"`
	Tool       string         `json:"tool"`
	OK         bool           `json:"ok"`
	Skipped    bool           `json:"skipped,omitempty"`
	DurationMs int64          `json:"durationMs"`
	Findings   []Finding      `json:"findings"`
	Metrics    map[string]any `json:"metrics,omitempty"`
}

// Finding is the one shape every stage reports. Fix says what to do, not only
// what failed. Output is a short, secret-scrubbed excerpt of the tool output.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Col      int    `json:"col,omitempty"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
	Output   string `json:"output,omitempty"`
}

// Finalize scrubs and caps every free-text field, then derives each stage's ok
// and the report's ok from the findings. It is the last step before marshaling,
// so nothing a parser or a crashing stage produced can bypass the scrub.
func (r *Report) Finalize(s *Scrubber) {
	r.Schema = schemaID
	r.OK = true
	for i := range r.Stages {
		st := &r.Stages[i]
		if st.Findings == nil {
			st.Findings = []Finding{}
		}
		st.Name = s.Clean(st.Name)
		st.Tool = s.Clean(st.Tool)
		st.Metrics = scrubMetrics(st.Metrics, s)
		hasError := false
		for j := range st.Findings {
			f := &st.Findings[j]
			f.File = s.Clean(f.File)
			f.Message = capBytes(s.Clean(f.Message), textCap)
			f.Fix = capBytes(s.Clean(f.Fix), textCap)
			f.Output = capBytes(s.Clean(f.Output), outputCap)
			if f.Severity == "" {
				f.Severity = sevError
			}
			if f.Severity == sevError {
				hasError = true
			}
		}
		st.OK = !st.Skipped && !hasError
		if !st.OK {
			r.OK = false
		}
	}
}

// runStage runs fn, times it and turns a panic into a stage/crashed finding, so
// one broken stage never takes the report (or the other stages) down with it.
func runStage(name, tool string, fn func() Stage) (st Stage) {
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			st = Stage{Name: name, Tool: tool, Findings: []Finding{crashed(name, fmt.Sprintf("stage panicked: %v", p))}}
		}
		st.DurationMs = time.Since(start).Milliseconds()
	}()
	st = fn()
	st.Name, st.Tool = name, tool
	return st
}

// crashed is the finding for a stage or tool that did not complete normally.
func crashed(stage, msg string) Finding {
	return Finding{
		Rule:     "stage/crashed",
		Severity: sevError,
		Message:  fmt.Sprintf("%s stage did not complete: %s", stage, msg),
		Fix:      fmt.Sprintf("run the %s stage's tool by hand (see scripts/check.sh) and fix what it reports; if the tool itself is broken, check its pinned version", stage),
	}
}

// scrubMetrics scrubs every string inside the metrics, however deeply nested,
// by round-tripping through JSON, which is how they are reported anyway.
func scrubMetrics(m map[string]any, s *Scrubber) map[string]any {
	if m == nil {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return map[string]any{}
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return map[string]any{}
	}
	return scrubValue(v, s).(map[string]any)
}

func scrubValue(v any, s *Scrubber) any {
	switch x := v.(type) {
	case string:
		return s.Clean(x)
	case []any:
		for i := range x {
			x[i] = scrubValue(x[i], s)
		}
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[s.Clean(k)] = scrubValue(e, s)
		}
		return out
	}
	return v
}
