package mcp

import (
	"bytes"
	"encoding/json"
	"sort"
	"sync"

	"github.com/ethosagent/warden/internal/scan"
)

// Direction distinguishes a tool's request shape from its response shape.
type Direction string

const (
	// DirRequest profiles the request params of a tools/call.
	DirRequest Direction = "request"
	// DirResponse profiles the result of a tools/call.
	DirResponse Direction = "response"
)

const defaultMaxFields = 200

// FieldDetector is one detector that has fired at a field path — the specific
// pattern (e.g. "github_token", "email"), its category, and severity. It carries
// NO matched value; Evidence (when present) is a MASKED form only (Phase 3,
// opt-in). Detectors are far more actionable than the coarse category alone.
type FieldDetector struct {
	Category string `json:"category"` // credential_leak | pii | injection
	Pattern  string `json:"pattern"`  // github_token | email | ssn | aws_access_key | ...
	Severity string `json:"severity"` // high | medium | low
	Evidence string `json:"evidence,omitempty"`
}

// FieldProfile is the learned profile of one field path. It stores structural
// shape and sensitivity flags only — never the field's value.
type FieldProfile struct {
	Types       []string // structural classes seen: "string","number","bool","object","array","null" (sorted, deduped)
	SeenCount   int      // how many observations touched this path
	Sensitivity []string // scan categories ever seen at this path (sorted, deduped)
	// Detectors is the specific detectors that fired here (pattern + severity),
	// deduped by (category, pattern). It refines the coarse Sensitivity list.
	Detectors []FieldDetector
}

// ToolProfile is the merged, observed schema of one (tool, direction).
type ToolProfile struct {
	// Fields is keyed by field path, e.g. "params.id", "result.email",
	// "result.orders[].total".
	Fields map[string]*FieldProfile
}

// FieldDetection ties a single scan Detection to the field path it came from.
type FieldDetection struct {
	Path     string
	Category string // from scan.Detection.Category
	Pattern  string
	Severity string
	Evidence string // masked sample (Phase 3, opt-in); empty otherwise
}

// FieldProfileView is a value copy of a FieldProfile, safe to expose.
type FieldProfileView struct {
	Types       []string
	SeenCount   int
	Sensitivity []string
	Detectors   []FieldDetector
}

// ToolProfileView is a value copy of a ToolProfile, safe to expose.
type ToolProfileView struct {
	Fields map[string]FieldProfileView
}

// SchemaProfiler learns the actual request/response JSON shape per tool, merged
// across calls, and tags which field paths have ever carried sensitive data. It
// is the observed-schema sibling to the declared-schema SchemaStore. It stores
// field paths, structural types, and scan-category flags only — never values.
type SchemaProfiler struct {
	mu        sync.Mutex
	profiles  map[string]*ToolProfile // key = tool + "\x00" + direction
	maxFields int                     // cap on distinct paths per (tool,direction)
}

// NewSchemaProfiler returns a profiler bounded to maxFields distinct paths per
// (tool, direction). A maxFields <= 0 selects the default (200).
func NewSchemaProfiler(maxFields int) *SchemaProfiler {
	if maxFields <= 0 {
		maxFields = defaultMaxFields
	}
	return &SchemaProfiler{
		profiles:  make(map[string]*ToolProfile),
		maxFields: maxFields,
	}
}

// profileKey builds the map key for a (tool, direction) profile.
func profileKey(tool string, dir Direction) string {
	return tool + "\x00" + string(dir)
}

// rootPrefix returns the field-path root for a direction: "params" for the
// request, "result" for the response.
func rootPrefix(dir Direction) string {
	if dir == DirRequest {
		return "params"
	}
	return "result"
}

// observation is one (path, type) pair gathered while walking a JSON value,
// plus any leaf string value to be scanned. value is used only transiently for
// scanning and is never stored in a profile.
type observation struct {
	path  string
	typ   string
	value string // non-empty only for leaf strings
	isStr bool
}

// Observe walks the JSON, infers the shape, merges it into the (tool, direction)
// profile, and scans each leaf string individually to attribute scan categories
// to the field path. It returns the detections found (with their field path) so
// the caller can reuse them for a verdict without re-scanning.
func (p *SchemaProfiler) Observe(tool string, dir Direction, raw json.RawMessage, scanner *scan.Scanner) []FieldDetection {
	if len(raw) == 0 {
		return nil
	}

	root := rootPrefix(dir)
	var obs []observation
	walkJSON(raw, root, 0, &obs)
	if len(obs) == 0 {
		return nil
	}

	// Scan leaf strings outside the lock; scanner is concurrency-safe.
	type scanned struct {
		path        string
		sensitivity []string
		dets        []FieldDetection
	}
	var results []scanned
	if scanner != nil {
		for _, o := range obs {
			if !o.isStr || o.value == "" {
				continue
			}
			dets := scanner.ScanResponse([]byte(o.value))
			if len(dets) == 0 {
				continue
			}
			sc := scanned{path: o.path}
			for _, d := range dets {
				sc.sensitivity = append(sc.sensitivity, d.Category)
				sc.dets = append(sc.dets, FieldDetection{
					Path:     o.path,
					Category: d.Category,
					Pattern:  d.Pattern,
					Severity: d.Severity,
					Evidence: d.Evidence,
				})
			}
			results = append(results, sc)
		}
	}

	// Index sensitivity + specific detectors by path for the merge step.
	sensByPath := make(map[string][]string, len(results))
	detByPath := make(map[string][]FieldDetector, len(results))
	var fieldDets []FieldDetection
	for _, r := range results {
		sensByPath[r.path] = append(sensByPath[r.path], r.sensitivity...)
		for _, d := range r.dets {
			detByPath[r.path] = append(detByPath[r.path], FieldDetector{
				Category: d.Category, Pattern: d.Pattern, Severity: d.Severity, Evidence: d.Evidence,
			})
		}
		fieldDets = append(fieldDets, r.dets...)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	key := profileKey(tool, dir)
	prof := p.profiles[key]
	if prof == nil {
		prof = &ToolProfile{Fields: make(map[string]*FieldProfile)}
		p.profiles[key] = prof
	}

	for _, o := range obs {
		fp := prof.Fields[o.path]
		if fp == nil {
			// Bounded: do not add new paths beyond the cap; still update existing.
			if len(prof.Fields) >= p.maxFields {
				continue
			}
			fp = &FieldProfile{}
			prof.Fields[o.path] = fp
		}
		fp.Types = addSorted(fp.Types, o.typ)
		fp.SeenCount++
		if sens := sensByPath[o.path]; len(sens) > 0 {
			fp.Sensitivity = addSorted(fp.Sensitivity, sens...)
		}
		if dets := detByPath[o.path]; len(dets) > 0 {
			fp.Detectors = addDetectors(fp.Detectors, dets...)
		}
	}

	return fieldDets
}

// walkJSON decodes raw at the given path and appends observations for the node
// and its descendants. Arrays collapse to a single representative element path
// ("[]") so large arrays don't explode the profile. It honors maxJSONDepth.
func walkJSON(raw json.RawMessage, path string, depth int, out *[]observation) {
	if depth > maxJSONDepth || len(raw) == 0 {
		return
	}

	// null
	if string(raw) == "null" {
		*out = append(*out, observation{path: path, typ: "null"})
		return
	}

	// string
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		*out = append(*out, observation{path: path, typ: "string", value: s, isStr: true})
		return
	}

	// bool
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		*out = append(*out, observation{path: path, typ: "bool"})
		return
	}

	// number
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err == nil {
		*out = append(*out, observation{path: path, typ: "number"})
		return
	}

	// array
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		*out = append(*out, observation{path: path, typ: "array"})
		elemPath := path + "[]"
		for _, item := range arr {
			walkJSON(item, elemPath, depth+1, out)
		}
		return
	}

	// object
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		*out = append(*out, observation{path: path, typ: "object"})
		for k, v := range obj {
			walkJSON(v, path+"."+k, depth+1, out)
		}
		return
	}
}

// Snapshot returns a deep copy of all profiles keyed by "tool\x00direction".
// The returned values share no pointers with internal state and are safe to read
// concurrently with further Observe calls.
func (p *SchemaProfiler) Snapshot() map[string]ToolProfileView {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make(map[string]ToolProfileView, len(p.profiles))
	for key, prof := range p.profiles {
		view := ToolProfileView{Fields: make(map[string]FieldProfileView, len(prof.Fields))}
		for path, fp := range prof.Fields {
			view.Fields[path] = FieldProfileView{
				Types:       cloneStrings(fp.Types),
				SeenCount:   fp.SeenCount,
				Sensitivity: cloneStrings(fp.Sensitivity),
				Detectors:   cloneDetectors(fp.Detectors),
			}
		}
		out[key] = view
	}
	return out
}

// Restore overwrites the profiler's state from a snapshot (as returned by
// Snapshot), keyed by "tool\x00direction". It deep-copies every view in so the
// caller's map shares no state with the profiler, and is safe to call
// concurrently with Observe/Snapshot. A nil snap is ignored.
func (p *SchemaProfiler) Restore(snap map[string]ToolProfileView) {
	if snap == nil {
		return
	}
	rebuilt := make(map[string]*ToolProfile, len(snap))
	for key, view := range snap {
		prof := &ToolProfile{Fields: make(map[string]*FieldProfile, len(view.Fields))}
		for path, fv := range view.Fields {
			prof.Fields[path] = &FieldProfile{
				Types:       cloneStrings(fv.Types),
				SeenCount:   fv.SeenCount,
				Sensitivity: cloneStrings(fv.Sensitivity),
				Detectors:   cloneDetectors(fv.Detectors),
			}
		}
		rebuilt[key] = prof
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.profiles = rebuilt
}

// addSorted returns dst with each value inserted if absent, kept sorted and
// deduped. It mutates and returns dst.
func addSorted(dst []string, vals ...string) []string {
	for _, v := range vals {
		i := sort.SearchStrings(dst, v)
		if i < len(dst) && dst[i] == v {
			continue
		}
		dst = append(dst, "")
		copy(dst[i+1:], dst[i:])
		dst[i] = v
	}
	return dst
}

// addDetectors merges vals into dst, deduped by (Category, Pattern) and kept
// sorted for stable output. A later observation's masked Evidence refreshes the
// stored one (single bounded sample per detector, never appended).
func addDetectors(dst []FieldDetector, vals ...FieldDetector) []FieldDetector {
	for _, v := range vals {
		found := false
		for i := range dst {
			if dst[i].Category == v.Category && dst[i].Pattern == v.Pattern {
				if v.Evidence != "" {
					dst[i].Evidence = v.Evidence
				}
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	sort.Slice(dst, func(i, j int) bool {
		if dst[i].Category != dst[j].Category {
			return dst[i].Category < dst[j].Category
		}
		return dst[i].Pattern < dst[j].Pattern
	})
	return dst
}

// cloneDetectors returns a copy of s (nil for empty).
func cloneDetectors(s []FieldDetector) []FieldDetector {
	if len(s) == 0 {
		return nil
	}
	out := make([]FieldDetector, len(s))
	copy(out, s)
	return out
}

// cloneStrings returns a copy of s (nil for empty) so callers can't mutate
// internal slices.
func cloneStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
