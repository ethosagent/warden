package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ethosagent/warden/internal/scan"
)

// DLP mode + action vocabularies, shared with the rule evaluator (internal/dlp)
// and the proxy wiring so the strings live in exactly one place.
const (
	DLPModeOff     = "off"
	DLPModeMonitor = "monitor"
	DLPModeEnforce = "enforce"

	DLPActionAllow   = "allow"
	DLPActionBlock   = "block"
	DLPActionRedact  = "redact"
	DLPActionMonitor = "monitor"
)

// DLPConfig gates and configures outbound REQUEST-body data-loss-prevention. Mode
// is the floor (off disables the stage entirely; monitor records but never blocks;
// enforce actually blocks). Classes/Rules express the per-class per-destination
// egress policy the rule evaluator applies; Custom declares operator data classes.
//
// Everything is off by default; a zero value means "no DLP" and is byte-identical
// to before. Policy.DLP is json:"-" (LOCAL config), so a control-plane-managed
// worker decodes it as the zero value — Active() reads that as disabled.
type DLPConfig struct {
	// Mode is one of off|monitor|enforce. Empty normalizes to off.
	Mode string
	// Classes is the per-class DEFAULT action, keyed by class spec (an exact class
	// like "pii.contact", a class glob like "pii.*"/"*", or a custom.<name>). It is
	// the "class-default" precedence tier — less specific than a destination rule,
	// more specific than the mode default.
	Classes map[string]DLPClassDefault
	// Rules is the ordered list of per-class per-destination egress rules. Order in
	// the file is NOT significant: the evaluator resolves by specificity + deny-wins,
	// never by first-match position.
	Rules []DLPRule
	// Custom declares operator data classes (compiled regexes) surfaced as
	// custom.<name>. Operator config, never secrets.
	Custom []DLPCustomClass
}

// DLPClassDefault is the default action for a class (the dlp.classes map value).
type DLPClassDefault struct {
	Action string
}

// DLPRule binds a class spec to an action, optionally scoped to a destination set.
// An empty To applies to every (statically-allowed) destination — a class default.
type DLPRule struct {
	// Class is the class spec this rule addresses (exact / glob / custom.<name>).
	Class string
	// To is the destination allow-set for this rule, matched with the SAME dialect
	// the policy evaluator uses (exact / *.wildcard / ~regex). Empty = all dests.
	To []string
	// Action is one of allow|block|redact|monitor.
	Action string
}

// DLPCustomClass is an operator-declared class: a unique name (surfaced as
// custom.<Name>), a regex compiled at load, and a severity.
type DLPCustomClass struct {
	Name     string
	Regex    string
	Severity string
}

// rawDLP mirrors the on-disk `dlp:` block. Pointer so an absent block is distinct
// from an explicit one. KnownFields(true) is strict, so every field MUST be
// registered here or a config carrying it fails to parse.
type rawDLP struct {
	Mode    string                        `yaml:"mode"`
	Classes map[string]rawDLPClassDefault `yaml:"classes"`
	Rules   []rawDLPRule                  `yaml:"rules"`
	Custom  []rawDLPCustomClass           `yaml:"custom"`
}

type rawDLPClassDefault struct {
	Action string `yaml:"action"`
}

type rawDLPRule struct {
	Class  string   `yaml:"class"`
	To     []string `yaml:"to"`
	Action string   `yaml:"action"`
}

type rawDLPCustomClass struct {
	Name     string `yaml:"name"`
	Regex    string `yaml:"regex"`
	Severity string `yaml:"severity"`
}

// defaultDLPMode is applied when the dlp block (or its mode) is omitted: DLP is
// off unless explicitly enabled, so an absent block is byte-identical to before.
const defaultDLPMode = DLPModeOff

// defaultDLPCustomSeverity is applied when a custom class omits its severity.
const defaultDLPCustomSeverity = "medium"

// parseDLP converts the raw dlp block into a typed DLPConfig, applying documented
// defaults and normalizing case. Cross-field validation (enums, class specs,
// destination patterns, custom-regex compilation) happens in validateDLP.
func parseDLP(r *rawDLP) DLPConfig {
	d := DLPConfig{Mode: defaultDLPMode}
	if r == nil {
		return d
	}
	if strings.TrimSpace(r.Mode) != "" {
		d.Mode = strings.ToLower(strings.TrimSpace(r.Mode))
	}
	if len(r.Classes) > 0 {
		d.Classes = make(map[string]DLPClassDefault, len(r.Classes))
		for k, v := range r.Classes {
			d.Classes[k] = DLPClassDefault{Action: normalizeAction(v.Action)}
		}
	}
	for _, rr := range r.Rules {
		d.Rules = append(d.Rules, DLPRule{
			Class:  rr.Class,
			To:     rr.To,
			Action: normalizeAction(rr.Action),
		})
	}
	for _, c := range r.Custom {
		sev := strings.ToLower(strings.TrimSpace(c.Severity))
		if sev == "" {
			sev = defaultDLPCustomSeverity
		}
		d.Custom = append(d.Custom, DLPCustomClass{
			Name:     c.Name,
			Regex:    c.Regex,
			Severity: sev,
		})
	}
	return d
}

// normalizeAction lower-cases + trims an action string so validation and the
// evaluator compare against the canonical DLPAction* constants.
func normalizeAction(a string) string {
	return strings.ToLower(strings.TrimSpace(a))
}

// Active reports whether DLP should run: only monitor or enforce enable the stage.
// off and the zero value ("") both disable it (so a CP-managed worker that decoded
// Policy.DLP as the zero value reads it as disabled).
func (d DLPConfig) Active() bool {
	return d.Mode == DLPModeMonitor || d.Mode == DLPModeEnforce
}

// validateDLP enforces the dlp block's invariants. This is the CP-side validation:
// it runs in the shared config.validate, which the control-plane editor also calls,
// so an operator editing rules in the dashboard gets the same errors as a local
// config. The empty zero value validates as "off" (Policy.DLP never crosses the
// wire, so a managed worker decodes an empty block that must pass).
func validateDLP(d DLPConfig) error {
	switch d.Mode {
	case "", DLPModeOff, DLPModeMonitor, DLPModeEnforce:
	default:
		return fmt.Errorf("config: dlp.mode %q is invalid; must be one of: off, monitor, enforce", d.Mode)
	}

	// Custom classes first: names/regex/severity, and build the declared-name set
	// the class-spec check below consults.
	customNames := make(map[string]struct{}, len(d.Custom))
	for i, c := range d.Custom {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return fmt.Errorf("config: dlp.custom[%d]: name is required", i)
		}
		if _, dup := customNames[name]; dup {
			return fmt.Errorf("config: dlp.custom: duplicate name %q", name)
		}
		customNames[name] = struct{}{}
		if strings.TrimSpace(c.Regex) == "" {
			return fmt.Errorf("config: dlp.custom[%d] (%s): regex is required", i, name)
		}
		if _, err := regexp.Compile(c.Regex); err != nil {
			return fmt.Errorf("config: dlp.custom[%d] (%s): invalid regex: %v", i, name, err)
		}
		switch c.Severity {
		case "low", "medium", "high":
		default:
			return fmt.Errorf("config: dlp.custom[%d] (%s): severity %q is invalid; must be one of: low, medium, high", i, name, c.Severity)
		}
	}

	// Class-default map: valid action + valid class spec.
	for spec, cd := range d.Classes {
		if err := validateDLPAction(fmt.Sprintf("dlp.classes[%q]", spec), cd.Action); err != nil {
			return err
		}
		if !validDLPClassSpec(spec, customNames) {
			return fmt.Errorf("config: dlp.classes: %q is not a known data class, class glob, or declared custom.<name>", spec)
		}
	}

	// Rules: valid action + valid class spec + valid destination patterns.
	for i, r := range d.Rules {
		if err := validateDLPAction(fmt.Sprintf("dlp.rules[%d]", i), r.Action); err != nil {
			return err
		}
		if !validDLPClassSpec(r.Class, customNames) {
			return fmt.Errorf("config: dlp.rules[%d]: class %q is not a known data class, class glob, or declared custom.<name>", i, r.Class)
		}
		for j, to := range r.To {
			if err := validateDomainPattern(fmt.Sprintf("dlp.rules[%d].to[%d]", i, j), to); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateDLPAction accepts the four DLP actions.
func validateDLPAction(context, action string) error {
	switch action {
	case DLPActionAllow, DLPActionBlock, DLPActionRedact, DLPActionMonitor:
		return nil
	default:
		return fmt.Errorf("config: %s: action %q is invalid; must be one of: allow, block, redact, monitor", context, action)
	}
}

// validDLPClassSpec reports whether spec is an acceptable class key: the bare "*"
// glob, a "<family>.*" glob, an exact built-in data class, or a custom.<name> /
// custom.* referencing a declared custom class.
func validDLPClassSpec(spec string, customNames map[string]struct{}) bool {
	if spec == "*" {
		return true
	}
	if spec == "" {
		return false
	}
	if prefix, ok := strings.CutSuffix(spec, ".*"); ok {
		if prefix == "custom" {
			return true
		}
		return dlpClassFamilies()[prefix]
	}
	if name, ok := strings.CutPrefix(spec, "custom."); ok {
		_, declared := customNames[name]
		return declared
	}
	return scan.IsKnownClass(spec)
}

// dlpClassFamilies is the set of valid glob prefixes derived from the built-in
// taxonomy: each class's leading dotted segment (e.g. "pii") plus each top-level
// (dot-free) class name. "custom" is handled separately in validDLPClassSpec.
func dlpClassFamilies() map[string]bool {
	fams := map[string]bool{}
	for _, c := range scan.KnownDataClasses() {
		s := string(c)
		if i := strings.IndexByte(s, '.'); i >= 0 {
			fams[s[:i]] = true
		} else {
			fams[s] = true
		}
	}
	return fams
}
