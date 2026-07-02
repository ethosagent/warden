package scan

// DataClass is a first-class, policy-facing sensitivity category for a finding.
// Unlike the flat Category (kept for back-compat with the response scanner and
// MCP gateway), DataClass uses a dotted hierarchy so egress rules can address a
// whole family (`pii.*`) or one leaf (`pii.financial`). One Detection may carry
// MULTIPLE classes — a PEM private key in a diff is both credentials AND
// source_code — so Detection.Classes is a slice, not a scalar.
type DataClass string

// The taxonomy. custom.<name> is intentionally absent: it needs the Phase 3
// config block to declare operator-supplied classes, so it is not a compile-time
// constant here.
const (
	ClassCredentials    DataClass = "credentials"
	ClassPIIContact     DataClass = "pii.contact"
	ClassPIIIdentity    DataClass = "pii.identity"
	ClassPIIFinancial   DataClass = "pii.financial"
	ClassPIIHealth      DataClass = "pii.health"
	ClassSourceCode     DataClass = "source_code"
	ClassInfrastructure DataClass = "infrastructure"
)

// patternClasses is the pattern-name -> data-class(es) mapping. IT IS THE
// CONTRACT with plan/Feat-Pattern-Depth.md: that plan grows the raw COUNT of
// credential/injection/PII patterns; when it adds a pattern it adds (or inherits)
// a class HERE, and detector code never changes. Resolution order at scan time
// (classesFor):
//
//  1. an explicit entry in this table (per-pattern override), else
//  2. the category fallback in categoryClasses (coarse, category-derived), else
//  3. no class (nil) — the Detection still carries Category for back-compat.
//
// A pattern with no mapping and an unmapped category emits Category-only (no
// DataClass) rather than guessing wrong; the fallback below covers the known
// categories so a newly added pattern in an existing family inherits a class for
// free.
var patternClasses = map[string][]DataClass{
	// --- credentials (the existing 7) ---
	"aws_access_key": {ClassCredentials},
	"aws_secret_key": {ClassCredentials},
	"github_token":   {ClassCredentials},
	"stripe_key":     {ClassCredentials},
	"jwt":            {ClassCredentials},
	// A PEM private key is a credential AND source-control artifact — the
	// canonical multi-class case.
	"private_key":     {ClassCredentials, ClassSourceCode},
	"generic_api_key": {ClassCredentials},

	// --- PII (existing) ---
	"email": {ClassPIIContact},
	"phone": {ClassPIIContact},
	"card":  {ClassPIIFinancial},
	"ssn":   {ClassPIIIdentity},

	// --- pii.identity (new) ---
	"aadhaar":  {ClassPIIIdentity},
	"pan":      {ClassPIIIdentity},
	"uk_ni":    {ClassPIIIdentity},
	"eu_vat":   {ClassPIIIdentity},
	"passport": {ClassPIIIdentity},

	// --- pii.financial (new) ---
	"iban":        {ClassPIIFinancial},
	"aba_routing": {ClassPIIFinancial},

	// --- pii.health (new, opt-in) ---
	"health_diagnosis":  {ClassPIIHealth},
	"health_medication": {ClassPIIHealth},
	"health_icd10":      {ClassPIIHealth},

	// --- infrastructure (new) ---
	"private_ip":        {ClassInfrastructure},
	"internal_hostname": {ClassInfrastructure},
	"aws_arn":           {ClassInfrastructure},
	"aws_resource_id":   {ClassInfrastructure},
	"k8s_manifest":      {ClassInfrastructure},

	// --- source_code (new; classifiers, one per language family) ---
	"code_go":         {ClassSourceCode},
	"code_python":     {ClassSourceCode},
	"code_javascript": {ClassSourceCode},
	"code_java":       {ClassSourceCode},
	"code_c":          {ClassSourceCode},
	"code_csharp":     {ClassSourceCode},
	"code_ruby":       {ClassSourceCode},
	"code_rust":       {ClassSourceCode},
	"code_php":        {ClassSourceCode},
	"code_shell":      {ClassSourceCode},
	"code_shebang":    {ClassSourceCode},
	"code_density":    {ClassSourceCode},
	"code_vcs":        {ClassSourceCode},
}

// categoryClasses is the coarse fallback: a pattern with no patternClasses entry
// inherits the class(es) of its Category. "injection" is deliberately ABSENT —
// prompt injection is threat detection, not a data class, so injection findings
// carry an empty Classes and can never gain a DLP data class. The "pii" fallback
// is the least-sensitive bucket (pii.contact); it only bites a future PII pattern
// that forgot its explicit entry, and even then still matches a `pii.*` rule.
var categoryClasses = map[string][]DataClass{
	"credential_leak": {ClassCredentials},
	"pii":             {ClassPIIContact},
	"infrastructure":  {ClassInfrastructure},
	"source_code":     {ClassSourceCode},
}

// classesFor resolves a detection's data classes from its pattern name (exact
// override) then its category (coarse fallback). Returns nil when neither maps —
// e.g. injection findings, which are threat detections, not data classes.
func classesFor(pattern, category string) []DataClass {
	if cs, ok := patternClasses[pattern]; ok {
		return cs
	}
	return categoryClasses[category]
}

// knownClasses is the set of BUILT-IN data classes. custom.<name> is deliberately
// absent — those are operator-declared in the dlp config block, not compile-time
// constants. It backs IsKnownClass / KnownDataClasses so config validation can vet
// a rule's class key without importing the taxonomy by hand.
var knownClasses = map[DataClass]struct{}{
	ClassCredentials:    {},
	ClassPIIContact:     {},
	ClassPIIIdentity:    {},
	ClassPIIFinancial:   {},
	ClassPIIHealth:      {},
	ClassSourceCode:     {},
	ClassInfrastructure: {},
}

// IsKnownClass reports whether c is a built-in data class (custom.<name> excluded).
// Config validation uses it to accept an exact class key in a dlp rule.
func IsKnownClass(c string) bool {
	_, ok := knownClasses[DataClass(c)]
	return ok
}

// KnownDataClasses returns the built-in data classes (custom.<name> excluded), so
// config validation can derive the set of valid class keys and glob families
// (e.g. "pii") without hardcoding the taxonomy a second time.
func KnownDataClasses() []DataClass {
	out := make([]DataClass, 0, len(knownClasses))
	for c := range knownClasses {
		out = append(out, c)
	}
	return out
}

// CustomClass is an operator-declared data class: a name (surfaced as the
// DataClass custom.<Name>), a regex compiled at scanner build, and a severity.
// It is supplied through WithCustomClasses and flows through the SAME detection →
// class → rule evaluation path as the built-in classes. Custom regexes are
// operator config (not secrets), so they are fine on the local scanner.
type CustomClass struct {
	Name     string // custom.<Name> becomes the emitted DataClass
	Regex    string // operator-supplied pattern, compiled at NewScanner time
	Severity string // "low" | "medium" | "high"; empty defaults to medium
}
