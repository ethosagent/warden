package harness

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Canary returns a fresh marker token, "CANARY-" + 24 random hex chars.
// Scenarios plant it where a secret would go (WithSecret value, request body,
// header) and AssertCanaryNeverLeaked proves it never came back out.
func Canary() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is an environment fault, not a scenario outcome.
		panic("harness: canary randomness: " + err.Error())
	}
	return "CANARY-" + hex.EncodeToString(b)
}

// leakForm is one rendering of a secret value the sweep matches, with the
// encoding's name for the failure message.
type leakForm struct {
	form string
	name string
}

// leakForms renders one secret value in every encoding a leak could plausibly
// take on the wire or in storage: raw, base64 (std + url alphabets, padded and
// unpadded — a body-length framing or a decoder in non-strict mode drops the
// padding), hex (both cases), the two URL escapes, and base64 at the two
// shifted bit alignments.
//
// Alignment-shifted base64: a base64 blob only shows encode(v) as a substring
// when v starts on a 3-byte group boundary. Embedded after a prefix of length
// ≡ 1 or 2 (mod 3) — `Basic ` + base64("user:"+v) being the canonical case —
// v's base64 lands on a different bit alignment and the plain forms never
// appear. For prefix remainder k, the blob's chars that lie ENTIRELY inside
// v's bits depend on v alone: encode("\x00"×k + v), dropping the first
// ceil(8k/6) chars (they still carry filler bits from the zeros) and the last
// char (it carries the following data's or padding's bits). The substring does
// not itself decode to v — it is the alignment's window onto v's bits, which is
// exactly what substring matching needs.
//
// The oracle deliberately does NOT see: base32/base85 or other exotic bases,
// MIME line-wrapped base64 (inserted newlines break Contains), nested
// encodings beyond one level (base64 of base64), compressed or encrypted
// renderings, JSON/HTML entity-escaped forms (an ASCII letter spelled as a
// numeric character reference, e.g. HTML's ampersand-hash-x-41), a value split
// across fields or chunks so no single string holds a whole form, and any
// surface outside the oracles (a real upstream not registered through
// h.Upstream, the agent's own memory or disk, DNS, traffic that never
// traversed the worker).
func leakForms(v string) []leakForm {
	forms := []leakForm{
		{v, "raw"},
		{base64.StdEncoding.EncodeToString([]byte(v)), "base64"},
		{base64.RawStdEncoding.EncodeToString([]byte(v)), "base64-unpadded"},
		{base64.URLEncoding.EncodeToString([]byte(v)), "base64url"},
		{base64.RawURLEncoding.EncodeToString([]byte(v)), "base64url-unpadded"},
		{hex.EncodeToString([]byte(v)), "hex"},
		{strings.ToUpper(hex.EncodeToString([]byte(v))), "HEX"},
		{url.QueryEscape(v), "url-query-escaped"},
		{url.PathEscape(v), "url-path-escaped"},
	}
	for _, spec := range []struct {
		enc  *base64.Encoding
		name string
	}{
		{base64.StdEncoding, "base64"},
		{base64.URLEncoding, "base64url"},
	} {
		for k := 1; k <= 2; k++ {
			s := spec.enc.EncodeToString([]byte(strings.Repeat("\x00", k) + v))
			forms = append(forms, leakForm{
				form: s[(8*k+5)/6 : len(s)-1],
				name: fmt.Sprintf("%s@shift%d", spec.name, k),
			})
		}
	}
	// Dedupe identical renderings, keeping the first (most specific) name: for
	// values with no reserved characters the URL escapes coincide with raw, and
	// a value whose length needs no padding makes padded and unpadded agree.
	seen := make(map[string]bool, len(forms))
	out := make([]leakForm, 0, len(forms))
	for _, f := range forms {
		if seen[f.form] {
			continue
		}
		seen[f.form] = true
		out = append(out, f)
	}
	return out
}

// unswappedForm names the violation where the PLACEHOLDER, not the value,
// reached an in-scope upstream: the swap was skipped.
const unswappedForm = "unswapped placeholder"

// leak is one place a canary surfaced.
type leak struct {
	secret string // the WithSecret name
	form   string // encoding it appeared in
	where  string // oracle surface + location
}

// AssertCanaryNeverLeaked sweeps every oracle surface — what the agent got
// back, what the components logged, what landed in analytics, what the metric
// labels carry, and what every fake upstream received — for every WithSecret
// value, in any leak form. The ONE exception: a value arriving at a host
// inside its own matchHosts scope is the intended swap, not a leak.
//
// A WithSecret PLACEHOLDER arriving at an upstream inside that secret's scope
// is a violation too (the swap never happened), reported as an "unswapped
// placeholder" hit.
//
// Call it at the END of a scenario, after all traffic. It fails the test
// naming each hit's location.
func (h *H) AssertCanaryNeverLeaked() {
	h.tb.Helper()
	h.assertCanaryNeverLeaked(h.tb)
}

func (h *H) assertCanaryNeverLeaked(tb testing.TB) {
	tb.Helper()
	if lines := h.canaryLeaks(tb); len(lines) > 0 {
		tb.Fatalf("harness: CANARY LEAKED in %d place(s):%s", len(lines), "\n  - "+strings.Join(lines, "\n  - "))
	}
}

// CanaryLeaks runs the same sweep as AssertCanaryNeverLeaked but RETURNS what it
// found (one line per hit, empty when clean) instead of failing the test. It
// exists for known-violation scenarios, which must assert that a documented
// leak STILL happens — and fail loudly the day it stops — rather than skip.
func (h *H) CanaryLeaks() []string {
	h.tb.Helper()
	return h.canaryLeaks(h.tb)
}

// canaryLeaks is the sweep: it returns one description per (secret, surface)
// hit. It fails tb only when the sweep itself cannot run.
func (h *H) canaryLeaks(tb testing.TB) []string {
	tb.Helper()
	if len(h.secrets) == 0 {
		tb.Fatalf("harness: AssertCanaryNeverLeaked but no WithSecret secrets registered; nothing is being guarded")
	}

	var leaks []leak
	// seenHits caps the report at one line per (secret, surface): several forms
	// can match the same hit (unpadded base64 is contained in its padded form),
	// and the line names the place and the encoding, not every alias.
	seenHits := make(map[string]bool)
	// record checks one surface for one secret's forms and appends the first
	// match. skipRaw excuses the RAW value — the intended swap when the surface
	// is an upstream inside the secret's own scope.
	record := func(sec secretSpec, where, s string, skipRaw bool) {
		for _, f := range leakForms(sec.value) {
			if skipRaw && f.form == sec.value {
				continue
			}
			if strings.Contains(s, f.form) {
				key := sec.name + "\x00" + where
				if !seenHits[key] {
					seenHits[key] = true
					leaks = append(leaks, leak{secret: sec.name, form: f.name, where: where})
				}
				return
			}
		}
	}
	scan := func(where, s string) {
		if s == "" {
			return
		}
		for _, sec := range h.secrets {
			record(sec, where, s, false)
		}
	}

	// 1. The agent's transcript: bodies, response headers, URLs.
	for i, r := range h.AgentResponses() {
		scan(fmt.Sprintf("agent response #%d body (%s)", i, r.URL), string(r.Body))
		scan(fmt.Sprintf("agent response #%d headers (%s)", i, r.URL), headersText(r.Header))
		scan(fmt.Sprintf("agent response #%d url", i), r.URL)
	}

	// 2. Worker + control-plane logs.
	scan("worker/control-plane logs", h.Logs())

	// 3. Analytics events, serialized whole (fields AND string values).
	for i, e := range h.Events() {
		blob, err := json.Marshal(e)
		if err != nil {
			tb.Fatalf("harness: marshal analytics event #%d: %v", i, err)
		}
		scan(fmt.Sprintf("analytics event #%d (domain %s)", i, e.Domain), string(blob))
	}

	// 4. Metric names and label values (values are floats; only keys can carry).
	for key := range h.Metrics() {
		scan("metric key "+key, key)
	}

	// 5. Every fake upstream's recorded requests. The ONE exception: the RAW
	// value arriving at a host inside its own matchHosts scope is the swap
	// working as designed. Every ENCODED form is a leak wherever it lands —
	// the worker's swap never encodes, so base64/hex/escaped forms mean the
	// value traveled outside the pipeline's intended shape.
	for _, u := range h.upstreamsSnapshot() {
		for i, req := range u.Requests() {
			where := fmt.Sprintf("upstream %s request #%d (%s %s)", u.host, i, req.Method, req.Path)
			blob := headersText(req.Header) + req.Path + "\x00" + string(req.Body)
			for _, sec := range h.secrets {
				inScope := hostAllowed(sec.matchHosts, u.host)
				record(sec, where, blob, inScope)
				// The placeholder arriving at a host the secret is scoped to means
				// the swap did not happen: the agent's stand-in reached the upstream
				// instead of the real credential. Outside the scope the placeholder
				// is correctly left alone.
				if key := sec.name + "\x00" + where; inScope && sec.placeholder != "" &&
					strings.Contains(blob, sec.placeholder) && !seenHits[key] {
					seenHits[key] = true
					leaks = append(leaks, leak{secret: sec.name, form: unswappedForm, where: where})
				}
			}
		}
	}

	lines := make([]string, 0, len(leaks))
	for _, l := range leaks {
		lines = append(lines, fmt.Sprintf("secret %q appeared %s in %s", l.secret, l.form, l.where))
	}
	return lines
}

// headersText renders headers deterministically (sorted) for scanning.
func headersText(h map[string][]string) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// hostAllowed applies the harness's host-pattern dialect: exact, "*.suffix",
// or "~regex". No patterns means everywhere is allowed (an unscoped secret
// may be swapped for any destination).
func hostAllowed(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		switch {
		case strings.HasPrefix(p, "~"):
			re, err := regexp.Compile(p[1:])
			if err == nil && re.MatchString(host) {
				return true
			}
		case strings.HasPrefix(p, "*."):
			if strings.HasSuffix(host, p[1:]) {
				return true
			}
		case p == host:
			return true
		}
	}
	return false
}

// upstreamsSnapshot is the registry copied under lock for the canary sweep.
func (h *H) upstreamsSnapshot() []*Upstream {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*Upstream, 0, len(h.upstreams))
	for _, u := range h.upstreams {
		out = append(out, u)
	}
	return out
}
