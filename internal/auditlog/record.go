// Package auditlog turns stored analytics events into the closed JSON decision
// record (warden.decision.v1) that a SIEM shipper reads, one line per event.
//
// Record is a closed struct and FromEvent is the ONLY mapping from
// analytics.Event: the package never marshals an Event, so SecretRef, Evidence,
// bodies, headers and any field added to Event later cannot reach a line unless
// someone maps it here on purpose. Every other Event field is listed in
// excludedEventFields.
//
// This file is pure: no goroutine and no I/O. The sink that writes lines
// (queue, rotation, metrics) is a separate ticket.
package auditlog

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ethosagent/warden/internal/analytics"
)

// Schema identifiers carried on every line.
const (
	SchemaDecisionV1 = "warden.decision.v1"
	SchemaRev        = 1
)

// QueryMode says what FromEvent may record of the request query.
type QueryMode string

const (
	// QueryDrop records no query data at all (the default; "" behaves the same).
	QueryDrop QueryMode = "drop"
	// QueryKeys records the sorted parameter NAMES, never values.
	QueryKeys QueryMode = "keys"
)

// Bounds. A Record's variable parts are capped so one line is bounded, and
// MarshalLine enforces MaxLineBytes as the last resort.
const (
	MaxLineBytes     = 16 << 10
	maxURLPathBytes  = 2048
	maxQueryKeys     = 64
	maxQueryKeyBytes = 64
	maxJudgeBytes    = 512
	maxGroups        = 64
	maxGroupBytes    = 256
	maxListEntries   = 64
	maxListEntryLen  = 128
	maxFieldBytes    = 256 // short identifier fields (domain, tool, ...)

	identityValid = "valid"
	tsLayout      = "2006-01-02T15:04:05.000000000Z"
)

// Meta is the per-process context stamped on every line.
type Meta struct {
	ProxyID       string
	ProxyIDSource string
	AgentID       string
	BootID        string
}

// User is the verified end-user attribution. Status is set whenever the event
// carried an identity status; every other field only when the status is valid.
type User struct {
	Status          string   `json:"status"`
	Sub             string   `json:"sub,omitempty"`
	Email           string   `json:"email,omitempty"`
	Groups          []string `json:"groups,omitempty"`
	GroupsTruncated bool     `json:"groups_truncated,omitempty"`
	SID             string   `json:"sid,omitempty"`
}

// Record is one warden.decision.v1 line. Field order here is the key order on
// the wire. Consumers must sort by ts, never by line order: ts is the worker's
// wall clock at event time and the async tee batches, so lines are not ordered.
// seq and boot_id order lines within one boot, and a gap in seq means dropped
// lines. List fields and judge_reason are omitted when empty.
type Record struct {
	Schema        string   `json:"schema"`
	SchemaRev     int      `json:"schema_rev"`
	TS            string   `json:"ts"`
	ProxyID       string   `json:"proxy_id"`
	ProxyIDSource string   `json:"proxy_id_source"`
	AgentID       string   `json:"agent_id"`
	BootID        string   `json:"boot_id"`
	Seq           uint64   `json:"seq"`
	Decision      string   `json:"decision"`
	Reason        string   `json:"reason,omitempty"`
	Protocol      string   `json:"protocol"`
	Domain        string   `json:"domain"`
	Port          int      `json:"port"`
	Method        string   `json:"method"`
	URLPath       string   `json:"url_path"`
	QueryKeys     []string `json:"query_keys,omitempty"`
	Status        int      `json:"status"`
	LatencyMs     int64    `json:"latency_ms"`
	Tool          string   `json:"tool"`
	Provider      string   `json:"provider"`
	CostUSD       float64  `json:"cost_usd"`
	DLPAction     string   `json:"dlp_action"`
	DLPRule       string   `json:"dlp_rule"`
	DLPPartial    bool     `json:"dlp_partial"`
	DataClasses   []string `json:"data_classes,omitempty"`
	SwappedRefs   []string `json:"swapped_refs,omitempty"`
	Compliance    []string `json:"compliance,omitempty"`
	JudgeReason   string   `json:"judge_reason,omitempty"`
	User          *User    `json:"user,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"`
}

// excludedEventFields lists the analytics.Event fields deliberately NOT mapped
// into Record, each with the reason. TestEventFieldsAccountedFor enforces
// that every Event field is either mapped by FromEvent or listed here.
var excludedEventFields = map[string]string{
	"SecretRef":      "references a secret by hash/last-4; a credential-adjacent value never leaves the store",
	"Evidence":       "masked scan samples; content-derived, not needed to explain a decision",
	"AddrClass":      "SSRF detail already summarised by the ssrf_* reason",
	"DLPEncoded":     "reserved and always false in this phase",
	"UID":            "set only at central sync, after the line is written",
	"ProxyID":        "set by the aggregating store at read time; the line carries Meta.ProxyID",
	"IdentityReason": "not exported in v1: a non-valid status needs no detail on the line",
}

// ExcludedEventFields returns a copy of the deliberately unmapped Event fields
// and the reason for each, for the accounting test that guards new Event fields.
func ExcludedEventFields() map[string]string {
	out := make(map[string]string, len(excludedEventFields))
	for k, v := range excludedEventFields {
		out[k] = v
	}
	return out
}

// FromEvent is the only mapping from analytics.Event to Record. It does not set
// Seq (the sink assigns it at the tee). It never fails: oversized or odd input is
// bounded or dropped, not rejected.
func FromEvent(ev analytics.Event, m Meta, q QueryMode) Record {
	path, keys := splitURL(ev.URL, q)
	r := Record{
		Schema:        SchemaDecisionV1,
		SchemaRev:     SchemaRev,
		TS:            ev.Timestamp.UTC().Format(tsLayout),
		ProxyID:       cut(m.ProxyID, maxFieldBytes),
		ProxyIDSource: cut(m.ProxyIDSource, maxFieldBytes),
		AgentID:       cut(m.AgentID, maxFieldBytes),
		BootID:        cut(m.BootID, maxFieldBytes),
		Decision:      cut(ev.Decision, maxFieldBytes),
		Reason:        cut(ev.Reason, maxFieldBytes),
		Protocol:      cut(ev.Protocol, maxFieldBytes),
		Domain:        cut(ev.Domain, maxFieldBytes),
		Port:          ev.Port,
		Method:        cut(ev.Method, maxFieldBytes),
		URLPath:       path,
		QueryKeys:     keys,
		Status:        ev.ResponseStatus,
		LatencyMs:     ev.LatencyMs,
		Tool:          cut(ev.Tool, maxFieldBytes),
		Provider:      cut(ev.Provider, maxFieldBytes),
		CostUSD:       ev.CostUSD,
		DLPAction:     cut(ev.DLPAction, maxFieldBytes),
		DLPRule:       cut(ev.DLPRule, maxFieldBytes),
		DLPPartial:    ev.DLPPartial,
		DataClasses:   boundedList(ev.DataClasses),
		SwappedRefs:   boundedList(ev.SwappedRefs),
		Compliance:    boundedList(ev.Compliance),
		JudgeReason:   cut(stripControl(ev.JudgeReason), maxJudgeBytes),
	}
	if ev.IdentityStatus != "" {
		u := &User{Status: cut(ev.IdentityStatus, maxFieldBytes)}
		if ev.IdentityStatus == identityValid {
			u.Sub = cut(ev.UserSub, maxFieldBytes)
			u.Email = cut(ev.UserEmail, maxFieldBytes)
			u.SID = cut(ev.UserSID, maxFieldBytes)
			u.Groups, u.GroupsTruncated = boundedGroups(ev.UserGroups, ev.UserGroupsTruncated)
		}
		r.User = u
	}
	return r
}

// MarshalLine returns the record as JSON plus one trailing newline, in a single
// buffer so the sink can emit it with one Write. A record over MaxLineBytes is
// shrunk by dropping optional fields in a fixed order until it fits, and
// Truncated is then set.
func (r Record) MarshalLine() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	drops := []func(*Record){
		func(r *Record) {
			if r.User != nil {
				u := *r.User
				u.Groups = nil
				r.User = &u
			}
		},
		func(r *Record) { r.DataClasses = nil },
		func(r *Record) { r.SwappedRefs = nil },
		func(r *Record) { r.Compliance = nil },
		func(r *Record) { r.JudgeReason = "" },
		func(r *Record) { r.QueryKeys = nil },
	}
	for i := 0; len(b)+1 > MaxLineBytes && i < len(drops); i++ {
		r.Truncated = true
		drops[i](&r)
		if b, err = json.Marshal(r); err != nil {
			return nil, err
		}
	}
	return append(b, '\n'), nil
}

// splitURL returns the escaped path of a recorded event URL (no scheme, host,
// userinfo, fragment or query) and, in QueryKeys mode, the sorted parameter
// names. Event.URL is already the pre-swap form (placeholders, never swapped
// values); this still never emits a value.
func splitURL(raw string, q QueryMode) (string, []string) {
	var path, rawQuery string
	if u, err := url.Parse(raw); err == nil {
		path, rawQuery = u.EscapedPath(), u.RawQuery
	} else {
		path, rawQuery = fallbackSplit(raw)
	}
	path = stripControl(path)
	if len(path) > maxURLPathBytes {
		path = cut(path, maxURLPathBytes)
		// do not end on half a percent-escape
		if i := strings.LastIndexByte(path, '%'); i >= 0 && len(path)-i < 3 {
			path = path[:i]
		}
	}
	if q != QueryKeys {
		return path, nil
	}
	return path, queryKeys(rawQuery)
}

// fallbackSplit handles a URL net/url rejects: keep only what follows the
// authority and precedes the query or fragment.
func fallbackSplit(raw string) (path, rawQuery string) {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw, rawQuery = raw[:i], raw[i+1:]
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
		if j := strings.IndexByte(raw, '/'); j >= 0 {
			raw = raw[j:]
		} else {
			raw = ""
		}
	} else if !strings.HasPrefix(raw, "/") {
		raw = ""
	}
	return raw, rawQuery
}

// queryKeys returns the sorted, de-duplicated parameter names of a raw query.
func queryKeys(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	seen := map[string]struct{}{}
	for _, part := range strings.Split(rawQuery, "&") {
		name, _, _ := strings.Cut(part, "=")
		if dec, err := url.QueryUnescape(name); err == nil {
			name = dec
		}
		name = cut(stripControl(name), maxQueryKeyBytes)
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxQueryKeys {
		keys = keys[:maxQueryKeys]
	}
	return keys
}

// boundedGroups caps the group list and reports whether anything was cut,
// including a cut the verifier already made.
func boundedGroups(groups []string, already bool) ([]string, bool) {
	truncated := already
	if len(groups) > maxGroups {
		groups, truncated = groups[:maxGroups], true
	}
	if len(groups) == 0 {
		return nil, truncated
	}
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = cut(g, maxGroupBytes)
		if len(out[i]) != len(g) {
			truncated = true
		}
	}
	return out, truncated
}

// boundedList copies a bounded identifier list; nil when empty.
func boundedList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxListEntries {
		in = in[:maxListEntries]
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = cut(s, maxListEntryLen)
	}
	return out
}

// stripControl removes control characters (newlines included).
func stripControl(s string) string {
	if strings.IndexFunc(s, unicode.IsControl) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// cut shortens s to at most n bytes without splitting a UTF-8 sequence.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
