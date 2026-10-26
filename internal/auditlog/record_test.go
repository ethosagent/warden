package auditlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
)

var testMeta = Meta{ProxyID: "px-1", ProxyIDSource: "config", AgentID: "agent-a", BootID: "boot-1"}

func marshal(t *testing.T, r Record) []byte {
	t.Helper()
	b, err := r.MarshalLine()
	if err != nil {
		t.Fatalf("MarshalLine: %v", err)
	}
	return b
}

func TestFromEvent_URL(t *testing.T) {
	ev := analytics.Event{URL: "https://u:p@api.example.test/v1/x?token=abc#frag"}

	r := FromEvent(ev, testMeta, QueryDrop)
	if r.URLPath != "/v1/x" || r.QueryKeys != nil {
		t.Fatalf("drop: url_path=%q query_keys=%v", r.URLPath, r.QueryKeys)
	}
	line := string(marshal(t, r))
	for _, leak := range []string{"token", "abc", "u:p", "frag", "api.example.test"} {
		if strings.Contains(line, leak) {
			t.Fatalf("line leaks %q: %s", leak, line)
		}
	}

	r = FromEvent(ev, testMeta, QueryKeys)
	if r.URLPath != "/v1/x" || len(r.QueryKeys) != 1 || r.QueryKeys[0] != "token" {
		t.Fatalf("keys: url_path=%q query_keys=%v", r.URLPath, r.QueryKeys)
	}
	line = string(marshal(t, r))
	if !strings.Contains(line, `"query_keys":["token"]`) {
		t.Fatalf("line lacks query_keys: %s", line)
	}
	for _, leak := range []string{"abc", "u:p", "frag"} {
		if strings.Contains(line, leak) {
			t.Fatalf("line leaks %q: %s", leak, line)
		}
	}
}

func TestFromEvent_URLShapes(t *testing.T) {
	cases := []struct {
		name, in string
		q        QueryMode
		path     string
		keys     []string
	}{
		{"escaped path kept", "https://h/a%20b/c?x=1", QueryDrop, "/a%20b/c", nil},
		{"keys sorted deduped", "https://h/p?b=1&a=2&b=3&c&=v&d%20e=4", QueryKeys, "/p", []string{"a", "b", "c", "d e"}},
		{"no query no keys", "https://h/p", QueryKeys, "/p", nil},
		{"bare host", "https://h", QueryDrop, "", nil},
		{"unparseable falls back", "http://u:p@h/p/q?k=v#f%zz\x7f", QueryKeys, "/p/q", []string{"k"}},
		{"unparseable keeps only the path", "ht tp://[bad/p?k=v", QueryDrop, "/p", nil},
		{"empty", "", QueryKeys, "", nil},
		{"control chars stripped", "https://h/a\nb", QueryDrop, "/ab", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := FromEvent(analytics.Event{URL: c.in}, testMeta, c.q)
			if r.URLPath != c.path {
				t.Fatalf("url_path = %q, want %q", r.URLPath, c.path)
			}
			if fmt.Sprint(r.QueryKeys) != fmt.Sprint(c.keys) {
				t.Fatalf("query_keys = %v, want %v", r.QueryKeys, c.keys)
			}
		})
	}
}

func TestFromEvent_URLBounds(t *testing.T) {
	r := FromEvent(analytics.Event{URL: "https://h/" + strings.Repeat("%41", 2000)}, testMeta, QueryDrop)
	if len(r.URLPath) > maxURLPathBytes || strings.HasSuffix(r.URLPath, "%") || strings.HasSuffix(r.URLPath[:len(r.URLPath)-1], "%") {
		t.Fatalf("url_path len %d / bad tail %q", len(r.URLPath), r.URLPath[len(r.URLPath)-3:])
	}

	var q []string
	for i := 0; i < 100; i++ {
		q = append(q, fmt.Sprintf("%03d%s=1", i, strings.Repeat("k", 80)))
	}
	r = FromEvent(analytics.Event{URL: "https://h/p?" + strings.Join(q, "&")}, testMeta, QueryKeys)
	if len(r.QueryKeys) != maxQueryKeys {
		t.Fatalf("query_keys = %d names, want %d", len(r.QueryKeys), maxQueryKeys)
	}
	for _, k := range r.QueryKeys {
		if len(k) > maxQueryKeyBytes {
			t.Fatalf("key of %d bytes", len(k))
		}
	}
}

func TestFromEvent_Identity(t *testing.T) {
	base := analytics.Event{UserSub: "sub-1", UserEmail: "a@b.test", UserSID: "sid-1", UserGroups: []string{"g1"}}

	t.Run("invalid status carries no claims", func(t *testing.T) {
		ev := base
		ev.IdentityStatus = "invalid"
		line := string(marshal(t, FromEvent(ev, testMeta, QueryDrop)))
		if !strings.Contains(line, `"user":{"status":"invalid"}`) {
			t.Fatalf("want bare user.status: %s", line)
		}
		for _, leak := range []string{"sub-1", "a@b.test", "sid-1", "g1", `"sub"`, `"groups"`} {
			if strings.Contains(line, leak) {
				t.Fatalf("line leaks %q: %s", leak, line)
			}
		}
	})

	t.Run("no status omits the user object", func(t *testing.T) {
		line := string(marshal(t, FromEvent(base, testMeta, QueryDrop)))
		if strings.Contains(line, `"user"`) || strings.Contains(line, "sub-1") {
			t.Fatalf("unattributed event must carry no user: %s", line)
		}
	})

	t.Run("valid status carries claims, groups capped", func(t *testing.T) {
		ev := base
		ev.IdentityStatus = "valid"
		for i := 0; i < 200; i++ {
			ev.UserGroups = append(ev.UserGroups, fmt.Sprintf("group-%d", i))
		}
		r := FromEvent(ev, testMeta, QueryDrop)
		u := r.User
		if u == nil || u.Status != "valid" || u.Sub != "sub-1" || u.Email != "a@b.test" || u.SID != "sid-1" {
			t.Fatalf("user = %+v", u)
		}
		if len(u.Groups) != maxGroups || !u.GroupsTruncated {
			t.Fatalf("groups = %d truncated=%v", len(u.Groups), u.GroupsTruncated)
		}
	})

	t.Run("verifier truncation flag and long entries propagate", func(t *testing.T) {
		ev := analytics.Event{IdentityStatus: "valid", UserGroups: []string{"g"}, UserGroupsTruncated: true}
		if u := FromEvent(ev, testMeta, QueryDrop).User; !u.GroupsTruncated {
			t.Fatal("verifier-set truncation must survive")
		}
		ev = analytics.Event{IdentityStatus: "valid", UserGroups: []string{strings.Repeat("g", 300)}}
		u := FromEvent(ev, testMeta, QueryDrop).User
		if len(u.Groups[0]) != maxGroupBytes || !u.GroupsTruncated {
			t.Fatalf("long entry: len=%d truncated=%v", len(u.Groups[0]), u.GroupsTruncated)
		}
	})
}

func TestMarshalLine_Caps(t *testing.T) {
	ev := analytics.Event{
		Timestamp:      time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC),
		JudgeReason:    "ok\n\x00\x1b[31m" + strings.Repeat("j", 30<<10),
		IdentityStatus: "valid",
		UserSub:        "s",
	}
	for i := 0; i < 200; i++ {
		ev.UserGroups = append(ev.UserGroups, strings.Repeat("g", 250)+fmt.Sprint(i))
	}
	r := FromEvent(ev, testMeta, QueryDrop)
	if len(r.JudgeReason) > maxJudgeBytes || strings.ContainsAny(r.JudgeReason, "\n\x00\x1b") {
		t.Fatalf("judge_reason len=%d %q", len(r.JudgeReason), r.JudgeReason[:12])
	}

	line := marshal(t, r)
	if len(line) > MaxLineBytes {
		t.Fatalf("line is %d bytes, cap %d", len(line), MaxLineBytes)
	}
	if bytes.Count(line, []byte("\n")) != 1 || line[len(line)-1] != '\n' {
		t.Fatal("want exactly one trailing newline")
	}
	var back map[string]any
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if back["truncated"] != true {
		t.Fatalf("truncated = %v", back["truncated"])
	}
	if _, ok := back["groups"]; ok {
		t.Fatal("unexpected top-level groups")
	}
}

func TestMarshalLine_SmallRecordUntouched(t *testing.T) {
	r := FromEvent(analytics.Event{Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC), Decision: "allow", Domain: "d.test"}, testMeta, QueryDrop)
	r.Seq = 7
	line := string(marshal(t, r))
	const prefix = `{"schema":"warden.decision.v1","schema_rev":1,"ts":"2026-01-02T03:04:05.000000006Z","proxy_id":"px-1","proxy_id_source":"config","agent_id":"agent-a","boot_id":"boot-1","seq":7,"decision":"allow",`
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("key order/shape changed: %s", line)
	}
	for _, k := range []string{`"time"`, `"level"`, `"msg"`, "truncated"} {
		if strings.Contains(line, k) {
			t.Fatalf("unexpected %s in %s", k, line)
		}
	}
}

func TestFromEvent_NeverMapsSecretRef(t *testing.T) {
	const secret = "sk-FAKE-do-not-leak-1234"
	ev := analytics.Event{
		Timestamp: time.Now(), Domain: "api.example.test", Port: 443, Protocol: "https", Method: "POST",
		URL: "https://api.example.test/v1", Decision: "deny", Reason: "dlp_block", ResponseStatus: 403,
		SecretRef: secret, Evidence: []string{secret, "••••1234 (len 24)"}, AddrClass: secret, UID: secret,
		Tool: "t", Provider: "p", CostUSD: 0.5, DLPAction: "block", DLPRule: "rule[1]", DLPPartial: true, DLPEncoded: true,
		DataClasses: []string{"credentials"}, SwappedRefs: []string{"{{OPENAI_API_KEY}}"}, Compliance: []string{"owasp:LLM01"},
		JudgeReason: "because", LatencyMs: 12, IdentityStatus: "valid", UserSub: "s", IdentityReason: secret, ProxyID: secret,
	}
	line := string(marshal(t, FromEvent(ev, testMeta, QueryKeys)))
	if strings.Contains(line, secret) || strings.Contains(line, "1234") {
		t.Fatalf("line leaks an excluded field: %s", line)
	}
	for _, want := range []string{`"reason":"dlp_block"`, `"swapped_refs":["{{OPENAI_API_KEY}}"]`, `"dlp_partial":true`, `"proxy_id":"px-1"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("line lacks %s: %s", want, line)
		}
	}
}

// Every excluded field must exist on analytics.Event, carry a reason, and be
// absent from the Record's JSON keys.
func TestExcludedEventFields(t *testing.T) {
	evType := reflect.TypeOf(analytics.Event{})
	for name, why := range ExcludedEventFields() {
		if _, ok := evType.FieldByName(name); !ok {
			t.Errorf("%s is not an analytics.Event field", name)
		}
		if why == "" {
			t.Errorf("%s has no reason", name)
		}
	}
}

// Optional fields are dropped one at a time in the documented order, stopping as
// soon as the line fits.
func TestMarshalLine_DropOrder(t *testing.T) {
	big := func(n int) []string {
		out := make([]string, 64)
		for i := range out {
			out[i] = strings.Repeat("x", n)
		}
		return out
	}
	// Each list is ~8 KiB at 128 bytes x 64 entries: two lists overflow the cap.
	ev := analytics.Event{DataClasses: big(120), SwappedRefs: big(120), Compliance: big(120), JudgeReason: strings.Repeat("j", 400)}
	line := marshal(t, FromEvent(ev, testMeta, QueryDrop))
	var back Record
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatal(err)
	}
	if len(line) > MaxLineBytes || !back.Truncated {
		t.Fatalf("len=%d truncated=%v", len(line), back.Truncated)
	}
	if back.DataClasses != nil || back.SwappedRefs != nil {
		t.Fatal("data_classes and swapped_refs must go first")
	}
	if back.Compliance == nil || back.JudgeReason == "" {
		t.Fatal("compliance and judge_reason must survive when dropping earlier fields is enough")
	}
}
