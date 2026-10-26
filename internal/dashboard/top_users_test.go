package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

type topUsersBody struct {
	Totals   struct{ Requests, Denied int } `json:"totals"`
	TopUsers []analytics.UserCount          `json:"topUsers"`
}

func getTopUsers(t *testing.T, h http.Handler, query string) topUsersBody {
	t.Helper()
	rr := doGet(t, h, "/dashboard/api/analytics"+query)
	if rr.Code != http.StatusOK {
		t.Fatalf("analytics%s: status %d (%s)", query, rr.Code, rr.Body.String())
	}
	var b topUsersBody
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return b
}

func TestAnalyticsTopUsers(t *testing.T) {
	now := time.Now().UTC()
	ds := &fakeDataSource{}
	// 12 users; user i has i+1 events (the first is a deny), plus 3 unattributed.
	for i := 0; i < 12; i++ {
		for n := 0; n <= i; n++ {
			dec := "allow"
			if n == 0 {
				dec = "deny"
			}
			ds.events = append(ds.events, analytics.Event{
				Timestamp: now, Domain: "a.example", Decision: dec,
				UserSub: fmt.Sprintf("sub-%02d", i), UserEmail: fmt.Sprintf("u%02d@corp", i),
			})
		}
	}
	for n := 0; n < 3; n++ {
		ds.events = append(ds.events, analytics.Event{Timestamp: now, Domain: "a.example", Decision: "allow"})
	}
	h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	got := getTopUsers(t, h, "?range=24h").TopUsers

	if len(got) != analytics.MaxTopUsers {
		t.Fatalf("topUsers has %d entries, want %d", len(got), analytics.MaxTopUsers)
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].Count > got[j].Count }) {
		t.Errorf("not sorted by count descending: %+v", got)
	}
	if got[0].Sub != "sub-11" || got[0].Count != 12 || got[0].Denied != 1 || got[0].Email != "u11@corp" {
		t.Errorf("first = %+v, want sub-11 u11@corp count 12 denied 1", got[0])
	}
	unattributed := 0
	for _, u := range got {
		if u.Unattributed {
			unattributed++
			if u.Count != 3 || u.Sub != "" {
				t.Errorf("unattributed bucket = %+v, want count 3 and empty sub", u)
			}
		}
	}
	if unattributed != 1 {
		t.Errorf("unattributed buckets = %d, want exactly 1", unattributed)
	}
}

// TestAnalyticsNoIdentity pins the choice for a store with no identity data:
// topUsers is an empty list (the all-events unattributed bucket is omitted)
// and every other field of the response is as before.
func TestAnalyticsNoIdentity(t *testing.T) {
	now := time.Now().UTC()
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: now, Domain: "a.example", Method: "GET", Decision: "allow", Protocol: "https"},
		{Timestamp: now, Domain: "b.example", Method: "GET", Decision: "deny", Protocol: "https"},
	}}
	h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	rr := doGet(t, h, "/dashboard/api/analytics?range=24h")
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if string(m["topUsers"]) != "[]" {
		t.Errorf("topUsers = %s, want []", m["topUsers"])
	}
	delete(m, "topUsers")
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "blocked,compliance,cost,dlp,generatedAt,hourly,judge,methods,protocols,proxies,secrets,selectedProxy,statusClasses,timeline,topDomains,topEndpoints,totals,writes"
	if strings.Join(keys, ",") != want {
		t.Errorf("fields = %s\nwant     %s", strings.Join(keys, ","), want)
	}
	var tot struct{ Requests, Allowed, Denied int }
	_ = json.Unmarshal(m["totals"], &tot)
	if tot.Requests != 2 || tot.Allowed != 1 || tot.Denied != 1 {
		t.Errorf("totals = %+v, want 2/1/1", tot)
	}
}

// TestTopUsersWorkerAndFleet: a worker (local SQLite) and the CP (fleet SQLite)
// answer the same request with the same shape and the same breakdown.
func TestTopUsersWorkerAndFleet(t *testing.T) {
	sources := userDataSources(t)
	var bodies []string
	for _, name := range []string{"worker", "cp"} {
		h := newTestServer(sources[name], config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
		b := getTopUsers(t, h, "?range=24h")
		want := []analytics.UserCount{
			{Sub: "sub-alice", Email: "alice@corp", Count: 2, Denied: 1},
			{Sub: "sub-bob", Email: "bob@corp", Count: 1},
		}
		out, _ := json.Marshal(b.TopUsers)
		bodies = append(bodies, string(out))
		wantJSON, _ := json.Marshal(want)
		if string(out) != string(wantJSON) {
			t.Errorf("%s: topUsers = %s, want %s", name, out, wantJSON)
		}
		// ?user= narrows the breakdown to that person.
		one := getTopUsers(t, h, "?range=24h&user=bob@corp").TopUsers
		if len(one) != 1 || one[0].Sub != "sub-bob" {
			t.Errorf("%s: user=bob topUsers = %+v", name, one)
		}
	}
	if bodies[0] != bodies[1] {
		t.Errorf("worker and fleet differ:\n%s\n%s", bodies[0], bodies[1])
	}
}

func TestEndpointsUserFilter(t *testing.T) {
	now := time.Now().UTC()
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: now, Domain: "a.example", Method: "GET", URL: "https://a.example/alice", Decision: "allow", UserSub: "sub-alice"},
		{Timestamp: now, Domain: "a.example", Method: "GET", URL: "https://a.example/bob", Decision: "allow", UserSub: "sub-bob"},
	}}
	h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	var resp struct {
		Items []struct{ URL string } `json:"items"`
	}
	doGetJSON(t, h, "/dashboard/api/endpoints?user=sub-bob", &resp)
	if len(resp.Items) != 1 || resp.Items[0].URL != "https://a.example/bob" {
		t.Errorf("user=sub-bob endpoints = %+v", resp.Items)
	}
	if rr := doGet(t, h, "/dashboard/api/endpoints?user="+strings.Repeat("a", 321)); rr.Code != http.StatusBadRequest {
		t.Errorf("321-char user: status %d, want 400", rr.Code)
	}
}

// --- served HTML ---

func servedIndex(t *testing.T) string {
	t.Helper()
	h := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	rr := doGet(t, h, "/dashboard/")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /dashboard/: status %d", rr.Code)
	}
	return rr.Body.String()
}

func TestIndexUserFilterPresent(t *testing.T) {
	html := servedIndex(t)
	for _, want := range []string{
		`id="actUser"`,                // the filter box
		`maxlength="320"`,             // bounded in the markup...
		`const USER_FILTER_MAX = 320`, // ...and in the script
		`'user='+encodeURIComponent(state.user)`,
		`withQS('/dashboard/api/traffic')`,
		`withQS('/dashboard/api/analytics?`,
		`id="topUsersBody"`, // the top-users table
		`<th>User</th>`,     // the user column
	} {
		if !strings.Contains(html, want) {
			t.Errorf("served index.html lacks %q", want)
		}
	}
}

// claimTokens match identifiers that carry IdP claim values in the page script.
var claimTokens = regexp.MustCompile(`user_email|user_sub|user_groups|UserEmail|UserSub|UserGroups|\bu\.(?:sub|email)\b|userCell\(`)

// htmlSinks are the DOM and string APIs that parse markup.
var htmlSinks = regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\besc\(`)

// Limit: it is statement-local, so a claim aliased into a variable first
// (const x = e.user_email; el.innerHTML = x) is not caught; review covers that.
//
// claimMarkupViolations reports every statement that assigns innerHTML (or
// otherwise builds markup) from a claim-derived value. A statement runs from a
// line holding a sink to the first line that ends in ';'.
func claimMarkupViolations(html string) []string {
	lines := strings.Split(html, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		if !htmlSinks.MatchString(lines[i]) {
			continue
		}
		stmt := lines[i]
		j := i
		for !strings.HasSuffix(strings.TrimSpace(lines[j]), ";") && j+1 < len(lines) && j-i < 12 {
			j++
			stmt += "\n" + lines[j]
		}
		if claimTokens.MatchString(stmt) {
			out = append(out, fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(lines[i])))
		}
	}
	return out
}

func TestIndexRendersClaimsAsText(t *testing.T) {
	html := servedIndex(t)
	if v := claimMarkupViolations(html); len(v) > 0 {
		t.Fatalf("claim-derived values reach markup:\n%s", strings.Join(v, "\n"))
	}
	// The user cells really are written with textContent.
	for _, want := range []string{"ut.textContent=who", "who.textContent=userCell(u.email, u.sub)"} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}

	// The checker itself must fail when a user field is concatenated into innerHTML.
	for name, bad := range map[string]string{
		"concatenated email": `tr.innerHTML='<td>'+e.user_email+'</td>';`,
		"escaped sub":        `td.innerHTML=esc(e.user_sub);`,
		"multi-line":         "tr.innerHTML='<td>x</td>'\n  +'<td>'+userCell(u.email,u.sub)+'</td>';",
		"group field":        `el.innerHTML = e.user_groups.join(',');`,
		"top users row":      `row.innerHTML = u.email;`,
	} {
		if len(claimMarkupViolations(bad)) == 0 {
			t.Errorf("checker missed a violation (%s): %s", name, bad)
		}
	}
	if v := claimMarkupViolations(`td.textContent = e.user_email;`); len(v) != 0 {
		t.Errorf("textContent assignment flagged: %v", v)
	}
}
