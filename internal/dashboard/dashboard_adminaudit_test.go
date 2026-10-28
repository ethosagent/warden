package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// fakeAdminAudit is an in-memory AdminAuditSource over seq 1..n. Verify fails
// at tampered (when set and reached); with block set it waits on it after
// signalling entered.
type fakeAdminAudit struct {
	mu       sync.Mutex
	entries  []AdminAuditEntry // oldest first
	tampered int64
	keys     []AdminAuditKey
	err      error
	lastQ    AdminAuditQuery
	lastV    AdminAuditVerifyRequest
	entered  chan struct{}
	block    chan struct{}
}

func newFakeAdminAudit(n int) *fakeAdminAudit {
	f := &fakeAdminAudit{}
	for i := 1; i <= n; i++ {
		f.entries = append(f.entries, AdminAuditEntry{
			Seq: int64(i), Action: "policy.write", Outcome: "ok", ActorID: fmt.Sprintf("actor-%d", i%3),
			ActorSub: "alice", ActorEmail: "alice@example.com", KeyID: "k1",
		})
	}
	return f
}

func (f *fakeAdminAudit) List(_ context.Context, q AdminAuditQuery) ([]AdminAuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastQ = q
	if f.err != nil {
		return nil, f.err
	}
	var out []AdminAuditEntry
	for i := len(f.entries) - 1; i >= 0 && len(out) < q.Limit; i-- {
		e := f.entries[i]
		if q.Cursor > 0 && e.Seq >= q.Cursor {
			continue
		}
		if q.Action != "" && e.Action != q.Action {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeAdminAudit) Verify(_ context.Context, req AdminAuditVerifyRequest) (AdminAuditVerifyResult, error) {
	f.mu.Lock()
	f.lastV = req
	entered, block, err := f.entered, f.block, f.err
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if block != nil {
		<-block
	}
	if err != nil {
		return AdminAuditVerifyResult{}, err
	}
	n := int64(len(f.entries))
	res := AdminAuditVerifyResult{HeadSeq: n, HeadHash: strings.Repeat("ab", 32)}
	from := max(req.FromSeq, 1)
	if f.tampered >= from {
		res.FirstBadSeq, res.Reason = f.tampered, "entry_hash"
		res.Checked, res.LastVerifiedSeq = int(f.tampered-from), f.tampered-1
		return res, nil
	}
	res.OK, res.Checked, res.LastVerifiedSeq = true, int(n-from+1), n
	return res, nil
}

func (f *fakeAdminAudit) PubKeys(context.Context) ([]AdminAuditKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.keys, nil
}

func adminAuditHandler(src AdminAuditSource) http.Handler {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	if src != nil {
		srv.SetAdminAudit(src)
	}
	return srv.Handler()
}

func adminAuditDo(h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) adminAuditListResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out adminAuditListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAdminAuditAPI: paging with limit=50 over 120 rows returns 50, 50 and 20
// entries newest first with no duplicates; the filters reach the source;
// malformed parameters are 400; and no entry carries a signature.
func TestAdminAuditAPI(t *testing.T) {
	src := newFakeAdminAudit(120)
	h := adminAuditHandler(src)

	var sizes []int
	seen := map[int64]bool{}
	last := int64(1 << 62)
	cursor := int64(0)
	for page := 0; ; page++ {
		target := "/dashboard/api/admin-audit?limit=50"
		if cursor > 0 {
			target += fmt.Sprintf("&cursor=%d", cursor)
		}
		resp := decodeList(t, adminAuditDo(h, http.MethodGet, target, ""))
		sizes = append(sizes, len(resp.Entries))
		for _, e := range resp.Entries {
			if e.Seq >= last || seen[e.Seq] {
				t.Fatalf("page %d: seq %d after %d (duplicate %v)", page, e.Seq, last, seen[e.Seq])
			}
			seen[e.Seq], last = true, e.Seq
		}
		if resp.NextCursor == 0 {
			break
		}
		cursor = resp.NextCursor
		if page > 5 {
			t.Fatal("paging does not terminate")
		}
	}
	if fmt.Sprint(sizes) != "[50 50 20]" || len(seen) != 120 {
		t.Fatalf("page sizes %v, %d distinct; want [50 50 20], 120", sizes, len(seen))
	}

	// Defaults and filters.
	resp := decodeList(t, adminAuditDo(h, http.MethodGet, "/dashboard/api/admin-audit", ""))
	if len(resp.Entries) != adminAuditDefaultLimit || src.lastQ.Limit != adminAuditDefaultLimit {
		t.Errorf("default page = %d entries, limit %d; want 50", len(resp.Entries), src.lastQ.Limit)
	}
	decodeList(t, adminAuditDo(h, http.MethodGet,
		"/dashboard/api/admin-audit?actor=alice&action=policy.write&outcome=denied&since=2026-10-01T00:00:00Z&limit=200", ""))
	want := AdminAuditQuery{Actor: "alice", Action: "policy.write", Outcome: "denied",
		Since: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Limit: 200}
	if got := src.lastQ; got.Actor != want.Actor || got.Action != want.Action || got.Outcome != want.Outcome ||
		!got.Since.Equal(want.Since) || got.Limit != want.Limit || got.Cursor != 0 {
		t.Errorf("query = %+v, want %+v", got, want)
	}

	for _, bad := range []string{
		"limit=0", "limit=201", "limit=ten", "cursor=0", "cursor=-3", "cursor=x",
		"since=yesterday", "since=2026-10-01", "outcome=maybe",
		"actor=" + strings.Repeat("a", adminAuditMaxActor+1), "action=" + strings.Repeat("a", adminAuditMaxAction+1),
	} {
		rec := adminAuditDo(h, http.MethodGet, "/dashboard/api/admin-audit?"+bad, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("?%.40s = %d, want 400", bad, rec.Code)
		}
	}

	raw := adminAuditDo(h, http.MethodGet, "/dashboard/api/admin-audit?limit=1", "").Body.String()
	for _, banned := range []string{"signature", "body"} {
		if strings.Contains(strings.ToLower(raw), banned) {
			t.Errorf("list response mentions %q: %s", banned, raw)
		}
	}

	src.err = errors.New("sqlite: disk I/O error at /var/lib/warden")
	rec := adminAuditDo(h, http.MethodGet, "/dashboard/api/admin-audit", "")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "sqlite") {
		t.Errorf("source error = %d %s, want a generic 500", rec.Code, rec.Body)
	}
}

// TestAdminAuditAPIEscapesActor: an actor email carrying markup is JSON-escaped
// on the wire and decodes back unchanged, so the page receives it as data.
func TestAdminAuditAPIEscapesActor(t *testing.T) {
	const evil = `<img src=x onerror=alert(1)>`
	src := newFakeAdminAudit(1)
	src.entries[0].ActorEmail, src.entries[0].Action = evil, evil
	rec := adminAuditDo(adminAuditHandler(src), http.MethodGet, "/dashboard/api/admin-audit", "")
	if strings.Contains(rec.Body.String(), "<img") {
		t.Fatalf("raw markup in the JSON body: %s", rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if e := decodeList(t, rec).Entries; len(e) != 1 || e[0].ActorEmail != evil {
		t.Fatalf("entries = %+v", e)
	}
}

// TestAdminAuditVerify: an untouched chain reports ok with every row checked;
// a tampered row 7 reports ok:false at 7; fromSeq and an anchor reach the
// source with the per-call row cap; a malformed body is 400.
func TestAdminAuditVerify(t *testing.T) {
	src := newFakeAdminAudit(120)
	h := adminAuditHandler(src)
	verify := func(body string) AdminAuditVerifyResult {
		t.Helper()
		rec := adminAuditDo(h, http.MethodPost, "/dashboard/api/admin-audit/verify", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("verify %q = %d %s", body, rec.Code, rec.Body)
		}
		for _, k := range []string{`"ok"`, `"checked"`, `"firstBadSeq"`, `"headSeq"`, `"headHash"`, `"lastVerifiedSeq"`} {
			if !strings.Contains(rec.Body.String(), k) {
				t.Errorf("verify response has no %s: %s", k, rec.Body)
			}
		}
		var res AdminAuditVerifyResult
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res
	}

	if res := verify(""); !res.OK || res.Checked != 120 || res.FirstBadSeq != 0 || res.HeadSeq != 120 {
		t.Fatalf("untouched = %+v, want ok, checked 120", res)
	}
	if src.lastV.MaxRows != adminAuditVerifyMaxRows || src.lastV.FromSeq != 0 || src.lastV.Anchor != nil {
		t.Errorf("request = %+v, want the row cap and no range", src.lastV)
	}
	src.tampered = 7
	if res := verify("{}"); res.OK || res.FirstBadSeq != 7 {
		t.Fatalf("tampered = %+v, want ok:false at 7", res)
	}

	hash := strings.Repeat("0f", 32)
	verify(`{"fromSeq":40,"anchor":{"seq":100,"hash":"` + hash + `"}}`)
	if a := src.lastV.Anchor; src.lastV.FromSeq != 40 || a == nil || a.Seq != 100 || len(a.Hash) != 32 || a.Hash[0] != 0x0f {
		t.Errorf("request = %+v (anchor %+v)", src.lastV, a)
	}

	for _, bad := range []string{
		`not json`, `{"fromSeq":-1}`, `{"fromSeq":"1"}`,
		`{"anchor":{"seq":0,"hash":"` + hash + `"}}`,
		`{"anchor":{"seq":5,"hash":"zz"}}`,
		`{"anchor":{"seq":5,"hash":"abcd"}}`,
		`{"fromSeq":1,"pad":"` + strings.Repeat("x", adminAuditVerifyMaxBody) + `"}`,
	} {
		if rec := adminAuditDo(h, http.MethodPost, "/dashboard/api/admin-audit/verify", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("verify %.40q = %d, want 400", bad, rec.Code)
		}
	}

	src.err = errors.New("sqlite: database is locked")
	rec := adminAuditDo(h, http.MethodPost, "/dashboard/api/admin-audit/verify", "")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "sqlite") {
		t.Errorf("source error = %d %s, want a generic 500", rec.Code, rec.Body)
	}
	// The failed run released the slot.
	src.err = nil
	verify("")
}

// TestAdminAuditVerifyConcurrent: while one verification runs, a second gets
// 429; once it finishes the next one runs.
func TestAdminAuditVerifyConcurrent(t *testing.T) {
	src := newFakeAdminAudit(10)
	src.entered, src.block = make(chan struct{}, 1), make(chan struct{})
	h := adminAuditHandler(src)

	first := make(chan int, 1)
	go func() { first <- adminAuditDo(h, http.MethodPost, "/dashboard/api/admin-audit/verify", "").Code }()
	select {
	case <-src.entered:
	case code := <-first:
		t.Fatalf("first verify returned %d without reaching the source", code)
	case <-time.After(5 * time.Second):
		t.Fatal("first verify never reached the source")
	}
	rec := adminAuditDo(h, http.MethodPost, "/dashboard/api/admin-audit/verify", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("concurrent verify = %d, want 429", rec.Code)
	}
	close(src.block)
	if code := <-first; code != http.StatusOK {
		t.Errorf("first verify = %d, want 200", code)
	}
	src.mu.Lock()
	src.entered, src.block = nil, nil
	src.mu.Unlock()
	if rec := adminAuditDo(h, http.MethodPost, "/dashboard/api/admin-audit/verify", ""); rec.Code != http.StatusOK {
		t.Errorf("verify after the first finished = %d, want 200", rec.Code)
	}
}

// TestAdminAuditPubKeyAPI: the pubkey route returns {alg, keys} as the source
// lists them, and [] for none.
func TestAdminAuditPubKeyAPI(t *testing.T) {
	src := newFakeAdminAudit(0)
	h := adminAuditHandler(src)
	rec := adminAuditDo(h, http.MethodGet, "/dashboard/api/admin-audit/pubkey", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"keys":[]`) {
		t.Fatalf("no keys = %d %s", rec.Code, rec.Body)
	}
	src.keys = []AdminAuditKey{{KeyID: "aaaa", PublicKey: "QUJD", FirstSeq: 1}, {KeyID: "bbbb", PublicKey: "REVG", FirstSeq: 9}}
	rec = adminAuditDo(h, http.MethodGet, "/dashboard/api/admin-audit/pubkey", "")
	var got adminAuditPubKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Alg != "ed25519" || len(got.Keys) != 2 || got.Keys[1] != src.keys[1] {
		t.Fatalf("pubkey = %+v", got)
	}
	src.err = errors.New("boom")
	if rec := adminAuditDo(h, http.MethodGet, "/dashboard/api/admin-audit/pubkey", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("source error = %d, want 500", rec.Code)
	}
}

// TestAdminAuditNotWired: without SetAdminAudit (a worker, or a control plane
// with admin audit off) all three routes are 404, other methods stay 405, and
// the served page keeps the Admin log tab hidden until the API answers.
func TestAdminAuditNotWired(t *testing.T) {
	h := adminAuditHandler(nil)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/admin-audit"},
		{http.MethodPost, "/dashboard/api/admin-audit/verify"},
		{http.MethodGet, "/dashboard/api/admin-audit/pubkey"},
	} {
		if rec := adminAuditDo(h, c.method, c.path, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
	if rec := adminAuditDo(h, http.MethodDelete, "/dashboard/api/admin-audit", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE = %d, want 405", rec.Code)
	}

	html := servedIndex(t)
	i := strings.Index(html, `data-page="adminlog"`)
	if i < 0 {
		t.Fatal("no Admin log nav item")
	}
	if tag := tagAt(html, i); !strings.Contains(tag, `style="display:none"`) || !strings.Contains(tag, `data-min-role="admin"`) {
		t.Errorf("Admin log nav item is not hidden by default and admin-gated: %s", tag)
	}
}

// insideEsc reports whether the expression at i in js sits inside an esc(...)
// call: walking back from i, the first unbalanced "(" that belongs to esc
// before the statement ends (a ";" outside parentheses).
func insideEsc(js string, i int) bool {
	depth := 0
	for j := i - 1; j >= 0; j-- {
		switch js[j] {
		case ')':
			depth++
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			if j >= 3 && js[j-3:j] == "esc" {
				return true
			}
		case ';':
			if depth == 0 {
				return false
			}
		}
	}
	return false
}

// adminLogFieldRef matches a read of an entry or key field the tab renders.
var adminLogFieldRef = regexp.MustCompile(`\b\w+\.(actorEmail|actorSub|actorId|actorRole|authMethod|action|target|targetRef|outcome|keyId|publicKey|requestId|clientIp|headHash|reason)\b`)

// TestAdminLogTabServedHTML pins the Admin log tab (W-P1-AAUD-03) in the
// served page: the nav item and page exist, separate from the receipts Audit
// tab; the script fetches all three routes through api(); every read of an
// entry or key field is inside esc(), so no innerHTML assignment carries a raw
// field; the tab is shown only to an admin (or in none mode) and only when the
// API answers; and failures show fixed messages, never a server error text.
func TestAdminLogTabServedHTML(t *testing.T) {
	html := servedIndex(t)
	for _, want := range []string{
		`data-page="adminlog"`, `id="page-adminlog"`, `>Admin log</h1>`,
		`id="al-actor"`, `id="al-action"`, `id="al-outcome"`, `id="al-older"`, `id="al-newer"`,
		`id="al-verify"`, `class="btn sm al-copy"`, `navigator.clipboard.writeText(`,
		`case 'adminlog':    loadAdminLog(); break;`, `adminLogProbe();`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("served page has no %s", want)
		}
	}
	// The receipts Audit tab and its routes are untouched and distinct.
	if !strings.Contains(html, `data-page="audit"`) || !strings.Contains(html, `jget('/dashboard/api/audit')`) {
		t.Error("the receipts Audit tab changed")
	}

	a, b := strings.Index(html, "/* adminlog:begin */"), strings.Index(html, "/* adminlog:end */")
	if a < 0 || b < a {
		t.Fatal("no adminlog script block")
	}
	js := html[a:b]
	for _, route := range []string{
		`api('GET','/dashboard/api/admin-audit?'`,
		`api('POST','/dashboard/api/admin-audit/verify'`,
		`api('GET','/dashboard/api/admin-audit/pubkey'`,
	} {
		if !strings.Contains(js, route) {
			t.Errorf("tab does not call %s", route)
		}
	}
	if strings.Contains(js, "fetch(") {
		t.Error("tab calls fetch() directly instead of api()")
	}
	refs := adminLogFieldRef.FindAllStringIndex(js, -1)
	if len(refs) < 10 {
		t.Fatalf("found only %d field reads; the pattern no longer matches the tab", len(refs))
	}
	for _, loc := range refs {
		ref := js[loc[0]:loc[1]]
		if strings.HasPrefix(ref, "al.filter.") || strings.HasPrefix(ref, "filter.") {
			continue // the filter state is sent as a query, never rendered
		}
		if !insideEsc(js, loc[0]) {
			t.Errorf("%s is rendered without esc(): %q", ref, js[max(0, loc[0]-60):loc[1]])
		}
	}
	// Visibility: admin role (roleAllows) and a wired API (any non-ok reply hides it).
	for _, want := range []string{`if(!roleAllows('admin')){ nav.style.display='none'; return; }`, `nav.style.display= r&&r.ok ? '' : 'none';`} {
		if !strings.Contains(js, want) {
			t.Errorf("probe lost %s", want)
		}
	}
	// Errors are fixed strings: no server error text reaches the page.
	if strings.Contains(js, ".error") || strings.Contains(js, "statusText") {
		t.Error("tab renders a server error message")
	}
}
