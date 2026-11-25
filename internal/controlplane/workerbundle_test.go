package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

type bundleFleetRow struct {
	ProxyID          string   `json:"proxyID"`
	Behind           bool     `json:"behind"`
	BundleSeq        int64    `json:"bundleSeq"`
	BundleKID        string   `json:"bundleKid"`
	BundleIssuedAt   string   `json:"bundleIssuedAt"`
	PinnedKIDs       []string `json:"pinnedKids"`
	BundleStale      bool     `json:"bundleStale"`
	LastRejectReason string   `json:"lastRejectReason"`
	LastRejectAt     string   `json:"lastRejectAt"`
	BundleSeqAhead   bool     `json:"bundleSeqAhead"`
}

func bundleFleetRows(t *testing.T, url string) map[string]bundleFleetRow {
	t.Helper()
	resp, err := http.Get(url + "/dashboard/api/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var rows []bundleFleetRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]bundleFleetRow{}
	for _, r := range rows {
		out[r.ProxyID] = r
	}
	return out
}

func pinnedBeat(seq int64, extra string) string {
	return fmt.Sprintf(`{"policyETag":"envelope-etag","caps":["bundle/v1"],"bundleSeq":%d,"bundleKid":"kid-1","bundleIssuedAt":"2026-06-01T12:00:00Z","pinnedKids":["kid-1","kid-2"]%s}`, seq, extra)
}

// TestFleetBundleState: a pinned worker reporting seq head-1 is behind and
// shows why its newest bundle was rejected; one at head is not behind although
// its ETag is the envelope's, never the legacy wire's; a worker without
// bundle/v1 keeps the ETag comparison.
func TestFleetBundleState(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	ts := httptest.NewServer(h.s.Handler())
	defer ts.Close()
	head := h.ps.bundleHeadSeq()
	if head < 1 {
		t.Fatalf("head seq = %d, want a signed bundle", head)
	}

	postHeartbeat(t, ts.URL, "lagging", pinnedBeat(head-1, `,"lastRejectReason":"bad_signature","lastRejectAt":"2026-06-01T12:05:00+02:00"`))
	postHeartbeat(t, ts.URL, "current", pinnedBeat(head, ""))
	postHeartbeat(t, ts.URL, "legacy", `{"policyETag":"not-the-served-etag"}`)
	rows := bundleFleetRows(t, ts.URL)

	lag := rows["lagging"]
	if !lag.Behind || lag.BundleSeq != head-1 || lag.LastRejectReason != "bad_signature" || lag.BundleKID != "kid-1" ||
		lag.LastRejectAt != "2026-06-01T10:05:00Z" || lag.BundleIssuedAt != "2026-06-01T12:00:00Z" ||
		len(lag.PinnedKIDs) != 2 || lag.BundleSeqAhead {
		t.Errorf("lagging worker = %+v", lag)
	}
	if cur := rows["current"]; cur.Behind || cur.BundleSeq != head || cur.LastRejectReason != "" || cur.BundleSeqAhead {
		t.Errorf("current pinned worker = %+v, want not behind (its ETag is the envelope's)", cur)
	}
	if !rows["legacy"].Behind {
		t.Error("a worker without bundle/v1 lost the ETag comparison")
	}
}

// TestFleetBundleSeqAheadLogsOnce: a worker reporting a seq above the head is
// flagged and logged as one ERROR line however many heartbeats it sends; a
// worker that rejects with the same reason repeatedly logs one WARN with the
// proxy id, seq and reason only; a new reason logs again.
func TestFleetBundleSeqAheadLogsOnce(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	ts := httptest.NewServer(h.s.Handler())
	defer ts.Close()
	head := h.ps.bundleHeadSeq()

	for i := 0; i < 3; i++ {
		postHeartbeat(t, ts.URL, "ahead", pinnedBeat(head+40, `,"lastRejectReason":"bad_signature"`))
	}
	postHeartbeat(t, ts.URL, "ahead", pinnedBeat(head+40, `,"lastRejectReason":"rollback"`))
	postHeartbeat(t, ts.URL, "ahead", pinnedBeat(head+40, `,"lastRejectReason":"free text <script>"`))
	row := bundleFleetRows(t, ts.URL)["ahead"]
	if !row.BundleSeqAhead || row.Behind {
		t.Errorf("ahead worker = %+v, want bundleSeqAhead and not behind", row)
	}
	if row.LastRejectReason != "other" {
		t.Errorf("an unknown reason = %q, want other", row.LastRejectReason)
	}

	logs := h.logs.String()
	errLines := 0
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, `"level":"ERROR"`) && strings.Contains(l, `"proxy_id":"ahead"`) {
			errLines++
		}
	}
	if errLines != 1 {
		t.Errorf("ERROR lines for the ahead worker = %d, want 1\n%s", errLines, logs)
	}
	if n := strings.Count(logs, `"msg":"worker bundle rejected"`); n != 3 {
		t.Errorf("rejection log lines = %d, want 3 (bad_signature once, rollback, other)\n%s", n, logs)
	}
	if strings.Contains(logs, "<script>") || strings.Contains(logs, "kid-1") {
		t.Errorf("a worker-supplied string reached the log\n%s", logs)
	}
}

// TestHeartbeatWithoutBundleFields: an old worker's body is stored as before.
func TestHeartbeatWithoutBundleFields(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if c := postHeartbeat(t, ts.URL, "old", `{"policyETag":"v1","caps":["blocklist/v1"]}`); c != http.StatusNoContent {
		t.Fatalf("status %d", c)
	}
	r := bundleFleetRows(t, ts.URL)["old"]
	if r.BundleSeq != 0 || r.LastRejectReason != "" || len(r.PinnedKIDs) != 0 || r.BundleSeqAhead {
		t.Errorf("old worker = %+v", r)
	}
}

func TestValidWorkerBundleBounds(t *testing.T) {
	kids := make([]string, 30)
	for i := range kids {
		kids[i] = "kid"
	}
	wb := validWorkerBundle(-4, "bad kid!", "yesterday", append(kids, "bad kid!"), true, "", "2026-06-01T12:00:00Z")
	if wb.Seq != 0 || wb.KID != "" || wb.IssuedAt != "" || len(wb.PinnedKIDs) != maxPinnedKIDs || !wb.Stale || wb.RejectAt != "" {
		t.Errorf("wb = %+v", wb)
	}
	if got := validWorkerBundle(MaxBundleSeqFloor+1, "", "", nil, false, "", "").Seq; got != 0 {
		t.Errorf("seq above the bound = %d", got)
	}
	for r := range bundleRejectReasons {
		if got := validWorkerBundle(1, "", "", nil, false, r, "").RejectReason; got != r {
			t.Errorf("reason %q stored as %q", r, got)
		}
	}
	if _, ok := bundleRejectReasons[config.BundleReasonInvalidPolicy]; !ok || len(bundleRejectReasons) != 13 {
		t.Errorf("reason set = %v, want the 12 bundle reasons and invalid_policy", bundleRejectReasons)
	}
}
