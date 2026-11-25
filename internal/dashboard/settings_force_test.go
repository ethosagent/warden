package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// TestSettingsWriterForceAndCapabilityRefusal: ?force=true reaches the writer
// through its context (only the exact value true), and a
// *WorkersLackCapabilityError becomes 409 workers_lack_capability with the ids.
func TestSettingsWriterForceAndCapabilityRefusal(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	var forced bool
	var refuse error
	srv.SetSettingsWriter(func(ctx context.Context, _ config.SettingsWire, _ WriteMeta) error {
		forced = ForceFrom(ctx)
		return refuse
	})
	h := srv.Handler()
	send := func(query string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/dashboard/api/settings"+query, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, strings.TrimSpace(rec.Body.String())
	}
	for query, want := range map[string]bool{"": false, "?force=true": true, "?force=1": false, "?force=false": false} {
		if code, body := send(query); code != http.StatusOK || forced != want {
			t.Errorf("POST settings%s = %d %s, writer saw force %v, want %v", query, code, body, forced, want)
		}
	}
	refuse = &WorkersLackCapabilityError{Workers: []string{"w1", "w2"}}
	if code, body := send(""); code != http.StatusConflict || body != `{"error":"workers_lack_capability","workers":["w1","w2"]}` {
		t.Fatalf("capability refusal = %d %s", code, body)
	}
	if refuse.Error() == "" {
		t.Error("empty Error()")
	}
}

// TestIndexFleetRequireFlags: the worker list shows the require-not-supported
// flag and 'agent unknown' for workers that report no agent id.
func TestIndexFleetRequireFlags(t *testing.T) {
	html := servedIndex(t)
	for _, want := range []string{"w.noIdentityRequire", "identity: require not supported, still allowing", "agent unknown"} {
		if !strings.Contains(html, want) {
			t.Errorf("index lacks %q", want)
		}
	}
}
