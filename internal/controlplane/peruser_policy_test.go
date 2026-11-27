package controlplane

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// getPolicyOnce serves GET /policy once from a CP over path.
func getPolicyOnce(t *testing.T, path string) (body []byte, etag string) {
	t.Helper()
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /policy = %d %s", resp.StatusCode, b)
	}
	return b, resp.Header.Get("ETag")
}

// TestPerUserSecretsPolicyGolden: with the perUserSecrets block absent, GET
// /policy bytes and the ETag equal the golden pair captured on main before the
// block existed. With the block present and enabled, nothing of it (switch,
// placeholder, provider, scope, domain, agent) reaches the worker wire.
func TestPerUserSecretsPolicyGolden(t *testing.T) {
	wantBody, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantETag, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.etag"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fixture, []byte("perUserSecrets")) {
		t.Fatal("the golden fixture must not carry a perUserSecrets block")
	}

	body, etag := getPolicyOnce(t, filepath.Join("testdata", "policy_overlay_none.yaml"))
	if !bytes.Equal(body, wantBody) {
		t.Errorf("/policy body differs from golden\n got: %s\nwant: %s", body, wantBody)
	}
	if want := strings.TrimSpace(string(wantETag)); etag != want {
		t.Errorf("/policy ETag = %s, want golden %s", etag, want)
	}

	withBlock := overlayFixture(t)
	f, err := os.OpenFile(withBlock, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(`
perUserSecrets:
  enabled: true
  workerCacheTTL: 7m
  mappings:
    - placeholder: PUSGOLDEN_USER
      provider: pusprovider
      scopes: [pus.scope.readonly]
      domains: [pus-golden.example.com]
      in: [header, query]
      agents: [pus-golden-agent]
`)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	body, _ = getPolicyOnce(t, withBlock)
	if !bytes.Equal(body, wantBody) {
		t.Errorf("/policy body with the block present differs from golden\n got: %s\nwant: %s", body, wantBody)
	}
	for _, banned := range []string{"perUserSecrets", "PUSGOLDEN_USER", "pusprovider", "pus.scope", "pus-golden", "workerCacheTTL"} {
		if bytes.Contains(body, []byte(banned)) {
			t.Errorf("/policy carries %q: %s", banned, body)
		}
	}
}
