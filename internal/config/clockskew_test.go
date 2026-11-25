package config

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestPollLongClockSkew pins that PollLong reports the CP Date header against
// the worker clock: a CP 120s ahead reads as about +120s, on 200 and on 304.
func TestPollLongClockSkew(t *testing.T) {
	ahead := 120 * time.Second
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().Add(ahead).UTC().Format(http.TimeFormat))
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(`{"allowlist":[{"domain":"a.com"}]}`))
	}))
	defer srv.Close()

	rp := newTLSProvider(t, srv)
	var mu sync.Mutex
	var got []time.Duration
	rp.SetDateObserver(func(cpNow time.Time) {
		mu.Lock()
		got = append(got, time.Until(cpNow))
		mu.Unlock()
	})
	for i := 0; i < 2; i++ { // 200, then 304
		if _, err := rp.PollLong(context.Background(), time.Second); err != nil {
			t.Fatalf("PollLong %d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("observer called %d times, want 2", len(got))
	}
	for i, d := range got {
		if d < ahead-5*time.Second || d > ahead+time.Second {
			t.Errorf("skew[%d] = %v, want about %v", i, d, ahead)
		}
	}
}

// TestPollLongClockSkewIgnored: no observer, or no usable Date header, is fine.
func TestPollLongClockSkewIgnored(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = []string{"not a date"}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	rp := newTLSProvider(t, srv)
	if _, err := rp.PollLong(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	called := false
	rp.SetDateObserver(func(time.Time) { called = true })
	if _, err := rp.PollLong(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("observer ran for an unparseable Date header")
	}
}

// newTLSProvider returns a RemoteProvider for srv's /policy trusting its cert.
func newTLSProvider(t *testing.T, srv *httptest.Server) *RemoteProvider {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	rp, err := NewRemoteProvider(srv.URL+"/policy", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.SetCACert(caPath); err != nil {
		t.Fatal(err)
	}
	return rp
}
