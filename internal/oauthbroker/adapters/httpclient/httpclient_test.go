package httpclient

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/proxy"
)

func TestBlocksLoopbackByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.PostForm(t.Context(), oauthbroker.FormRequest{URL: srv.URL, Form: "a=b"})
	if err == nil || hits.Load() != 0 {
		t.Fatalf("loopback must be refused by the SSRF dialer: err=%v hits=%d", err, hits.Load())
	}
	var ssrf *proxy.SSRFError
	if !errors.As(err, &ssrf) {
		t.Fatalf("want an SSRFError, got %v", err)
	}
}

func TestNoRedirectAndBodyCap(t *testing.T) {
	var followed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/r", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(http.ResponseWriter, *http.Request) { followed.Add(1) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", MaxBodyBytes*2))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, err := New([]string{"127.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	status, _, err := c.PostForm(t.Context(), oauthbroker.FormRequest{URL: srv.URL + "/r", Form: "a=b", BasicUser: "u", BasicPass: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusFound || followed.Load() != 0 {
		t.Fatalf("redirect must not be followed: %d followed=%d", status, followed.Load())
	}
	_, b, err := c.PostForm(t.Context(), oauthbroker.FormRequest{URL: srv.URL + "/big", Form: "a=b"})
	if err != nil || len(b) != MaxBodyBytes+1 {
		t.Fatalf("body must be capped at cap+1: len=%d err=%v", len(b), err)
	}
}
