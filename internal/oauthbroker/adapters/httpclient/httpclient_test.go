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
	var be *oauthbroker.BlockedError
	if !errors.As(err, &be) || be.AddrClass != "loopback" {
		t.Fatalf("want a BlockedError(loopback), got %v", err)
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

func TestDoDeleteWithBodyAndHardening(t *testing.T) {
	var gotMethod, gotBody, gotCT, gotAccept, gotUser string
	var followed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/grant", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotMethod, gotBody, gotCT, gotAccept = r.Method, string(b), r.Header.Get("Content-Type"), r.Header.Get("Accept")
		gotUser, _, _ = r.BasicAuth()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/r", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/final", http.StatusFound) })
	mux.HandleFunc("/final", func(http.ResponseWriter, *http.Request) { followed.Add(1) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New([]string{"127.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	status, _, err := c.Do(t.Context(), oauthbroker.Request{
		Method: http.MethodDelete, URL: srv.URL + "/grant", Body: []byte(`{"access_token":"x"}`),
		ContentType: "application/json", Accept: "application/vnd.github+json", BasicUser: "cid", BasicPass: "s",
	})
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if gotMethod != "DELETE" || gotBody != `{"access_token":"x"}` || gotCT != "application/json" || gotAccept != "application/vnd.github+json" || gotUser != "cid" {
		t.Fatalf("bad request: %s %q %q %q %q", gotMethod, gotBody, gotCT, gotAccept, gotUser)
	}
	status, _, err = c.Do(t.Context(), oauthbroker.Request{Method: http.MethodDelete, URL: srv.URL + "/r", BasicUser: "u", BasicPass: "p"})
	if err != nil || status != http.StatusFound || followed.Load() != 0 {
		t.Fatalf("redirect must not be followed: %d %d %v", status, followed.Load(), err)
	}

	d, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var be *oauthbroker.BlockedError
	if _, _, err = d.Do(t.Context(), oauthbroker.Request{Method: http.MethodDelete, URL: srv.URL + "/grant"}); !errors.As(err, &be) {
		t.Fatalf("loopback must be blocked for Do too: %v", err)
	}
}

func TestDoHonoursMaxBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 5000))
	}))
	defer srv.Close()
	c, err := New([]string{"127.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := c.Do(t.Context(), oauthbroker.Request{Method: http.MethodPost, URL: srv.URL, MaxBytes: 100})
	if err != nil || len(b) != 101 {
		t.Fatalf("read must stop at MaxBytes+1: len=%d err=%v", len(b), err)
	}
}

func TestDoSendsBearer(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") }))
	defer srv.Close()
	c, err := New([]string{"127.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Do(t.Context(), oauthbroker.Request{Method: "GET", URL: srv.URL, Bearer: "tok-1"}); err != nil || got != "Bearer tok-1" {
		t.Fatalf("Authorization = %q, %v", got, err)
	}
}
