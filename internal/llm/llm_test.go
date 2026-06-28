package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient_Validation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing baseURL", Config{Model: "m", APIKey: "k"}},
		{"missing model", Config{BaseURL: "http://x", APIKey: "k"}},
		{"missing apiKey", Config{BaseURL: "http://x", Model: "m"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewClient(tc.cfg); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
	if _, err := NewClient(Config{BaseURL: "http://x", Model: "m", APIKey: "k"}); err != nil {
		t.Fatalf("valid config errored: %v", err)
	}
}

func TestEvaluate_Success(t *testing.T) {
	const secret = "sk-supersecret"
	var gotAuth, gotPath, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"decision\":\"allow\"}"}}]}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{BaseURL: srv.URL, Model: "gpt-4o-mini", APIKey: secret})
	if err != nil {
		t.Fatal(err)
	}

	out, err := c.Evaluate("is this allowed?")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out != `{"decision":"allow"}` {
		t.Fatalf("unexpected content: %q", out)
	}
	if gotAuth != "Bearer "+secret {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotPath != "/chat/completions" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type = %q", gotCT)
	}
	// Request body must carry the model and the prompt as a user message.
	var req chatRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("server got non-JSON body: %v", err)
	}
	if req.Model != "gpt-4o-mini" {
		t.Fatalf("model = %q", req.Model)
	}
	if len(req.Messages) != 1 || req.Messages[0].Role != "user" || req.Messages[0].Content != "is this allowed?" {
		t.Fatalf("messages = %+v", req.Messages)
	}
}

// The API key must never appear in any error returned to the caller.
func TestEvaluate_ErrorDoesNotLeakKey(t *testing.T) {
	const secret = "sk-leakcheck"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request: "+r.Header.Get("Authorization"), http.StatusBadRequest)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{BaseURL: srv.URL, Model: "m", APIKey: secret})
	_, err := c.Evaluate("x")
	if err == nil {
		t.Fatal("expected error on non-2xx")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked API key: %v", err)
	}
}

func TestEvaluate_NoChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{BaseURL: srv.URL, Model: "m", APIKey: "k"})
	if _, err := c.Evaluate("x"); err == nil {
		t.Fatal("expected error for empty choices")
	}
}

func TestEvaluate_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{BaseURL: srv.URL, Model: "m", APIKey: "k"})
	if _, err := c.Evaluate("x"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestEvaluate_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Config{BaseURL: srv.URL, Model: "m", APIKey: "k", Timeout: 20 * time.Millisecond})
	if _, err := c.Evaluate("x"); err == nil {
		t.Fatal("expected timeout error")
	}
}
