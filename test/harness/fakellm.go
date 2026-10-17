package harness

import (
	"encoding/json"
	"net/http"
	"sync"
)

// The LLM fake is an OpenAI-style completions stub: one fixed completion, and
// a record of every Authorization header that reached it — the assertion
// material for "the worker swapped the placeholder, the agent never saw the
// value".
//
// The fixed completion is inert by design: scenarios that need the fake LLM to
// SAY something back (judge pipelines, agent loops) set their own text with
// SetCompletion.

// defaultLLMCompletion is the completion served until SetCompletion changes it.
const defaultLLMCompletion = "This is the harness fake LLM's fixed completion."

// FakeLLM is the fake provider behind llm.example.com. Mounting is automatic;
// obtain it with h.FakeLLM().
type FakeLLM struct {
	u *Upstream

	mu         sync.Mutex
	completion string
}

// FakeLLM returns the fake provider on llm.example.com (creating it on first
// use). POST /v1/chat/completions answers with the fixed completion JSON;
// every request is recorded by the underlying Upstream, Authorization headers
// included (see AuthHeaders).
func (h *H) FakeLLM() *FakeLLM {
	h.tb.Helper()
	h.llmOnce.Do(func() {
		f := &FakeLLM{completion: defaultLLMCompletion}
		u := h.Upstream(h.Host("llm"))
		u.route("/v1/chat/completions", http.HandlerFunc(f.serve))
		f.u = u
		h.llm = f
	})
	return h.llm
}

// AuthHeaders returns the Authorization header values the fake has received on
// the completions path, in arrival order — after a swapped request this holds
// the REAL secret value (that is the point: the value reached the provider,
// never the agent).
func (f *FakeLLM) AuthHeaders() []string {
	var out []string
	for _, r := range f.u.Requests() {
		if r.Path == "/v1/chat/completions" {
			if v := r.Header.Get("Authorization"); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// SetCompletion replaces the text served in the completion's message.content.
func (f *FakeLLM) SetCompletion(text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completion = text
}

// serve answers with a minimal OpenAI chat.completion document.
func (f *FakeLLM) serve(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	text := f.completion
	f.mu.Unlock()
	body, err := json.Marshal(map[string]any{
		"id":      "chatcmpl-harness",
		"object":  "chat.completion",
		"created": 0,
		"model":   "warden-harness-fake",
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": text},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
	})
	if err != nil {
		http.Error(w, "harness: fake llm marshal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
