package llmpolicy

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockLLM is a configurable mock for LLMClient.
type mockLLM struct {
	mu        sync.Mutex
	callCount int
	response  string
	err       error
}

func (m *mockLLM) Evaluate(_ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	return m.response, m.err
}

func (m *mockLLM) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func newJudgeWithMock(t *testing.T, mock *mockLLM, opts JudgeOptions) *Judge {
	t.Helper()
	policies := map[string]string{
		"agent-1": "Allow GET requests to api.example.com only.",
	}
	return NewJudge(mock, policies, opts)
}

func TestEvaluateAllow(t *testing.T) {
	mock := &mockLLM{response: `{"decision":"allow","reason":"matches policy"}`}
	j := newJudgeWithMock(t, mock, JudgeOptions{})

	v := j.Evaluate("agent-1", "GET", "https://api.example.com/data", "api.example.com", "application/json", false)

	if v.Decision != "allow" {
		t.Fatalf("expected allow, got %q", v.Decision)
	}
	if v.Reason != "matches policy" {
		t.Fatalf("expected reason 'matches policy', got %q", v.Reason)
	}
	if v.Cached {
		t.Fatal("first call should not be cached")
	}
}

func TestEvaluateDeny(t *testing.T) {
	mock := &mockLLM{response: `{"decision":"deny","reason":"not allowed"}`}
	j := newJudgeWithMock(t, mock, JudgeOptions{})

	v := j.Evaluate("agent-1", "POST", "https://evil.com/hack", "evil.com", "text/plain", false)

	if v.Decision != "deny" {
		t.Fatalf("expected deny, got %q", v.Decision)
	}
	if v.Reason != "not allowed" {
		t.Fatalf("expected reason 'not allowed', got %q", v.Reason)
	}
}

func TestCacheHit(t *testing.T) {
	mock := &mockLLM{response: `{"decision":"allow","reason":"ok"}`}
	j := newJudgeWithMock(t, mock, JudgeOptions{CacheTTL: time.Minute})

	// First call: not cached, hits the mock.
	v1 := j.Evaluate("agent-1", "GET", "https://api.example.com/v1/items", "api.example.com", "application/json", false)
	if v1.Cached {
		t.Fatal("first call should not be cached")
	}

	// Second call with same args: should be cached.
	v2 := j.Evaluate("agent-1", "GET", "https://api.example.com/v1/items", "api.example.com", "application/json", false)
	if !v2.Cached {
		t.Fatal("second call should be cached")
	}
	if v2.Decision != "allow" {
		t.Fatalf("cached decision should be allow, got %q", v2.Decision)
	}

	if mock.calls() != 1 {
		t.Fatalf("expected 1 LLM call, got %d", mock.calls())
	}
}

func TestCircuitBreaker(t *testing.T) {
	mock := &mockLLM{err: errors.New("timeout")}
	j := newJudgeWithMock(t, mock, JudgeOptions{
		MaxFailures: 2,
		Cooldown:    time.Minute,
	})

	// Two failures to trip the breaker.
	j.Evaluate("agent-1", "GET", "https://api.example.com/a", "api.example.com", "", false)
	j.Evaluate("agent-1", "GET", "https://api.example.com/b", "api.example.com", "", false)

	callsBefore := mock.calls()

	// Third call should be blocked by the circuit breaker without hitting the mock.
	v := j.Evaluate("agent-1", "GET", "https://api.example.com/c", "api.example.com", "", false)
	if v.Decision != "deny" {
		t.Fatalf("expected deny from circuit breaker, got %q", v.Decision)
	}
	if !strings.Contains(v.Reason, "circuit breaker open") {
		t.Fatalf("expected circuit breaker reason, got %q", v.Reason)
	}
	if mock.calls() != callsBefore {
		t.Fatal("circuit breaker should prevent LLM calls")
	}
}

func TestCircuitBreakerResetsAfterCooldown(t *testing.T) {
	mock := &mockLLM{err: errors.New("timeout")}
	fakeClock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j := newJudgeWithMock(t, mock, JudgeOptions{
		MaxFailures: 2,
		Cooldown:    30 * time.Second,
	})
	j.now = func() time.Time { return fakeClock }

	// Trip the breaker.
	j.Evaluate("agent-1", "GET", "https://api.example.com/a", "api.example.com", "", false)
	j.Evaluate("agent-1", "GET", "https://api.example.com/b", "api.example.com", "", false)

	// Advance clock past cooldown.
	fakeClock = fakeClock.Add(31 * time.Second)

	// Now make the mock return a valid response.
	mock.mu.Lock()
	mock.err = nil
	mock.response = `{"decision":"allow","reason":"recovered"}`
	mock.mu.Unlock()

	callsBefore := mock.calls()

	v := j.Evaluate("agent-1", "GET", "https://api.example.com/c", "api.example.com", "", false)
	if mock.calls() <= callsBefore {
		t.Fatal("expected LLM call after cooldown expired")
	}
	if v.Decision != "allow" {
		t.Fatalf("expected allow after recovery, got %q", v.Decision)
	}
}

func TestNoPolicyForAgent(t *testing.T) {
	mock := &mockLLM{response: `{"decision":"allow","reason":"ok"}`}
	j := newJudgeWithMock(t, mock, JudgeOptions{})

	v := j.Evaluate("unknown-agent", "GET", "https://example.com", "example.com", "", false)

	if v.Decision != "deny" {
		t.Fatalf("expected deny for unknown agent, got %q", v.Decision)
	}
	if !strings.Contains(v.Reason, "no policy") {
		t.Fatalf("expected 'no policy' in reason, got %q", v.Reason)
	}
	if mock.calls() != 0 {
		t.Fatal("should not call LLM when no policy exists")
	}
}

func TestUnparseableLLMResponse(t *testing.T) {
	mock := &mockLLM{response: "not json"}
	j := newJudgeWithMock(t, mock, JudgeOptions{})

	v := j.Evaluate("agent-1", "GET", "https://api.example.com/x", "api.example.com", "", false)

	if v.Decision != "deny" {
		t.Fatalf("expected deny for unparseable response, got %q", v.Decision)
	}
	if !strings.Contains(v.Reason, "unparseable") {
		t.Fatalf("expected 'unparseable' in reason, got %q", v.Reason)
	}
}
