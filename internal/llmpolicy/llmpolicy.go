package llmpolicy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// LLMClient abstracts the LLM API call. Users wire in their own HTTP client.
type LLMClient interface {
	Evaluate(prompt string) (string, error)
}

// Verdict is the LLM judge's decision on a request.
type Verdict struct {
	Decision string // "allow" or "deny"
	Reason   string
	Cached   bool
}

// Judge evaluates ambiguous requests using an LLM and per-agent policies.
type Judge struct {
	client   LLMClient
	policies map[string]string // agentID -> natural-language policy text
	cache    map[string]cachedVerdict
	mu       sync.RWMutex
	cacheTTL time.Duration
	timeout  time.Duration

	// Circuit breaker
	failures    int
	maxFailures int
	cooldownEnd time.Time
	cooldown    time.Duration

	now func() time.Time // injectable for tests
}

type cachedVerdict struct {
	verdict Verdict
	expiry  time.Time
}

// JudgeOptions configures a Judge.
type JudgeOptions struct {
	CacheTTL    time.Duration // default 5m
	Timeout     time.Duration // default 5s
	MaxFailures int           // default 5
	Cooldown    time.Duration // default 30s
}

func NewJudge(client LLMClient, policies map[string]string, opts JudgeOptions) *Judge {
	if opts.CacheTTL == 0 {
		opts.CacheTTL = 5 * time.Minute
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.MaxFailures == 0 {
		opts.MaxFailures = 5
	}
	if opts.Cooldown == 0 {
		opts.Cooldown = 30 * time.Second
	}
	return &Judge{
		client:      client,
		policies:    policies,
		cache:       make(map[string]cachedVerdict),
		cacheTTL:    opts.CacheTTL,
		timeout:     opts.Timeout,
		maxFailures: opts.MaxFailures,
		cooldown:    opts.Cooldown,
		now:         time.Now,
	}
}

// numericSegment matches path segments that are purely numeric (e.g. IDs).
var numericSegment = regexp.MustCompile(`/\d+`)

// normalizePath replaces numeric path segments with "*" for cache key stability.
func normalizePath(rawURL string) string {
	return numericSegment.ReplaceAllString(rawURL, "/*")
}

// cacheKey builds a deterministic key from the request attributes.
func cacheKey(agentID, host, normalizedPath, method string) string {
	return agentID + "|" + host + "|" + normalizedPath + "|" + method
}

// Evaluate asks the LLM to decide on a request. Returns deny on any failure (fail-closed).
func (j *Judge) Evaluate(agentID, method, url, host, contentType string, hasAuth bool) Verdict {
	normalizedPath := normalizePath(url)
	key := cacheKey(agentID, host, normalizedPath, method)

	// Check cache.
	j.mu.RLock()
	if cv, ok := j.cache[key]; ok && j.now().Before(cv.expiry) {
		j.mu.RUnlock()
		v := cv.verdict
		v.Cached = true
		return v
	}
	j.mu.RUnlock()

	// Check circuit breaker.
	j.mu.RLock()
	if j.failures >= j.maxFailures && j.now().Before(j.cooldownEnd) {
		j.mu.RUnlock()
		return Verdict{Decision: "deny", Reason: "circuit breaker open"}
	}
	j.mu.RUnlock()

	// Look up agent policy.
	policyText, ok := j.policies[agentID]
	if !ok {
		return Verdict{Decision: "deny", Reason: fmt.Sprintf("no policy for agent %q", agentID)}
	}

	// Build prompt.
	prompt := fmt.Sprintf(
		"Given this security policy for the agent:\n%s\n\n"+
			"Should this request be allowed?\n"+
			"Method: %s\nURL: %s\nHost: %s\nContent-Type: %s\nHas auth: %v\n\n"+
			"Respond with JSON: {\"decision\": \"allow\" or \"deny\", \"reason\": \"...\"}",
		policyText, method, url, host, contentType, hasAuth,
	)

	// Call LLM.
	resp, err := j.callLLM(prompt)
	if err != nil {
		j.recordFailure()
		return Verdict{Decision: "deny", Reason: fmt.Sprintf("LLM error: %v", err)}
	}

	// Parse response.
	var parsed struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(resp)), &parsed); err != nil {
		j.recordFailure()
		return Verdict{Decision: "deny", Reason: fmt.Sprintf("unparseable LLM response: %v", err)}
	}

	// Normalize decision: anything other than "allow" is treated as "deny" (fail-closed).
	decision := strings.ToLower(parsed.Decision)
	if decision != "allow" {
		decision = "deny"
	}

	// Success: reset failures, cache result.
	j.mu.Lock()
	j.failures = 0
	v := Verdict{Decision: decision, Reason: parsed.Reason}
	j.cache[key] = cachedVerdict{verdict: v, expiry: j.now().Add(j.cacheTTL)}
	j.mu.Unlock()

	return v
}

type llmResult struct {
	response string
	err      error
}

func (j *Judge) callLLM(prompt string) (string, error) {
	ch := make(chan llmResult, 1)
	go func() {
		resp, err := j.client.Evaluate(prompt)
		ch <- llmResult{resp, err}
	}()
	select {
	case res := <-ch:
		return res.response, res.err
	case <-time.After(j.timeout):
		return "", fmt.Errorf("llmpolicy: LLM call timed out after %s", j.timeout)
	}
}

// recordFailure increments the failure counter and trips the circuit breaker if needed.
func (j *Judge) recordFailure() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.failures++
	if j.failures >= j.maxFailures {
		j.cooldownEnd = j.now().Add(j.cooldown)
	}
}
