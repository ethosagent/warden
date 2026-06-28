// Package llm provides a concrete, OpenAI-compatible chat-completions HTTP
// client that satisfies llmpolicy.LLMClient. It is the only place that talks to
// an external LLM provider; the judge and advisor depend on the interface, not
// on this implementation.
//
// Logging hygiene (a core Warden invariant) applies here too: the API key is
// read from an environment variable and is NEVER logged. This package does not
// log prompts or responses at all — callers decide what to record, and they
// record metadata only, never bodies.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config configures the OpenAI-compatible client.
type Config struct {
	// BaseURL is the API root (e.g. "https://api.openai.com/v1"). The client
	// posts to BaseURL + "/chat/completions".
	BaseURL string
	// Model is the chat model name (e.g. "gpt-4o-mini").
	Model string
	// APIKey is the bearer token. It is sent in the Authorization header and is
	// never logged.
	APIKey string
	// Timeout bounds each HTTP request. Zero means no client-level timeout (the
	// judge applies its own timeout on top).
	Timeout time.Duration
	// HTTPClient is optional; when nil a default client is constructed with
	// Timeout. Injecting one is primarily for tests (httptest.Server).
	HTTPClient *http.Client
}

// Client is an OpenAI-compatible chat-completions client.
type Client struct {
	baseURL string
	model   string
	apiKey  string
	http    *http.Client
}

// NewClient validates the config and constructs a Client. It does not perform
// any network I/O.
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("llm: BaseURL is required")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, fmt.Errorf("llm: Model is required")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("llm: APIKey is required")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		model:   cfg.Model,
		apiKey:  cfg.APIKey,
		http:    httpClient,
	}, nil
}

// chatRequest is the OpenAI chat-completions request body.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse captures the assistant text we need from the response.
type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Evaluate sends prompt as a single user message and returns the assistant's
// text. It satisfies llmpolicy.LLMClient. Errors never include the API key.
func (c *Client) Evaluate(prompt string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:    c.model,
		Messages: []chatMessage{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", fmt.Errorf("llm: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the read so a hostile/buggy upstream cannot exhaust memory.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("llm: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do not echo the response body verbatim — it may contain echoed input.
		return "", fmt.Errorf("llm: upstream status %d", resp.StatusCode)
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("llm: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("llm: response had no choices")
	}
	return parsed.Choices[0].Message.Content, nil
}

// maxResponseBytes caps the response read. Judge verdicts are tiny JSON; this
// is a generous ceiling that still prevents memory exhaustion.
const maxResponseBytes = 1 << 20 // 1 MB
