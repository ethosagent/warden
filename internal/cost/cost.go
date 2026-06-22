// Package cost provides rough cost estimation for LLM API traffic based on
// observed request/response sizes and known provider pricing. Estimates are
// heuristic (bytes / 4 ≈ tokens) and not billing-grade — they exist to give
// operators order-of-magnitude visibility into agent spend.
package cost

import "strings"

// Provider represents a known LLM provider for cost estimation.
type Provider struct {
	Name            string
	DomainPattern   string  // exact domain match (no regex needed for built-ins)
	InputCostPer1K  float64 // $ per 1K tokens (estimated from bytes)
	OutputCostPer1K float64
}

// CostEstimate holds the estimated cost for a single request/response pair.
type CostEstimate struct {
	Provider     string
	InputCost    float64
	OutputCost   float64
	TotalCost    float64
	InputTokens  int64 // estimated: bytes / 4
	OutputTokens int64
}

// defaultProviders contains heuristic pricing for popular LLM API providers.
// These are rough estimates, not billing-grade figures.
var defaultProviders = []Provider{
	{Name: "openai", DomainPattern: "api.openai.com", InputCostPer1K: 0.005, OutputCostPer1K: 0.015},
	{Name: "anthropic", DomainPattern: "api.anthropic.com", InputCostPer1K: 0.003, OutputCostPer1K: 0.015},
	{Name: "google", DomainPattern: "generativelanguage.googleapis.com", InputCostPer1K: 0.00025, OutputCostPer1K: 0.0005},
	{Name: "cohere", DomainPattern: "api.cohere.com", InputCostPer1K: 0.001, OutputCostPer1K: 0.002},
}

// Estimator estimates cost from observed traffic.
type Estimator struct {
	providers []Provider
}

// NewEstimator creates an Estimator loaded with the default provider pricing.
func NewEstimator() *Estimator {
	return &Estimator{
		providers: defaultProviders,
	}
}

// bytesToTokens converts byte count to estimated token count.
// Rough approximation: 1 token ≈ 4 bytes for English text.
func bytesToTokens(bytes int64) int64 {
	return bytes / 4
}

// Estimate returns the estimated cost for a request/response to the given
// domain with the given request/response sizes in bytes.
// Returns nil if the domain does not match any known provider.
func (e *Estimator) Estimate(domain string, requestBytes, responseBytes int64) *CostEstimate {
	domain = strings.ToLower(strings.TrimSpace(domain))
	var matched *Provider
	for i := range e.providers {
		if e.providers[i].DomainPattern == domain {
			matched = &e.providers[i]
			break
		}
	}
	if matched == nil {
		return nil
	}

	inputTokens := bytesToTokens(requestBytes)
	outputTokens := bytesToTokens(responseBytes)

	inputCost := float64(inputTokens) / 1000.0 * matched.InputCostPer1K
	outputCost := float64(outputTokens) / 1000.0 * matched.OutputCostPer1K

	return &CostEstimate{
		Provider:     matched.Name,
		InputCost:    inputCost,
		OutputCost:   outputCost,
		TotalCost:    inputCost + outputCost,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
	}
}
