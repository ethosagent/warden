package cost

import (
	"math"
	"testing"
)

const floatTol = 1e-9

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < floatTol
}

func TestEstimate_OpenAI(t *testing.T) {
	e := NewEstimator()
	// 4000 bytes = 1000 tokens
	est := e.Estimate("api.openai.com", 4000, 8000)
	if est == nil {
		t.Fatal("expected non-nil estimate for OpenAI")
	}
	if est.Provider != "openai" {
		t.Errorf("Provider = %q, want %q", est.Provider, "openai")
	}
	if est.InputTokens != 1000 {
		t.Errorf("InputTokens = %d, want %d", est.InputTokens, 1000)
	}
	if est.OutputTokens != 2000 {
		t.Errorf("OutputTokens = %d, want %d", est.OutputTokens, 2000)
	}
	// InputCost = 1000/1000 * 0.005 = 0.005
	if !almostEqual(est.InputCost, 0.005) {
		t.Errorf("InputCost = %f, want %f", est.InputCost, 0.005)
	}
	// OutputCost = 2000/1000 * 0.015 = 0.030
	if !almostEqual(est.OutputCost, 0.030) {
		t.Errorf("OutputCost = %f, want %f", est.OutputCost, 0.030)
	}
	// TotalCost = 0.005 + 0.030 = 0.035
	if !almostEqual(est.TotalCost, 0.035) {
		t.Errorf("TotalCost = %f, want %f", est.TotalCost, 0.035)
	}
}

func TestEstimate_Anthropic(t *testing.T) {
	e := NewEstimator()
	est := e.Estimate("api.anthropic.com", 4000, 4000)
	if est == nil {
		t.Fatal("expected non-nil estimate for Anthropic")
	}
	if est.Provider != "anthropic" {
		t.Errorf("Provider = %q, want %q", est.Provider, "anthropic")
	}
	// 4000 bytes = 1000 tokens
	if est.InputTokens != 1000 {
		t.Errorf("InputTokens = %d, want %d", est.InputTokens, 1000)
	}
}

func TestEstimate_UnknownDomain(t *testing.T) {
	e := NewEstimator()
	est := e.Estimate("unknown.example.com", 4000, 4000)
	if est != nil {
		t.Errorf("expected nil for unknown domain, got %+v", est)
	}
}

func TestEstimate_ZeroBytes(t *testing.T) {
	e := NewEstimator()
	est := e.Estimate("api.openai.com", 0, 0)
	if est == nil {
		t.Fatal("expected non-nil estimate for known domain with zero bytes")
	}
	if est.InputTokens != 0 {
		t.Errorf("InputTokens = %d, want 0", est.InputTokens)
	}
	if est.OutputTokens != 0 {
		t.Errorf("OutputTokens = %d, want 0", est.OutputTokens)
	}
	if !almostEqual(est.TotalCost, 0) {
		t.Errorf("TotalCost = %f, want 0", est.TotalCost)
	}
}

func TestEstimate_TokenEstimation(t *testing.T) {
	e := NewEstimator()
	// 100 bytes → 25 tokens (100/4)
	est := e.Estimate("api.openai.com", 100, 200)
	if est == nil {
		t.Fatal("expected non-nil estimate")
	}
	if est.InputTokens != 25 {
		t.Errorf("InputTokens = %d, want %d", est.InputTokens, 25)
	}
	if est.OutputTokens != 50 {
		t.Errorf("OutputTokens = %d, want %d", est.OutputTokens, 50)
	}
}

func TestEstimate_Google(t *testing.T) {
	e := NewEstimator()
	est := e.Estimate("generativelanguage.googleapis.com", 4000, 4000)
	if est == nil {
		t.Fatal("expected non-nil estimate for Google")
	}
	if est.Provider != "google" {
		t.Errorf("Provider = %q, want %q", est.Provider, "google")
	}
}

func TestEstimate_Cohere(t *testing.T) {
	e := NewEstimator()
	est := e.Estimate("api.cohere.com", 4000, 4000)
	if est == nil {
		t.Fatal("expected non-nil estimate for Cohere")
	}
	if est.Provider != "cohere" {
		t.Errorf("Provider = %q, want %q", est.Provider, "cohere")
	}
}
