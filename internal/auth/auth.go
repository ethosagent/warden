// Package auth injects real, request-scoped credentials into outbound requests at
// the proxy edge (OAuth2 client-credentials, AWS SigV4, HMAC, and API-key), matched
// to destinations by host, suffix, or regex. Credentials are resolved from the
// environment and held by the proxy only — the agent never sees them.
package auth

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/ethosagent/warden/internal/policy"
)

// RequestTransformer modifies an outbound HTTP request for authentication.
type RequestTransformer interface {
	Transform(req *http.Request) error
}

// MatchedTransformer applies a RequestTransformer only when the request
// destination matches the configured domain pattern.
type MatchedTransformer struct {
	Pattern     string // exact, *.wildcard, or ~regex
	Transformer RequestTransformer
	re          *regexp.Regexp // compiled if Pattern starts with ~
}

func NewMatchedTransformer(pattern string, t RequestTransformer) (*MatchedTransformer, error) {
	m := &MatchedTransformer{Pattern: pattern, Transformer: t}
	if strings.HasPrefix(pattern, "~") {
		re, err := regexp.Compile(pattern[1:])
		if err != nil {
			return nil, fmt.Errorf("auth: invalid regex pattern %q: %w", pattern, err)
		}
		m.re = re
	}
	return m, nil
}

func (m *MatchedTransformer) Matches(host string) bool {
	// policy.NormalizeHost is the one shared host normalisation (#397): case
	// and any number of trailing dots never decide the match, and a host that
	// is only dots — or empty — matches nothing (the request would otherwise
	// be forwarded without its credential).
	host = policy.NormalizeHost(host)
	if host == "" {
		return false
	}
	if m.re != nil {
		return m.re.MatchString(host)
	}
	pattern := policy.NormalizeHost(m.Pattern)
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return host != suffix && strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}
