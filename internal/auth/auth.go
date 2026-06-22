package auth

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
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
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	pattern := strings.ToLower(m.Pattern)
	if m.re != nil {
		return m.re.MatchString(host)
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return host != suffix && strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}
