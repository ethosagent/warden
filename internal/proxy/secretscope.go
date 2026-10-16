package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/policy"
)

// decisionSecretOutOfScope is the analytics Decision for a placeholder that was
// present in a request to a host outside its matchHosts. It is deliberately
// neither "allow" nor "deny" so allow/deny counts are unchanged.
const decisionSecretOutOfScope = "secret_out_of_scope"

// newSecretScopes compiles per-placeholder matchHosts once at startup. Entries
// with no hosts are unscoped and omitted.
func newSecretScopes(scopes map[string][]string) (map[string]*policy.HostMatcher, error) {
	out := make(map[string]*policy.HostMatcher, len(scopes))
	for placeholder, hosts := range scopes {
		if len(hosts) == 0 {
			continue
		}
		m, err := policy.NewHostMatcher(hosts)
		if err != nil {
			return nil, fmt.Errorf("proxy: placeholder %q matchHosts: %w", placeholder, err)
		}
		out[placeholder] = m
	}
	return out, nil
}

// placeholderInScope reports whether placeholder may be swapped for a request to
// host. host MUST be the CONNECT/SNI destination (the host the policy decision
// used and the upstream is dialed at) — never a request Host header or URL host,
// which the agent controls. Unscoped placeholders are always in scope.
func (p *Proxy) placeholderInScope(placeholder, host string) bool {
	m, scoped := p.scopes[placeholder]
	return !scoped || m.Matches(host)
}

// headerCarriesPlaceholder reports whether any header value carries placeholder,
// raw or inside HTTP Basic auth (Authorization only, as in the swap itself). It
// never needs the secret value: the swap helper is probed with an empty value.
func headerCarriesPlaceholder(h http.Header, placeholder string) bool {
	for key, vals := range h {
		for _, v := range vals {
			if strings.Contains(v, placeholder) {
				return true
			}
			if key == "Authorization" {
				if _, ok := swapBasicAuth(v, placeholder, ""); ok {
					return true
				}
			}
		}
	}
	return false
}

// queryCarriesPlaceholder reports whether any decoded query value carries
// placeholder (the same view the swap rewrites).
func queryCarriesPlaceholder(u *url.URL, placeholder string) bool {
	if u.RawQuery == "" {
		return false
	}
	for _, vals := range u.Query() {
		for _, v := range vals {
			if strings.Contains(v, placeholder) {
				return true
			}
		}
	}
	return false
}

// recordOutOfScope emits one analytics event + log record per placeholder that
// was present but out of scope. Only the placeholder NAME is recorded.
func (p *Proxy) recordOutOfScope(domain string, port int, protocol, method, uri string, names []string) {
	fullURL := "https://" + domain + uri
	for _, name := range names {
		reason := decisionSecretOutOfScope + ":" + name
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  protocol,
			Method:    method,
			URL:       fullURL,
			Decision:  decisionSecretOutOfScope,
			Reason:    reason,
		})
		p.logDecision(decisionLog{
			Domain: domain, Port: port, Protocol: protocol,
			Method: method, URL: fullURL, Decision: decisionSecretOutOfScope,
		})
	}
}
