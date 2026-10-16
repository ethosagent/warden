package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
)

const scopeReal = "real-secret-value"

// sendScoped sends req (to backend.test) through a proxy whose placeholders carry
// the given matchHosts scopes. It returns the status the client saw, the request
// the backend recorded, and the analytics events.
func sendScoped(t *testing.T, req *http.Request, values map[string]string, names []string, scopes map[string][]string) (int, *recordingBackend, []analytics.Event) {
	t.Helper()
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)
	p, store := startTestProxyWithScopedSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, values, names, scopes)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}
	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	time.Sleep(50 * time.Millisecond)
	return resp.StatusCode, rb, store.snapshot()
}

func scopedReqs(t *testing.T) map[string]*http.Request {
	t.Helper()
	hdr, _ := http.NewRequest("GET", "https://backend.test/v1", nil)
	hdr.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	hdr.Header.Set("X-Echo", "PLACEHOLDER_001")
	qry, _ := http.NewRequest("GET", "https://backend.test/v1?k=PLACEHOLDER_001", nil)
	body, _ := http.NewRequest("POST", "https://backend.test/v1", strings.NewReader(`{"prompt":"my key is PLACEHOLDER_001"}`))
	basic, _ := http.NewRequest("GET", "https://backend.test/v1", nil)
	basic.Header.Set("Authorization", basicHeader("x-access-token:PLACEHOLDER_001"))
	return map[string]*http.Request{"header": hdr, "query": qry, "body": body, "basic": basic}
}

// Regression for #373: a placeholder scoped to host A, carried in a request to
// host B, must be forwarded UNSWAPPED (header, query, body, Basic auth).
func TestHTTP_SecretScope_OutOfScopeForwardedUnswapped(t *testing.T) {
	values := map[string]string{"PLACEHOLDER_001": scopeReal}
	scopes := map[string][]string{"PLACEHOLDER_001": {"other.test", "*.llm.example.com"}}
	for name, req := range scopedReqs(t) {
		t.Run(name, func(t *testing.T) {
			status, rb, events := sendScoped(t, req, values, []string{"PLACEHOLDER_001"}, scopes)
			if status != 200 {
				t.Fatalf("status = %d, want 200 (request itself is allowed)", status)
			}
			rb.mu.Lock()
			seen := rb.path + rb.body + fmtHeaders(rb.headers)
			rb.mu.Unlock()
			if strings.Contains(seen, scopeReal) {
				t.Fatalf("real secret reached out-of-scope host: %q", seen)
			}
			if !strings.Contains(seen, "PLACEHOLDER_001") && !strings.Contains(seen, "UExBQ0VIT0xERVJfMDAx") {
				t.Fatalf("placeholder was altered/removed: %q", seen)
			}
			var oos, swapped int
			for _, e := range events {
				if e.Decision == "secret_out_of_scope" {
					oos++
					if e.Domain != "backend.test" || e.Reason != "secret_out_of_scope:PLACEHOLDER_001" {
						t.Fatalf("bad out-of-scope event: %+v", e)
					}
				}
				if e.SecretRef != "" || len(e.SwappedRefs) > 0 {
					swapped++
				}
				if eventContains(t, e, scopeReal) {
					t.Fatalf("event leaks secret: %+v", e)
				}
			}
			if oos != 1 || swapped != 0 {
				t.Fatalf("oos events = %d (want 1), swapped events = %d (want 0): %+v", oos, swapped, events)
			}
		})
	}
}

func fmtHeaders(h http.Header) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k + ":" + strings.Join(v, ",") + "\n")
	}
	return b.String()
}

// In-scope placeholders (exact, wildcard, regex, unscoped) still swap.
func TestHTTP_SecretScope_InScopeSwapped(t *testing.T) {
	values := map[string]string{"PLACEHOLDER_001": scopeReal}
	for name, hosts := range map[string][]string{
		"exact":    {"backend.test"},
		"wildcard": {"*.test"},
		"regex":    {`~^back.*\.test$`},
		"unscoped": nil,
	} {
		t.Run(name, func(t *testing.T) {
			scopes := map[string][]string{"PLACEHOLDER_001": hosts}
			for kind, req := range scopedReqs(t) {
				status, rb, events := sendScoped(t, req, values, []string{"PLACEHOLDER_001"}, scopes)
				if status != 200 {
					t.Fatalf("%s: status %d", kind, status)
				}
				rb.mu.Lock()
				seen := rb.path + rb.body + fmtHeaders(rb.headers)
				rb.mu.Unlock()
				if strings.Contains(seen, "PLACEHOLDER_001") {
					t.Fatalf("%s: in-scope placeholder not swapped: %q", kind, seen)
				}
				if kind == "basic" {
					// Base64 hides the literal, so assert the re-encoded credential.
					rb.mu.Lock()
					got := rb.headers.Get("Authorization")
					rb.mu.Unlock()
					if want := basicHeader("x-access-token:" + scopeReal); got != want {
						t.Fatalf("basic: Authorization = %q, want %q", got, want)
					}
				}
				for _, e := range events {
					if e.Decision == "secret_out_of_scope" {
						t.Fatalf("%s: unexpected out-of-scope event %+v", kind, e)
					}
				}
			}
		})
	}
}

// A missing secret 503s only when it is in scope for the destination.
func TestHTTP_SecretScope_MissingSecretOnlyInScope(t *testing.T) {
	values := map[string]string{"PLACEHOLDER_001": scopeReal} // PLACEHOLDER_002 missing
	names := []string{"PLACEHOLDER_001", "PLACEHOLDER_002"}

	req, _ := http.NewRequest("GET", "https://backend.test/v1", nil)
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	scopes := map[string][]string{"PLACEHOLDER_001": {"backend.test"}, "PLACEHOLDER_002": {"other.test"}}
	if status, _, _ := sendScoped(t, req, values, names, scopes); status != 200 {
		t.Fatalf("out-of-scope missing secret must not 503: got %d", status)
	}

	req2, _ := http.NewRequest("GET", "https://backend.test/v1", nil)
	scopes2 := map[string][]string{"PLACEHOLDER_001": {"backend.test"}, "PLACEHOLDER_002": {"backend.test"}}
	if status, _, _ := sendScoped(t, req2, values, names, scopes2); status != 503 {
		t.Fatalf("in-scope missing secret must 503: got %d", status)
	}
}

// The scope check uses the CONNECT/SNI host, not an attacker-controlled Host
// header: a mismatching Host header ends the session before any swap happens.
func TestHTTP_SecretScope_HostHeaderSpoofIgnored(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)
	p, _ := startTestProxyWithScopedSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM,
		map[string]string{"PLACEHOLDER_001": scopeReal}, []string{"PLACEHOLDER_001"},
		map[string][]string{"PLACEHOLDER_001": {"trusted.test"}})
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}
	c := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("GET", "https://backend.test/v1", nil)
	req.Host = "trusted.test"
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, c)
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if strings.Contains(fmtHeaders(rb.headers), scopeReal) {
		t.Fatal("real secret swapped for spoofed Host header")
	}
}

func TestNew_RejectsInvalidSecretScope(t *testing.T) {
	cfg := Config{PlaceholderScopes: map[string][]string{"P": {"~("}}}
	if _, err := newSecretScopes(cfg.PlaceholderScopes); err == nil {
		t.Fatal("expected error for invalid regex scope")
	}
}

// Unit-level pin that swapSecrets scopes on the session (CONNECT) domain, never
// the request's Host: the spoof test above is masked by readRequest's Host
// recheck, so call the swap stage directly with a mismatching Host.
func TestSwapSecrets_ScopeUsesSessionDomainNotReqHost(t *testing.T) {
	p, store := startTestProxyWithScopedSecrets(t, []string{"backend.test"}, nil, nil,
		map[string]string{"PLACEHOLDER_001": scopeReal}, []string{"PLACEHOLDER_001"},
		map[string][]string{"PLACEHOLDER_001": {"trusted.test"}})
	req, _ := http.NewRequest("GET", "https://backend.test/v1", nil)
	req.Host = "trusted.test"
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	s := &requestScope{domain: "backend.test", port: 443, req: req}
	if p.swapSecrets(s) {
		t.Fatal("swapSecrets ended the session")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer PLACEHOLDER_001" {
		t.Fatalf("Authorization = %q: swapped for the request Host instead of the session domain", got)
	}
	var oos bool
	for _, e := range store.snapshot() {
		oos = oos || (e.Decision == "secret_out_of_scope" && e.Domain == "backend.test")
	}
	if !oos {
		t.Fatalf("no out-of-scope event: %+v", store.snapshot())
	}
}
