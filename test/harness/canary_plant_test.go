package harness

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
)

// The planted-leak tests: each oracle surface gets its own test that plants a
// canary there and proves AssertCanaryNeverLeaked fails NAMING that surface.
// A surface the sweep stopped scanning would leave exactly one red test here —
// that is the point: the oracle's coverage is pinned test by test, not by one
// mega-test that fails for any of ten reasons.
//
// Real flow (a request through the worker) is used wherever the production
// pipeline could actually produce the leak; the logs/events/metrics stores and
// the encoded upstream forms are planted directly — production surfaces that
// by design never carry raw values, so a regression (or a future change that
// starts leaking) is simulated at the oracle's own boundary.

// plantEcho mounts a handler on u that echoes the request body back as the
// response body — a malicious reflector, entirely within the fake's powers.
func plantEcho(u *Upstream) {
	u.SetNext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
}

// postThrough sends one POST with the given body through the harness agent
// (the worker proxy) to the host, failing t on anything but a 200.
func postThrough(t *testing.T, h *H, host, path, body string) {
	t.Helper()
	resp, err := h.Agent().Post("https://"+host+path, "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s%s through the worker: %v", host, path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s%s = %d, want 200", host, path, resp.StatusCode)
	}
}

// assertPlanted runs the sweep on a recording TB and requires one failure that
// names the expected surface (and, when set, the encoding).
func assertPlanted(t *testing.T, h *H, want ...string) {
	t.Helper()
	rec := &recordingTB{T: t}
	h.assertCanaryNeverLeaked(rec)
	if !rec.Failed() {
		t.Fatalf("AssertCanaryNeverLeaked PASSED with a canary planted where it must never appear; want failure naming %q", want)
	}
	msg := rec.failureMessage()
	for _, w := range want {
		if !strings.Contains(msg, w) {
			t.Errorf("oracle failure does not name %q:\n%s", w, msg)
		}
	}
}

// TestCanary_Plant_AgentResponseBody: a reflector upstream bounces the swapped
// value straight back — the leak lands in what the AGENT's transcript records.
func TestCanary_Plant_AgentResponseBody(t *testing.T) {
	value := Canary()
	h := New(t, WithSecret("openai", value), Allow("echo.example.com"))
	u := h.Upstream("echo.example.com")
	plantEcho(u)

	postThrough(t, h, "echo.example.com", "/reflect", "token="+value)

	assertPlanted(t, h, "agent response #0 body")
}

// TestCanary_Plant_AgentResponseHeaders: the same reflector, but the value
// rides a response HEADER — a different scan than the body's.
func TestCanary_Plant_AgentResponseHeaders(t *testing.T) {
	value := Canary()
	h := New(t, WithSecret("openai", value), Allow("echo.example.com"))
	u := h.Upstream("echo.example.com")
	u.SetNext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Reflected", r.Header.Get("X-Token"))
		w.WriteHeader(http.StatusOK)
	}))

	req, err := http.NewRequest(http.MethodGet, "https://echo.example.com/reflect", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Token", value)
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("GET the reflector through the worker: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET the reflector = %d, want 200", resp.StatusCode)
	}

	assertPlanted(t, h, "agent response #0 headers")
}

// TestCanary_Plant_AgentRequestURL: the agent itself is the leak — it puts the
// value in a query string (a sloppy integration pastes its secret into a URL).
// The transcript's URL is a scanned surface of its own.
func TestCanary_Plant_AgentRequestURL(t *testing.T) {
	value := Canary()
	h := New(t, WithSecret("openai", value), Allow("api.example.com"))
	h.Upstream("api.example.com")

	resp, err := h.Agent().Get("https://api.example.com/search?q=" + url.QueryEscape(value))
	if err != nil {
		t.Fatalf("GET with the value in the URL: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", resp.StatusCode)
	}

	assertPlanted(t, h, "agent response #0 url")
}

// TestCanary_Plant_Logs: the value reached the component logs. Production
// never logs raw values (an AGENTS.md invariant), so the plant is at the
// oracle's boundary: a Target whose Logs() carries it.
func TestCanary_Plant_Logs(t *testing.T) {
	value := Canary()
	ft := &fakeTarget{logs: `{"level":"info","msg":"leaked ` + value + `"}`}
	h := New(t, WithTarget(ft), WithSecret("openai", value))

	assertPlanted(t, h, "worker/control-plane logs")
}

// TestCanary_Plant_Events: the value reached analytics. The Event fields are
// documented never-secret carriers, so the plant simulates a regression that
// put a raw value into one (SecretRef, the field closest to secrets).
func TestCanary_Plant_Events(t *testing.T) {
	value := Canary()
	ft := &fakeTarget{events: []analytics.Event{{
		Domain:    "llm.example.com",
		Decision:  "allow",
		Protocol:  "https",
		SecretRef: value,
	}}}
	h := New(t, WithTarget(ft), WithSecret("openai", value))

	assertPlanted(t, h, "analytics event #0")
}

// TestCanary_Plant_MetricKeys: the value reached a metric LABEL (unbounded
// cardinality lives in event fields, not labels — a label carrying a secret is
// the leak class this scan exists for).
func TestCanary_Plant_MetricKeys(t *testing.T) {
	value := Canary()
	ft := &fakeTarget{metrics: map[string]float64{
		`warden.requests.total{decision="allow",secret="` + value + `"}`: 1,
	}}
	h := New(t, WithTarget(ft), WithSecret("openai", value))

	assertPlanted(t, h, "metric key")
}

// TestCanary_Plant_Encodings pins the sweep ONE CASE PER ENCODING, each on an
// upstream request (header or body) with the failure naming the upstream and
// the encoding. The plants are white-box RecordedRequests — the worker's swap
// never encodes, so every encoded form on the wire is a hypothetical pipeline
// regression; the upstream-raw case (scoped secret, out-of-scope host) is
// pinned separately by TestCanary_UpstreamOutOfScopeCaught.
func TestCanary_Plant_Encodings(t *testing.T) {
	cases := []struct {
		name     string
		value    string // the secret value (default: a fresh canary)
		plant    func(v string) RecordedRequest
		wantForm string
	}{
		{
			name: "base64 padded, in a body",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("payload=" + base64.StdEncoding.EncodeToString([]byte(v))),
				}
			},
			wantForm: "base64",
		},
		{
			name: "base64 unpadded (padding stripped)",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("payload=" + base64.RawStdEncoding.EncodeToString([]byte(v))),
				}
			},
			wantForm: "base64-unpadded",
		},
		{
			// \xff\xff\xff\x21 encodes to a "____…" blob in the url alphabet
			// and "////…" in the std one, so the two alphabets' forms are
			// provably distinct — and 4 bytes ≡ 1 (mod 3), so padded and
			// unpadded differ too.
			name:  "base64url padded",
			value: "\xff\xff\xff\x21",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("payload=" + base64.URLEncoding.EncodeToString([]byte(v))),
				}
			},
			wantForm: "base64url",
		},
		{
			name:  "base64url unpadded",
			value: "\xff\xff\xff\x21",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("payload=" + base64.RawURLEncoding.EncodeToString([]byte(v))),
				}
			},
			wantForm: "base64url-unpadded",
		},
		{
			name: "hex lowercase",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("fingerprint=" + hex.EncodeToString([]byte(v))),
				}
			},
			wantForm: "hex",
		},
		{
			name: "hex uppercase",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("fingerprint=" + strings.ToUpper(hex.EncodeToString([]byte(v)))),
				}
			},
			wantForm: "HEX",
		},
		{
			// The escapes only differ from raw for values WITH reserved
			// characters, so these two cases use a crafted value.
			name:  "url query escaped",
			value: "p4ss w?rd&=",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/search",
					Body: []byte("q=" + url.QueryEscape(v)),
				}
			},
			wantForm: "url-query-escaped",
		},
		{
			// A value whose PathEscape differs from its QueryEscape (space, '='):
			// "a b/c=d" escapes to "a%20b%2Fc%3Dd" on the path but "a+b%2Fc%3Dd"
			// in a query, so only the path form matches the plant.
			name:  "url path escaped",
			value: "a b/c=d",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/file",
					Body: []byte("name=" + url.PathEscape(v)),
				}
			},
			wantForm: "url-path-escaped",
		},
		{
			// The motivating alignment case: a Basic header the worker swapped
			// inside — the value sits at bit offset 5*8 mod 3 within
			// base64("user:"+v), which no plain base64 form can match.
			name: "basic auth base64, value at shifted alignment",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/login",
					Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+v))}},
				}
			},
			wantForm: "base64@shift2",
		},
		{
			name: "base64 with a 1-byte prefix (shift 1)",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("blob=" + base64.StdEncoding.EncodeToString([]byte(":"+v))),
				}
			},
			wantForm: "base64@shift1",
		},
		{
			// "abcd:" is 5 bytes ≡ 2 (mod 3) — the url alphabet at shift 2. The
			// alphabet-distinct value keeps the URL form's name unambiguous (a
			// canary's std and url encodings can coincide).
			name:  "base64url at shifted alignment",
			value: "\xff\xff\xff\x21",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("blob=" + base64.URLEncoding.EncodeToString([]byte("abcd:"+v))),
				}
			},
			wantForm: "base64url@shift2",
		},
		{
			// ":" is 1 byte ≡ 1 (mod 3) — the url alphabet at shift 1.
			name:  "base64url with a 1-byte prefix (shift 1)",
			value: "\xff\xff\xff\x21",
			plant: func(v string) RecordedRequest {
				return RecordedRequest{
					Method: http.MethodPost, Host: "api.example.com", Path: "/upload",
					Body: []byte("blob=" + base64.URLEncoding.EncodeToString([]byte(":"+v))),
				}
			},
			wantForm: "base64url@shift1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := tc.value
			if value == "" {
				value = Canary()
			}
			h := New(t, WithSecret("openai", value))
			u := h.Upstream("api.example.com") // IN scope: only the encoding makes it a leak

			u.mu.Lock()
			u.reqs = append(u.reqs, tc.plant(value))
			u.mu.Unlock()

			assertPlanted(t, h, "upstream api.example.com request #0", tc.wantForm)
		})
	}
}
