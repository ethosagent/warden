package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/test/fakes"
)

func gzipTwice(s string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(gzipBytes(s))
	_ = zw.Close()
	return b.Bytes()
}

func requireNoValue(t *testing.T, what string, got []byte) {
	t.Helper()
	if lp := leakedPrefix(got); lp != "" {
		t.Fatalf("%s carries the secret (%s): %q", what, lp, got)
	}
}

func TestEchoGuard_TrailerSecret(t *testing.T) {
	trailerHandler := func(withLength bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Trailer", "X-Echo")
			if withLength {
				w.Header().Set("Content-Length", "5")
			}
			_, _ = io.WriteString(w, "hello")
			if !withLength {
				w.(http.Flusher).Flush() // unknown length: the body is streamed
			}
			w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		}
	}
	t.Run("streaming", func(t *testing.T) {
		eachProto(t, func(t *testing.T, h2 bool) {
			e := newEchoEnv(t, trailerHandler(false), nil)
			res := e.do(h2, echoReq(t, "GET", "/t", bearer(), ""))
			if res.err == nil {
				t.Fatalf("stream with a secret in its trailer was not aborted: %+v", res)
			}
			requireNoValue(t, "trailer", []byte(fmt.Sprint(res.trailer)))
			evs := e.events(1)
			if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != "secret_echo" {
				t.Fatalf("events = %+v", evs)
			}
		})
	})
	t.Run("buffered", func(t *testing.T) {
		// A known length plus trailers is only expressible on h2.
		e := newEchoEnv(t, trailerHandler(true), nil)
		res := e.do(true, echoReq(t, "GET", "/t", bearer(), ""))
		requireBlocked(t, e, res, "secret_echo")
		requireNoValue(t, "trailer", []byte(fmt.Sprint(res.trailer)))
	})
}

func TestEchoGuard_NoBodyResponses(t *testing.T) {
	cases := []struct {
		name   string
		method string
		status int
	}{{"HEAD", "HEAD", 200}, {"204", "GET", 204}, {"304", "GET", 304}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eachProto(t, func(t *testing.T, h2 bool) {
				e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(c.status)
				}, nil)
				res := e.do(h2, echoReq(t, c.method, "/n", bearer(), ""))
				if res.err != nil || res.status != c.status {
					t.Fatalf("clean bodyless response not relayed: %+v", res)
				}
				evs := e.events(1)
				if len(evs) != 1 || evs[0].Decision != "allow" {
					t.Fatalf("events = %+v, want one allow", evs)
				}
			})
		})
		t.Run(c.name+"_header_echo", func(t *testing.T) {
			eachProto(t, func(t *testing.T, h2 bool) {
				e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Echo", r.Header.Get("Authorization"))
					w.WriteHeader(c.status)
				}, nil)
				res := e.do(h2, echoReq(t, c.method, "/n", bearer(), ""))
				if res.status != 502 {
					t.Fatalf("header echo on a bodyless response not blocked: %+v", res)
				}
				requireNoValue(t, "headers", []byte(fmt.Sprint(res.header)))
			})
		})
	}
}

func TestEchoGuard_MonitorStreamingHit(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		half := len(echoTestValue) / 2
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			f := w.(http.Flusher)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "one "+echoTestValue[:half])
			f.Flush()
			time.Sleep(30 * time.Millisecond)
			_, _ = io.WriteString(w, echoTestValue[half:]+" two")
			f.Flush()
		}, func(c *Config) { c.EchoGuard = EchoGuardConfig{Monitor: true} })
		res := e.do(h2, echoReq(t, "GET", "/m", bearer(), ""))
		if res.err != nil || res.status != 200 || string(res.body) != "one "+echoTestValue+" two" {
			t.Fatalf("monitor must forward the whole stream: %+v", res)
		}
		evs := e.events(1)
		if len(evs) != 1 || evs[0].Decision != "allow" || evs[0].Reason != "secret_echo" {
			t.Fatalf("events = %+v, want one allow/secret_echo", evs)
		}
		e.assertNoValueInEvents()
	})
}

func TestEchoGuard_CodingChains(t *testing.T) {
	write := func(coding string, body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", coding)
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			_, _ = w.Write(body)
		}
	}
	withAE := func() map[string]string { h := bearer(); h["Accept-Encoding"] = "gzip"; return h }
	t.Run("gzip_gzip_echo", func(t *testing.T) {
		eachProto(t, func(t *testing.T, h2 bool) {
			e := newEchoEnv(t, write("gzip, gzip", gzipTwice("v="+echoTestValue)), nil)
			requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/c", withAE(), "")), "secret_echo")
		})
	})
	t.Run("gzip_gzip_clean", func(t *testing.T) {
		eachProto(t, func(t *testing.T, h2 bool) {
			payload := gzipTwice("fine")
			e := newEchoEnv(t, write("gzip, gzip", payload), nil)
			res := e.do(h2, echoReq(t, "GET", "/c", withAE(), ""))
			if res.err != nil || res.status != 200 || !bytes.Equal(res.body, payload) {
				t.Fatalf("clean nested gzip altered: %+v", res)
			}
		})
	})
	t.Run("gzip_identity_echo", func(t *testing.T) {
		eachProto(t, func(t *testing.T, h2 bool) {
			e := newEchoEnv(t, write("gzip, identity", gzipBytes("v="+echoTestValue)), nil)
			requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/c", withAE(), "")), "secret_echo")
		})
	})
	t.Run("gzip_identity_clean", func(t *testing.T) {
		eachProto(t, func(t *testing.T, h2 bool) {
			payload := gzipBytes("fine")
			e := newEchoEnv(t, write("gzip, identity", payload), nil)
			res := e.do(h2, echoReq(t, "GET", "/c", withAE(), ""))
			if res.err != nil || res.status != 200 || !bytes.Equal(res.body, payload) {
				t.Fatalf("clean gzip,identity altered: %+v", res)
			}
		})
	})
}

func TestEchoGuard_CompressedUnknownLengthBlockedImmediately(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "text/plain")
			w.(http.Flusher).Flush() // unknown length
			_, _ = w.Write(gzipBytes("fine, and clean"))
		}, nil)
		h := bearer()
		h["Accept-Encoding"] = "gzip"
		requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/u", h, "")), "secret_echo_unscannable")
	})
}

func TestEchoGuard_SigV4WithoutTokenKeepsAcceptEncoding(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		mt, err := auth.NewMatchedTransformer(echoHost, auth.NewAWSSigV4("AKIDEXAMPLE", "secretkey", "", "us-east-1", "s3"))
		if err != nil {
			t.Fatal(err)
		}
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }, func(c *Config) {
			c.Transformers = []*auth.MatchedTransformer{mt}
			c.PlaceholderNames = nil
		})
		res := e.do(h2, echoReq(t, "GET", "/s", map[string]string{"Accept-Encoding": "gzip, br"}, ""))
		if res.err != nil || res.status != 200 {
			t.Fatalf("request failed: %+v", res)
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if len(e.upstrAE) != 1 || e.upstrAE[0] != "gzip, br" {
			t.Fatalf("Accept-Encoding upstream = %q, want the client's untouched", e.upstrAE)
		}
	})
}

// ---- event URL: no event or log line may carry a value swapped into the query ----

type echoLogBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *echoLogBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *echoLogBuf) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

// urlGW is an MCP gateway that passes requests and answers every response with
// verdict.
type urlGW struct {
	fakeMCPGateway
	verdict gateway.Verdict
}

func (g *urlGW) OnRequest(string, string, string, http.Header, []byte) gateway.Verdict {
	return gateway.Verdict{Action: gateway.Pass, Tool: "t"}
}

func (g *urlGW) OnResponse(string, int, http.Header, []byte) gateway.Verdict { return g.verdict }

const mcpCallBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"}}`

func TestEvents_QuerySwapNeverRendersTheValue(t *testing.T) {
	const otherPH = "rt_other_secret_002"
	query := "?a=" + echoPlaceholder + "&b=keep"
	mcpHdr := map[string]string{"Content-Type": "application/json"}
	jsonOK := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}
	sse := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
	}
	mcp := func(v gateway.Verdict) func(*Config) {
		return func(c *Config) { c.MCP = &urlGW{verdict: v} }
	}
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		mutate   func(*Config)
		method   string
		hdr      map[string]string
		body     string
		path     string
		wantKind string // an event with this Decision must exist
		extra    string // appended to the query
	}{
		{"echo_deny", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.URL.RawQuery) }, nil, "GET", nil, "", "/q", "deny", ""},
		{"allow", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }, nil, "GET", nil, "", "/q", "allow", ""},
		{"out_of_scope", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }, func(c *Config) {
			c.Secrets = &fakes.FakeSecretProvider{Values: map[string]string{echoPlaceholder: echoTestValue, otherPH: "other-secret-value"}}
			c.PlaceholderNames = []string{echoPlaceholder, otherPH}
			c.PlaceholderScopes = map[string][]string{otherPH: {"elsewhere.test"}}
		}, "GET", nil, "", "/q", decisionSecretOutOfScope, "&c=" + otherPH},
		{"mcp_response_deny", jsonOK, mcp(gateway.Verdict{Action: gateway.Deny, Reason: "mcp_resp"}), "POST", mcpHdr, mcpCallBody, "/q", "deny", ""},
		{"mcp_sse_allow", sse, mcp(gateway.Verdict{Action: gateway.Pass}), "POST", mcpHdr, mcpCallBody, "/q", "allow", ""},
		{"mcp_sse_deny", sse, mcp(gateway.Verdict{Action: gateway.Deny, Reason: "mcp_resp"}), "POST", mcpHdr, mcpCallBody, "/q", "deny", ""},
		{"http_response_scan_deny", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, leakBody)
		}, func(c *Config) { c.ResponseScan = NewResponseScanner("enforce", 1<<20, false, false) }, "GET", nil, "", "/q", "deny", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eachProto(t, func(t *testing.T, h2 bool) {
				logs := &echoLogBuf{}
				e := newEchoEnv(t, c.handler, func(cfg *Config) {
					cfg.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
					if c.mutate != nil {
						c.mutate(cfg)
					}
				})
				res := e.do(h2, echoReq(t, c.method, c.path+query+c.extra, c.hdr, c.body))
				if c.wantKind != "deny" && res.err != nil {
					t.Fatalf("request failed: %v", res.err)
				}
				evs := e.events(1)
				var kinds []string
				found := false
				for _, ev := range evs {
					kinds = append(kinds, ev.Decision)
					found = found || ev.Decision == c.wantKind
					assertEventURLClean(t, ev)
				}
				if !found {
					t.Fatalf("no %q event among %v", c.wantKind, kinds)
				}
				requireNoValue(t, "log output", logs.bytes())
			})
		})
	}
}

func assertEventURLClean(t *testing.T, ev analytics.Event) {
	t.Helper()
	if lp := leakedPrefix([]byte(fmt.Sprintf("%+v", ev))); lp != "" {
		t.Fatalf("event carries the secret (%s): %+v", lp, ev)
	}
	if !strings.Contains(ev.URL, "a="+echoPlaceholder) {
		t.Fatalf("event URL %q should keep the agent's original query", ev.URL)
	}
}

func TestEvents_QuerySwapStreamBodyTransformDeny(t *testing.T) {
	mt, err := auth.NewMatchedTransformer(echoHost, auth.NewAWSSigV4("AKIDEXAMPLE", "secretkey", "", "us-east-1", "s3"))
	if err != nil {
		t.Fatal(err)
	}
	logs := &echoLogBuf{}
	e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }, func(c *Config) {
		c.Transformers = []*auth.MatchedTransformer{mt}
		c.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	hdr := map[string]string{"Content-Type": "application/grpc", "Te": "trailers"}
	_ = e.do(true, echoReq(t, "POST", "/pkg.Svc/Get?a="+echoPlaceholder, hdr, string(grpcFrame("req"))))
	evs := e.events(1)
	if len(evs) != 1 || evs[0].Reason != "transform_needs_buffered_body" {
		t.Fatalf("events = %+v, want one transform_needs_buffered_body deny", evs)
	}
	assertEventURLClean(t, evs[0])
	requireNoValue(t, "log output", logs.bytes())
}
