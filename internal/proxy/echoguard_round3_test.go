package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/test/fakes"
)

const coldToken = "cold-start-bearer-TOKEN-leak"

// A transformer that learns its value only when it first runs (a cold OAuth2
// token) must still have that value guarded on the very first request.
func TestEchoGuard_ColdOAuth2FirstRequestBlocked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		hdr    map[string]string
		reason string
		h      http.HandlerFunc
	}{
		{"plain", nil, "secret_echo", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"Authorization":%q}`, r.Header.Get("Authorization"))
		}},
		{"client_asks_gzip_answer_gzipped", map[string]string{"Accept-Encoding": "gzip"}, "secret_echo",
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write(gzipBytes(`{"Authorization":"` + r.Header.Get("Authorization") + `"}`))
			}},
		{"client_asks_gzip_answer_chunked_gzip", map[string]string{"Accept-Encoding": "gzip"}, "secret_echo_unscannable",
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				zw := gzip.NewWriter(w)
				_, _ = io.WriteString(zw, r.Header.Get("Authorization"))
				_ = zw.Close()
				w.(http.Flusher).Flush()
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eachProto(t, func(t *testing.T, h2 bool) {
				tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": coldToken, "expires_in": 3600, "token_type": "Bearer"})
				}))
				defer tokenSrv.Close()
				oa := auth.NewOAuth2ClientCredentials(tokenSrv.Client(), tokenSrv.URL, "id", "sec", nil)
				if len(oa.InjectedSecrets()) != 0 {
					t.Fatal("precondition: a fresh OAuth2 transformer must report no secret yet")
				}
				mt, err := auth.NewMatchedTransformer(echoHost, oa)
				if err != nil {
					t.Fatal(err)
				}
				e := newEchoEnv(t, tc.h, func(c *Config) {
					c.Transformers = []*auth.MatchedTransformer{mt}
					c.PlaceholderNames = nil
				})
				res := e.do(h2, echoReq(t, "GET", "/first", tc.hdr, ""))
				if res.err != nil || res.status != 502 || strings.Contains(string(res.body), coldToken) ||
					strings.Contains(fmt.Sprint(res.header), coldToken) {
					t.Fatalf("the first request leaked the token or was not blocked: %+v", res)
				}
				evs := e.events(1)
				if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != tc.reason {
					t.Fatalf("events = %+v, want one deny/%s", evs, tc.reason)
				}
			})
		})
	}
}

// startEchoWSProxy runs a proxy in front of a WebSocket backend whose 101 carries
// respHeader, optionally with the MCP gateway on.
func startEchoWSProxy(t *testing.T, mcpOn bool, respHeader string) (*Proxy, *syncStore, []byte) {
	t.Helper()
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn := startWSBackend(t, caCert, caKey, &wsBackend{respHeader: respHeader})
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certFile, caCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	store := &syncStore{}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: "backend.test", Port: 443},
		}}),
		Secrets:          &fakes.FakeSecretProvider{Values: map[string]string{echoPlaceholder: echoTestValue}},
		PlaceholderNames: []string{echoPlaceholder},
		Analytics:        store,
		AgentID:          "agent",
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		CACertPath:       certFile,
		CAKeyPath:        keyFile,
	}
	if mcpOn {
		cfg.MCP = &scanningDecorator{inner: gateway.New(enforceMCPConfig(), scan.NewScanner(), nil)}
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	waitForAddr(t, p)
	p.dialTLS = dialBackend(backendLn)
	return p, store, caCertPEM
}

// A 101 whose headers carry the swapped value is refused with a 502 and a deny
// event, with the MCP gateway on (the WebSocket handoff path) and off.
func TestEchoGuard_WebSocket101HeaderEcho(t *testing.T) {
	for _, mcpOn := range []bool{true, false} {
		t.Run(fmt.Sprintf("mcp_%v", mcpOn), func(t *testing.T) {
			p, store, caPEM := startEchoWSProxy(t, mcpOn, "X-Echo: Bearer "+echoTestValue+"\r\n")
			conn := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caPEM)
			t.Cleanup(func() { _ = conn.Close() })
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: backend.test\r\nAuthorization: Bearer "+echoPlaceholder+"\r\n"+
				"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
			raw, _ := io.ReadAll(bufio.NewReader(conn))
			if !bytes.HasPrefix(raw, []byte("HTTP/1.1 502")) {
				t.Fatalf("want a 502, got %q", raw)
			}
			if lp := leakedPrefix(raw); lp != "" || bytes.Contains(raw, []byte(echoTestValue)) {
				t.Fatalf("the agent received the value: %q", raw)
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				for _, ev := range store.snapshot() {
					if ev.Decision == "deny" && ev.Reason == "secret_echo" {
						if strings.Contains(fmt.Sprintf("%+v", ev), echoTestValue) {
							t.Fatalf("event carries the value: %+v", ev)
						}
						return
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
			t.Fatalf("no deny/secret_echo event: %+v", store.snapshot())
		})
	}
}

// A clean 101 still upgrades with the MCP gateway on (the guard must not refuse it).
func TestEchoGuard_WebSocket101CleanStillUpgrades(t *testing.T) {
	p, _, caPEM := startEchoWSProxy(t, true, "X-Fine: yes\r\n")
	conn := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caPEM)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: backend.test\r\nAuthorization: Bearer "+echoPlaceholder+"\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 101") {
		t.Fatalf("status line = %q err %v, want 101", line, err)
	}
}

// A stream that ends right after a prefix of the value must not deliver it.
func TestEchoGuard_NeedlePrefixAtEOF(t *testing.T) {
	for _, n := range []int{4, 12} {
		prefix := echoTestValue[:n]
		t.Run(fmt.Sprintf("prefix_%d", n), func(t *testing.T) {
			eachProto(t, func(t *testing.T, h2 bool) {
				// Something already sent, then the stream ends on the prefix.
				e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = io.WriteString(w, "data: first\n\n")
					w.(http.Flusher).Flush()
					time.Sleep(20 * time.Millisecond)
					_, _ = io.WriteString(w, "token: Bearer "+prefix)
				}, nil)
				res := e.do(h2, echoReq(t, "GET", "/p", bearer(), ""))
				if res.err == nil {
					t.Fatalf("stream ended cleanly after a value prefix: %q", res.body)
				}
				if lp := leakedPrefix(res.body); lp != "" {
					t.Fatalf("delivered a value prefix (%s): %q", lp, res.body)
				}
				if !strings.Contains(string(res.body), "data: first") {
					t.Fatalf("the clean event was not delivered: %q", res.body)
				}
				evs := e.events(1)
				if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != "secret_echo" {
					t.Fatalf("events = %+v, want one deny/secret_echo", evs)
				}
			})
			eachProto(t, func(t *testing.T, h2 bool) {
				// Nothing sent yet: the whole (short, known-length) body is the prefix.
				e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = io.WriteString(w, "Bearer "+prefix)
				}, nil)
				requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/p", bearer(), "")), "secret_echo")
			})
		})
	}
}

func TestEchoGuard_CleanTailAtEOFStillDelivered(t *testing.T) {
	for _, tail := range []string{"all done zzzz", "ends in AKI", "ends in AKIX"} {
		eachProto(t, func(t *testing.T, h2 bool) {
			e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "data: first\n\n")
				w.(http.Flusher).Flush()
				time.Sleep(20 * time.Millisecond)
				_, _ = io.WriteString(w, tail)
			}, nil)
			res := e.do(h2, echoReq(t, "GET", "/c", bearer(), ""))
			if res.err != nil || res.status != 200 || string(res.body) != "data: first\n\n"+tail {
				t.Fatalf("tail %q: %+v", tail, res)
			}
		})
	}
}

// A known-length uncompressed body of any size is streamed through the guard.
func TestEchoGuard_LargeKnownLengthBodyStreamed(t *testing.T) {
	const size = 3 << 19 // 1.5 MiB, over the 1 MiB default cap
	chunk := strings.Repeat("0123456789abcdef", 1024)
	body := func(echoAt int) []byte {
		b := bytes.Repeat([]byte(chunk), size/len(chunk))
		if echoAt >= 0 {
			copy(b[echoAt:], echoTestValue)
		}
		return b
	}
	serve := func(b []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprint(len(b)))
			_, _ = w.Write(b)
		}
	}
	t.Run("clean_intact", func(t *testing.T) {
		eachProto(t, func(t *testing.T, h2 bool) {
			want := body(-1)
			e := newEchoEnv(t, serve(want), nil)
			res := e.do(h2, echoReq(t, "GET", "/dl", bearer(), ""))
			if res.err != nil || res.status != 200 || !bytes.Equal(res.body, want) {
				t.Fatalf("status %d err %v len %d, want 200 intact %d", res.status, res.err, len(res.body), len(want))
			}
		})
	})
	t.Run("echo_at_1MiB_aborts", func(t *testing.T) {
		eachProto(t, func(t *testing.T, h2 bool) {
			e := newEchoEnv(t, serve(body(1<<20)), nil)
			res := e.do(h2, echoReq(t, "GET", "/dl", bearer(), ""))
			if res.err == nil {
				t.Fatalf("stream not aborted (%d bytes)", len(res.body))
			}
			if lp := leakedPrefix(res.body); lp != "" || bytes.Contains(res.body, []byte(echoTestValue)) {
				t.Fatalf("delivered value bytes (%s)", lp)
			}
			evs := e.events(1)
			if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != "secret_echo" {
				t.Fatalf("events = %+v, want one deny/secret_echo", evs)
			}
		})
	})
}

// A compressed body over the cap cannot be streamed-checked: still blocked.
func TestEchoGuard_CompressedOverCapBlockedUnscannable(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		noise := make([]byte, 4096)
		_, _ = rand.New(rand.NewSource(1)).Read(noise)
		gz := gzipBytes(string(noise))
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", fmt.Sprint(len(gz)))
			_, _ = w.Write(gz)
		}, func(c *Config) { c.ResponseScan = NewResponseScanner("monitor", 1024, false, false) })
		requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/big", bearer(), "")), "secret_echo_unscannable")
	})
}

// A zero-length read must return at once, not spin on the upstream.
func TestEchoReader_ZeroLengthReadReturns(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	r := newEchoReader(io.NopCloser(zeroReader{}), set, nil)
	done := make(chan struct{})
	go func() {
		n, err := r.Read(nil)
		if n != 0 || err != nil {
			t.Errorf("Read(nil) = %d, %v", n, err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Read with an empty buffer spun")
	}
}

type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) { return 0, nil }
