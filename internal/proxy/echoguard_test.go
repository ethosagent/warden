package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

const (
	echoHost        = "echo.test"
	echoPlaceholder = "rt_canary_secret_001"
)

// echoEnv is a proxy in front of a recording TLS backend that speaks h1 and h2.
type echoEnv struct {
	t       *testing.T
	p       *Proxy
	store   *syncStore
	caPEM   []byte
	mu      sync.Mutex
	upstrAE []string // Accept-Encoding the backend received, per request
}

func newEchoEnv(t *testing.T, handler http.HandlerFunc, mutate func(*Config)) *echoEnv {
	t.Helper()
	e := &echoEnv{t: t, store: &syncStore{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.upstrAE = append(e.upstrAE, r.Header.Get("Accept-Encoding"))
		e.mu.Unlock()
		handler(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	backendAddr := strings.TrimPrefix(srv.URL, "https://")

	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	e.caPEM = caCertPEM
	dir := t.TempDir()
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: echoHost, Port: 443},
		}}),
		Secrets:          &fakes.FakeSecretProvider{Values: map[string]string{echoPlaceholder: echoTestValue}},
		PlaceholderNames: []string{echoPlaceholder},
		Analytics:        e.store,
		AgentID:          "agent",
		CACertPath:       filepath.Join(dir, "ca.crt"),
		CAKeyPath:        filepath.Join(dir, "ca.key"),
	}
	if err := os.WriteFile(cfg.CACertPath, caCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.CAKeyPath, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 200 && p.Addr() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy did not start")
	}
	p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
	}
	e.p = p
	return e
}

type echoResult struct {
	status  int
	header  http.Header
	trailer http.Header
	body    []byte
	err     error // round-trip error, or the body read error (stream aborted)
}

// do sends req through the proxy over h1 or h2 and reads the whole response.
func (e *echoEnv) do(h2 bool, req *http.Request) echoResult {
	e.t.Helper()
	var resp *http.Response
	var err error
	if h2 {
		resp, err = dialGRPCClient(e.t, e.p.Addr().String(), echoHost, e.caPEM).RoundTrip(req)
	} else {
		c := dialProxyAndConnect(e.t, e.p.Addr().String(), echoHost, e.caPEM)
		e.t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if err = req.Write(c); err == nil {
			resp, err = http.ReadResponse(bufio.NewReader(c), req)
		}
	}
	if err != nil {
		return echoResult{err: err}
	}
	body, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return echoResult{status: resp.StatusCode, header: resp.Header, trailer: resp.Trailer, body: body, err: rerr}
}

func echoReq(t *testing.T, method, path string, hdr map[string]string, body string) *http.Request {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+echoHost+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.ContentLength = int64(len(body))
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

func bearer() map[string]string {
	return map[string]string{"Authorization": "Bearer " + echoPlaceholder}
}

// events waits for n events and returns them.
func (e *echoEnv) events(n int) []analytics.Event {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.store.snapshot()) < n && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let a surplus event show up
	return e.store.snapshot()
}

func (e *echoEnv) assertNoValueInEvents() {
	e.t.Helper()
	for _, ev := range e.store.snapshot() {
		dump := fmt.Sprintf("%+v", ev)
		for name, enc := range encodingsOf(echoTestValue) {
			if strings.Contains(dump, enc) {
				e.t.Errorf("event carries the secret (%s form): %s", name, dump)
			}
		}
	}
}

// echoHeaderHandler reflects the Authorization header in a response header and body.
func echoHeaderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Echo", r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "ok")
}

func echoBodyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"headers":{"Authorization":%q}}`, r.Header.Get("Authorization"))
}

func eachProto(t *testing.T, f func(t *testing.T, h2 bool)) {
	t.Helper()
	for _, h2 := range []bool{false, true} {
		name := "h1"
		if h2 {
			name = "h2"
		}
		t.Run(name, func(t *testing.T) { f(t, h2) })
	}
}

func requireBlocked(t *testing.T, e *echoEnv, res echoResult, reason string) {
	t.Helper()
	if res.err != nil {
		t.Fatalf("round trip: %v", res.err)
	}
	if res.status != 502 {
		t.Fatalf("status = %d, want 502 (body %q)", res.status, res.body)
	}
	for _, enc := range encodingsOf(echoTestValue) {
		if bytes.Contains(res.body, []byte(enc)) || strings.Contains(fmt.Sprint(res.header), enc) {
			t.Fatalf("the agent received the secret: %q %v", res.body, res.header)
		}
	}
	evs := e.events(1)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want exactly 1: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Decision != "deny" || ev.Reason != reason {
		t.Fatalf("event = %s/%s, want deny/%s", ev.Decision, ev.Reason, reason)
	}
	if len(ev.SwappedRefs) != 1 || ev.SwappedRefs[0] != echoPlaceholder {
		t.Fatalf("SwappedRefs = %v, want the placeholder name", ev.SwappedRefs)
	}
	if !strings.Contains(ev.SecretRef, "last4:"+echoTestValue[len(echoTestValue)-4:]) {
		t.Fatalf("SecretRef = %q, want a by-reference description", ev.SecretRef)
	}
	e.assertNoValueInEvents()
}

func TestEchoGuard_HeaderEcho(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, echoHeaderHandler, nil)
		requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/headers", bearer(), "")), "secret_echo")
	})
}

func TestEchoGuard_BodyEcho(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, echoBodyHandler, nil)
		requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/headers", bearer(), "")), "secret_echo")
	})
}

func TestEchoGuard_QueryAndBodySwapEcho(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(append([]byte(r.URL.RawQuery+"|"), b...))
		}, nil)
		requireBlocked(t, e, e.do(h2, echoReq(t, "POST", "/x?k="+echoPlaceholder, nil, "payload "+echoPlaceholder)), "secret_echo")
	})
}

func TestEchoGuard_BasicAuthEcho(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, echoBodyHandler, nil)
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:"+echoPlaceholder))
		requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/h", map[string]string{"Authorization": basic}, "")), "secret_echo")
	})
}

func TestEchoGuard_EachEncodingInBody(t *testing.T) {
	for name, enc := range encodingsOf(echoTestValue) {
		t.Run(name, func(t *testing.T) {
			eachProto(t, func(t *testing.T, h2 bool) {
				e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = io.WriteString(w, "before "+enc+" after")
				}, nil)
				requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/e", bearer(), "")), "secret_echo")
			})
		})
	}
}

func TestEchoGuard_TransformerSecretEcho(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		inj, err := auth.NewAPIKeyInjector("header", "X-Api-Key", echoTestValue)
		if err != nil {
			t.Fatal(err)
		}
		mt, err := auth.NewMatchedTransformer(echoHost, inj)
		if err != nil {
			t.Fatal(err)
		}
		e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, r.Header.Get("X-Api-Key"))
		}, func(c *Config) {
			c.Transformers = []*auth.MatchedTransformer{mt}
			c.PlaceholderNames = nil
		})
		res := e.do(h2, echoReq(t, "GET", "/t", nil, ""))
		if res.err != nil || res.status != 502 || bytes.Contains(res.body, []byte(echoTestValue)) {
			t.Fatalf("transformer-injected secret reached the agent: %+v", res)
		}
		evs := e.events(1)
		if len(evs) != 1 || evs[0].Reason != "secret_echo" || evs[0].Decision != "deny" {
			t.Fatalf("events = %+v", evs)
		}
		e.assertNoValueInEvents()
	})
}

func TestEchoGuard_NoSwapRequestUnchanged(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write([]byte("compressed hello"))
		_ = zw.Close()
		e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
			// An echo of an ordinary header is fine without a swap.
			w.Header().Set("X-Echo", r.Header.Get("X-Custom"))
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(gz.Bytes())
		}, nil)
		res := e.do(h2, echoReq(t, "GET", "/h", map[string]string{"X-Custom": echoTestValue, "Accept-Encoding": "gzip, br"}, ""))
		if res.err != nil || res.status != 200 {
			t.Fatalf("no-swap request changed: %+v", res)
		}
		if !bytes.Equal(res.body, gz.Bytes()) {
			t.Fatal("no-swap response body was altered")
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if len(e.upstrAE) != 1 || e.upstrAE[0] != "gzip, br" {
			t.Fatalf("Accept-Encoding upstream = %q, want the client's untouched", e.upstrAE)
		}
		evs := e.store.snapshot()
		_ = evs
	})
}

func TestEchoGuard_CleanSwappedResponsePassesAndForcesIdentity(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "all good")
		}, nil)
		h := bearer()
		h["Accept-Encoding"] = "gzip, br"
		res := e.do(h2, echoReq(t, "GET", "/h", h, ""))
		if res.err != nil || res.status != 200 || string(res.body) != "all good" {
			t.Fatalf("clean response not relayed: %+v", res)
		}
		e.mu.Lock()
		ae := append([]string(nil), e.upstrAE...)
		e.mu.Unlock()
		if len(ae) != 1 || ae[0] != "identity" {
			t.Fatalf("upstream Accept-Encoding = %q, want identity", ae)
		}
		evs := e.events(1)
		if len(evs) != 1 || evs[0].Decision != "allow" {
			t.Fatalf("events = %+v, want one allow", evs)
		}
	})
}

func gzipBytes(s string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return b.Bytes()
}

func TestEchoGuard_GzipEchoBlocked(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(gzipBytes(`{"a":"` + r.Header.Get("Authorization") + `"}`))
		}, nil)
		requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/g", bearer(), "")), "secret_echo")
	})
}

func TestEchoGuard_GzipCleanPassesCompressed(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		payload := gzipBytes(`{"ok":true}`)
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(payload)
		}, nil)
		h := bearer()
		h["Accept-Encoding"] = "gzip" // an explicit value stops the client transport decoding for us
		res := e.do(h2, echoReq(t, "GET", "/g", h, ""))
		if res.err != nil || res.status != 200 || !bytes.Equal(res.body, payload) {
			t.Fatalf("clean gzip response was altered: %+v", res)
		}
	})
}

func TestEchoGuard_BrotliUnscannableBlocked(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "br")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "opaque-bytes")
		}, nil)
		requireBlocked(t, e, e.do(h2, echoReq(t, "GET", "/b", bearer(), "")), "secret_echo_unscannable")
	})
}

func TestEchoGuard_StreamingSplitValueAborts(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		half := len(echoTestValue) / 2
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			f := w.(http.Flusher)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "chunk-one "+echoTestValue[:half])
			f.Flush()
			time.Sleep(50 * time.Millisecond)
			_, _ = io.WriteString(w, echoTestValue[half:]+" chunk-two")
			f.Flush()
		}, nil)
		res := e.do(h2, echoReq(t, "GET", "/s", bearer(), ""))
		if res.err == nil {
			t.Fatalf("stream was not aborted: status %d body %q", res.status, res.body)
		}
		if bytes.Contains(res.body, []byte(echoTestValue)) || bytes.Contains(res.body, []byte("chunk-two")) {
			t.Fatalf("the agent received the withheld chunk: %q", res.body)
		}
		evs := e.events(1)
		if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != "secret_echo" {
			t.Fatalf("events = %+v, want one deny/secret_echo", evs)
		}
		e.assertNoValueInEvents()
	})
}

func TestEchoGuard_SSEAbortsMidStream(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
			f := w.(http.Flusher)
			w.Header().Set("Content-Type", "text/event-stream")
			for i, line := range []string{"one", "two", "echo " + r.Header.Get("Authorization"), "four"} {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", line)
				f.Flush()
				if i < 3 {
					time.Sleep(30 * time.Millisecond)
				}
			}
		}, nil)
		res := e.do(h2, echoReq(t, "GET", "/sse", bearer(), ""))
		if res.err == nil {
			t.Fatalf("SSE stream not aborted: %q", res.body)
		}
		got := string(res.body)
		if !strings.Contains(got, "data: one") || !strings.Contains(got, "data: two") {
			t.Fatalf("events before the hit were not delivered: %q", got)
		}
		if strings.Contains(got, echoTestValue) || strings.Contains(got, "four") {
			t.Fatalf("hit event or later data delivered: %q", got)
		}
		evs := e.events(1)
		if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != "secret_echo" {
			t.Fatalf("events = %+v", evs)
		}
	})
}

func grpcFrame(payload string) []byte {
	b := []byte{0, 0, 0, 0, byte(len(payload))}
	return append(b, payload...)
}

func TestEchoGuard_GRPCUnaryAndStream(t *testing.T) {
	hdr := map[string]string{"Content-Type": "application/grpc", "Authorization": "Bearer " + echoPlaceholder, "Te": "trailers"}
	t.Run("unary_echo_blocked", func(t *testing.T) {
		e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			_, _ = w.Write(grpcFrame(r.Header.Get("Authorization")))
			w.Header().Set("Grpc-Status", "0")
		}, nil)
		res := e.do(true, echoReq(t, "POST", "/pkg.Svc/Get", hdr, string(grpcFrame("req"))))
		if res.err == nil && res.status == 200 && bytes.Contains(res.body, []byte(echoTestValue)) {
			t.Fatalf("gRPC unary response leaked the secret: %q", res.body)
		}
		if bytes.Contains(res.body, []byte(echoTestValue)) {
			t.Fatalf("secret reached the agent: %q", res.body)
		}
		evs := e.events(1)
		if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != "secret_echo" {
			t.Fatalf("events = %+v", evs)
		}
	})
	t.Run("unary_clean_keeps_trailers", func(t *testing.T) {
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			_, _ = w.Write(grpcFrame("fine"))
			w.Header().Set("Grpc-Status", "0")
		}, nil)
		req := echoReq(t, "POST", "/pkg.Svc/Get", hdr, string(grpcFrame("req")))
		resp, err := dialGRPCClient(t, e.p.Addr().String(), echoHost, e.caPEM).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		if !bytes.Contains(body, []byte("fine")) || resp.Trailer.Get("Grpc-Status") != "0" {
			t.Fatalf("clean gRPC response altered: body %q trailer %v", body, resp.Trailer)
		}
	})
	t.Run("stream_echo_aborted", func(t *testing.T) {
		e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
			f := w.(http.Flusher)
			w.Header().Set("Content-Type", "application/grpc")
			_, _ = w.Write(grpcFrame("msg-1"))
			f.Flush()
			time.Sleep(30 * time.Millisecond)
			_, _ = w.Write(grpcFrame("msg-2 " + r.Header.Get("Authorization")))
			f.Flush()
		}, nil)
		res := e.do(true, echoReq(t, "POST", "/pkg.Svc/Watch", hdr, string(grpcFrame("req"))))
		if res.err == nil {
			t.Fatalf("gRPC stream not aborted: %q", res.body)
		}
		if bytes.Contains(res.body, []byte(echoTestValue)) || !bytes.Contains(res.body, []byte("msg-1")) {
			t.Fatalf("body = %q", res.body)
		}
		evs := e.events(1)
		if len(evs) != 1 || evs[0].Reason != "secret_echo" {
			t.Fatalf("events = %+v", evs)
		}
	})
}

func TestEchoGuard_DisabledForwardsUnchanged(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, echoBodyHandler, func(c *Config) { c.EchoGuard = EchoGuardConfig{Disabled: true} })
		res := e.do(h2, echoReq(t, "GET", "/h", bearer(), ""))
		if res.err != nil || res.status != 200 || !bytes.Contains(res.body, []byte(echoTestValue)) {
			t.Fatalf("disabled guard must forward unchanged: %+v", res)
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.upstrAE[0] == "identity" {
			t.Fatal("disabled guard must not touch Accept-Encoding")
		}
	})
}

func TestEchoGuard_MonitorRecordsButForwards(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, echoBodyHandler, func(c *Config) { c.EchoGuard = EchoGuardConfig{Monitor: true} })
		res := e.do(h2, echoReq(t, "GET", "/h", bearer(), ""))
		if res.err != nil || res.status != 200 {
			t.Fatalf("monitor must forward: %+v", res)
		}
		evs := e.events(1)
		if len(evs) != 1 || evs[0].Decision != "allow" || evs[0].Reason != "secret_echo" {
			t.Fatalf("events = %+v, want one allow/secret_echo", evs)
		}
		e.assertNoValueInEvents()
	})
}
