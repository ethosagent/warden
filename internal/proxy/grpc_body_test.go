package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/denyreason"
)

const grpcBodyPH = "PLACEHOLDER_001"

// grpcBodyProxy starts the edge proxy with the placeholder configured and a gRPC
// backend; maxFrame (when >0) lowers the inspection bound.
func grpcBodyProxy(t *testing.T, scopes map[string][]string, maxFrame int) (*Proxy, *syncStore, *parityBackend, []byte) {
	t.Helper()
	be := newParityBackend(t, "application/grpc", "resp")
	p, store, caPEM := startEdgeProxy(t, be, func(c *Config) { paritySwap(scopes)(t, c) })
	p.grpcMaxFrame = maxFrame
	return p, store, be, caPEM
}

func grpcCall(t *testing.T, p *Proxy, caPEM []byte, body io.Reader, auth string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://"+parityHost+"/pkg.Svc/Call", body)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := dialGRPCClient(t, p.Addr().String(), parityHost, caPEM).RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

func grpcStatusOf(resp *http.Response) string {
	if v := resp.Trailer.Get("Grpc-Status"); v != "" {
		return v
	}
	return resp.Header.Get("Grpc-Status")
}

func TestGRPCBody_PlaceholderRefusedAndNeverForwarded(t *testing.T) {
	p, store, be, caPEM := grpcBodyProxy(t, nil, 0)
	tr := NewInflight()
	p.cfg.Inflight = tr

	resp := grpcCall(t, p, caPEM, bytes.NewReader(testFrame(0, []byte("token="+grpcBodyPH))), "Bearer "+grpcBodyPH)
	if resp.StatusCode != http.StatusOK || grpcStatusOf(resp) != "7" {
		t.Fatalf("status %d grpc-status %q, want 200 + PERMISSION_DENIED(7)", resp.StatusCode, grpcStatusOf(resp))
	}
	if m := resp.Header.Get("Grpc-Message"); m != "secret placeholders must be sent in gRPC metadata" {
		t.Fatalf("grpc-message = %q", m)
	}
	waitTrackerDrained(t, tr)
	evs := store.snapshot()
	requireSingleDeny(t, evs, string(denyreason.GRPCBodyPlaceholder))
	if evs[0].Protocol != "grpc" {
		t.Fatalf("protocol = %q, want grpc", evs[0].Protocol)
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	for _, g := range be.got {
		if strings.Contains(g.Body, grpcBodyPH) || strings.Contains(g.Body, "real-secret-value") {
			t.Fatalf("the refused message reached the upstream: %q", g.Body)
		}
	}
}

func TestGRPCBody_MetadataStillSwappedCleanBodyVerbatim(t *testing.T) {
	p, store, be, caPEM := grpcBodyProxy(t, nil, 0)
	body := append(testFrame(0, []byte("hello")), testFrame(0, nil)...)
	resp := grpcCall(t, p, caPEM, bytes.NewReader(body), "Bearer "+grpcBodyPH)
	if grpcStatusOf(resp) != "0" {
		t.Fatalf("grpc-status %q, want 0", grpcStatusOf(resp))
	}
	evs := waitEvents(t, store, 1)
	if len(evs) != 1 || evs[0].Decision != "allow" {
		t.Fatalf("events = %+v, want one allow", evs)
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.got) != 1 || be.got[0].Auth != "Bearer real-secret-value" || be.got[0].Body != string(body) {
		t.Fatalf("upstream got %+v, want the swapped metadata and the body verbatim", be.got)
	}
}

func TestGRPCBody_FailClosedShapes(t *testing.T) {
	cases := []struct {
		name   string
		body   []byte
		reason denyreason.Reason
		status string
	}{
		{"oversize", testFrame(0, bytes.Repeat([]byte("x"), 65)), denyreason.GRPCFrameTooLarge, "8"},
		{"compressed", testFrame(1, []byte("x")), denyreason.GRPCFrameCompressed, "9"},
		{"truncated", testFrame(0, []byte("hello"))[:7], denyreason.GRPCFrameMalformed, "3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, store, be, caPEM := grpcBodyProxy(t, nil, 64)
			resp := grpcCall(t, p, caPEM, bytes.NewReader(tc.body), "")
			if grpcStatusOf(resp) != tc.status {
				t.Fatalf("grpc-status %q, want %s", grpcStatusOf(resp), tc.status)
			}
			requireSingleDeny(t, waitEvents(t, store, 1), string(tc.reason))
			be.mu.Lock()
			defer be.mu.Unlock()
			for _, g := range be.got {
				if g.Body != "" {
					t.Fatalf("a refused body reached the upstream: %q", g.Body)
				}
			}
		})
	}
}

// A client-streaming call: the clean message goes through, the one carrying the
// placeholder is held back, and the stream records exactly one (deny) event.
func TestGRPCBody_StreamRefusedMidway(t *testing.T) {
	p, store, be, caPEM := grpcBodyProxy(t, nil, 0)
	tr := NewInflight()
	p.cfg.Inflight = tr
	first := testFrame(0, []byte("first"))
	body := io.MultiReader(bytes.NewReader(first), bytes.NewReader(testFrame(0, []byte(grpcBodyPH))))
	_ = grpcCall(t, p, caPEM, struct{ io.Reader }{body}, "")
	waitTrackerDrained(t, tr)
	requireSingleDeny(t, waitEvents(t, store, 1), string(denyreason.GRPCBodyPlaceholder))
	be.mu.Lock()
	defer be.mu.Unlock()
	for _, g := range be.got {
		if strings.Contains(g.Body, grpcBodyPH) {
			t.Fatalf("the refused message reached the upstream: %q", g.Body)
		}
	}
}

// A placeholder scoped to another host is not one the swap would act on for this
// destination, so the message is relayed (as the h1 path leaves it): the guard
// refuses only what the swap's own scoping calls in scope.
func TestGRPCBody_OutOfScopePlaceholderNotRefused(t *testing.T) {
	p, store, _, caPEM := grpcBodyProxy(t, map[string][]string{grpcBodyPH: {"other.example.com"}}, 0)
	resp := grpcCall(t, p, caPEM, bytes.NewReader(testFrame(0, []byte(grpcBodyPH))), "")
	if grpcStatusOf(resp) != "0" {
		t.Fatalf("grpc-status %q, want 0", grpcStatusOf(resp))
	}
	for _, e := range waitEvents(t, store, 1) {
		if e.Decision == "deny" && strings.HasPrefix(e.Reason, "grpc_") {
			t.Fatalf("out-of-scope placeholder refused: %+v", e)
		}
	}
}

// The body guard's deny rides the one chokepoint like the h1 path's denies: the
// declared reason is on the event AND on the blocked metric, once.
func TestGRPCBody_DenyParityWithChokepoint(t *testing.T) {
	p, store, _, caPEM := grpcBodyProxy(t, nil, 0)
	metrics := &recordingMetrics{}
	p.cfg.Metrics = metrics
	_ = grpcCall(t, p, caPEM, bytes.NewReader(testFrame(0, []byte(grpcBodyPH))), "")
	denies := waitDenies(t, store, 1)
	requireDeclaredDeny(t, denies[0], string(denyreason.GRPCBodyPlaceholder), metrics)
}

// A bidi call whose response already started when the offending message arrives:
// the stream ends with the refusal status as trailers, the offending message
// never reaches the upstream, and the only event is the deny (no allow).
func TestGRPCBody_RefusedAfterResponseStarted(t *testing.T) {
	var (
		mu  sync.Mutex
		got []byte
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(testFrame(0, nil)) // a first response message: the relay flushes the headers with it
		w.(http.Flusher).Flush()          // the response starts before the request body is read
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = b
		mu.Unlock()
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	be := &parityBackend{srv: srv}
	p, store, caPEM := startEdgeProxy(t, be, func(c *Config) { paritySwap(nil)(t, c) })

	first := testFrame(0, []byte("first"))
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", "https://"+parityHost+"/pkg.Svc/Bidi", pr)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := dialGRPCClient(t, p.Addr().String(), parityHost, caPEM).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Write(first)
	_, _ = pw.Write(testFrame(0, []byte(grpcBodyPH)))
	_ = pw.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if st := grpcStatusOf(resp); st != "7" {
		t.Fatalf("grpc-status %q, want 7 as a trailer", st)
	}
	requireSingleDeny(t, waitEvents(t, store, 1), string(denyreason.GRPCBodyPlaceholder))
	time.Sleep(100 * time.Millisecond)
	requireSingleDeny(t, store.snapshot(), string(denyreason.GRPCBodyPlaceholder))
	mu.Lock()
	defer mu.Unlock()
	if bytes.Contains(got, []byte(grpcBodyPH)) {
		t.Fatalf("the refused message reached the upstream: %q", got)
	}
}

// A first message that arrives after the hold-back window: the request has gone
// upstream by then, but the message is still inspected and refused.
func TestGRPCBody_LateFirstMessageStillRefused(t *testing.T) {
	p, store, be, caPEM := grpcBodyProxy(t, nil, 0)
	pr, pw := io.Pipe()
	go func() {
		time.Sleep(grpcFirstFrameWait + 150*time.Millisecond)
		_, _ = pw.Write(testFrame(0, []byte(grpcBodyPH)))
		_ = pw.Close()
	}()
	_ = grpcCall(t, p, caPEM, pr, "")
	requireSingleDeny(t, waitEvents(t, store, 1), string(denyreason.GRPCBodyPlaceholder))
	be.mu.Lock()
	defer be.mu.Unlock()
	for _, g := range be.got {
		if strings.Contains(g.Body, grpcBodyPH) {
			t.Fatalf("the refused message reached the upstream: %q", g.Body)
		}
	}
}
