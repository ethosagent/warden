package proxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// chunkReader returns one scripted chunk per Read.
type chunkReader struct{ chunks []string }

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	if c.chunks[0] == "" {
		c.chunks = c.chunks[1:]
	}
	return n, nil
}

// Only the bytes that could still become a needle are held; a chunk that ends in
// something that is no needle prefix is released whole (#389 latency).
func TestEchoReader_ReleasesAllButNeedlePrefix(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	prefix := base64.StdEncoding.EncodeToString([]byte(echoTestValue))[:5]
	r := newEchoReader(io.NopCloser(&chunkReader{chunks: []string{
		"data: {\"x\":1}\n\n",
		"data: " + prefix,
		"ok\n\n",
	}}), set, nil)
	buf := make([]byte, 4096)
	read := func() string {
		n, err := r.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return string(buf[:n])
	}
	if got := read(); got != "data: {\"x\":1}\n\n" {
		t.Fatalf("clean event held or altered: %q", got)
	}
	if got := read(); got != "data: " {
		t.Fatalf("released %q, want everything but the %q prefix", got, prefix)
	}
	if string(r.hold) != prefix {
		t.Fatalf("held %q, want %q", r.hold, prefix)
	}
	if got := read(); got != prefix+"ok\n\n" {
		t.Fatalf("held prefix not released with the next clean chunk: %q", got)
	}
	if len(r.hold) != 0 {
		t.Fatalf("still holding %q", r.hold)
	}
}

func TestEchoSet_HeldSuffix(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	for in, want := range map[string]int{
		"":                        0,
		"data: x\n\n":             0,
		"abc" + echoTestValue[:6]: 6,
		echoTestValue[:1]:         1,
		"zz" + echoTestValue[:len(echoTestValue)-1]: len(echoTestValue) - 1,
	} {
		if got := set.heldSuffix([]byte(in)); got != want {
			t.Errorf("heldSuffix(%q) = %d, want %d", in, got, want)
		}
	}
}

// A streaming upstream: the agent gets each SSE event before the next is sent,
// not one event late and not at the end.
func TestEchoGuard_SSEEventsNotHeldBack(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		// Different lengths: no fixed hold-back window can release all of them.
		events := []string{"data: {\"x\":1}\n\n", "data: 2\n\n", "data: {\"y\":\"abc\"}\n\n"}
		gates := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}
		var stalled atomic.Bool
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			f := w.(http.Flusher)
			w.Header().Set("Content-Type", "text/event-stream")
			for i, g := range gates {
				_, _ = io.WriteString(w, events[i])
				f.Flush()
				select {
				case <-g: // the agent has this event; send the next
				case <-time.After(5 * time.Second):
					stalled.Store(true)
					return
				}
			}
		}, nil)
		resp := e.open(h2, echoReq(t, "GET", "/sse", bearer(), ""))
		defer func() { _ = resp.Body.Close() }()
		for i, g := range gates {
			event := events[i]
			buf := make([]byte, len(event))
			if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != event {
				t.Fatalf("event %d: got %q err %v (stalled=%v)", i+1, buf, err, stalled.Load())
			}
			close(g)
		}
		if stalled.Load() {
			t.Fatal("the agent received an event only after the upstream gave up waiting")
		}
	})
}

func (e *echoEnv) open(h2 bool, req *http.Request) *http.Response {
	e.t.Helper()
	var resp *http.Response
	var err error
	if h2 {
		resp, err = dialGRPCClient(e.t, e.p.Addr().String(), echoHost, e.caPEM).RoundTrip(req)
	} else {
		c := dialProxyAndConnect(e.t, e.p.Addr().String(), echoHost, e.caPEM)
		e.t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		if err = req.Write(c); err == nil {
			resp, err = http.ReadResponse(bufio.NewReader(c), req)
		}
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

// A response with a Content-Length is streamed, not buffered to its end: the
// first chunk reaches the agent while the upstream is still sending.
func TestEchoGuard_KnownLengthBodyNotHeldToEnd(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		gate := make(chan struct{})
		var stalled atomic.Bool
		e := newEchoEnv(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "6")
			_, _ = io.WriteString(w, "***")
			w.(http.Flusher).Flush()
			select {
			case <-gate:
			case <-time.After(5 * time.Second):
				stalled.Store(true)
			}
			_, _ = io.WriteString(w, "***")
		}, nil)
		resp := e.open(h2, echoReq(t, "GET", "/drip", bearer(), ""))
		defer func() { _ = resp.Body.Close() }()
		buf := make([]byte, 3)
		if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "***" {
			t.Fatalf("first chunk: %q err %v", buf, err)
		}
		close(gate)
		rest, _ := io.ReadAll(resp.Body)
		if stalled.Load() || string(rest) != "***" {
			t.Fatalf("stalled=%v rest=%q", stalled.Load(), rest)
		}
	})
}
