package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// leakedPrefix reports a prefix (4+ bytes) of the raw value or of any encoding
// that appears in got.
func leakedPrefix(got []byte) string {
	for name, enc := range encodingsOf(echoTestValue) {
		for k := 4; k <= len(enc); k++ {
			if bytes.Contains(got, []byte(enc[:k])) {
				return fmt.Sprintf("%s[:%d]=%q", name, k, enc[:k])
			}
		}
	}
	return ""
}

// The value split at every position over a real proxy: whatever the cut, the
// agent must not receive even the first bytes of it (#389 hold-back).
func TestEchoGuard_SplitAtEveryPositionDeliversNoValueBytes(t *testing.T) {
	eachProto(t, func(t *testing.T, h2 bool) {
		e := newEchoEnv(t, func(w http.ResponseWriter, r *http.Request) {
			k, _ := strconv.Atoi(r.URL.Query().Get("k"))
			f := w.(http.Flusher)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "pre-"+echoTestValue[:k])
			f.Flush()
			time.Sleep(15 * time.Millisecond)
			_, _ = io.WriteString(w, echoTestValue[k:]+"-post")
			f.Flush()
		}, nil)
		for k := 1; k < len(echoTestValue); k++ {
			res := e.do(h2, echoReq(t, "GET", fmt.Sprintf("/s?k=%d", k), bearer(), ""))
			if res.err == nil {
				t.Fatalf("split %d: stream not aborted: %q", k, res.body)
			}
			if lp := leakedPrefix(res.body); lp != "" {
				t.Fatalf("split %d: the agent received part of the value (%s): %q", k, lp, res.body)
			}
		}
	})
}

// Every encoding, split at every position, straight through the reader.
func TestEchoReader_NoNeedleBytesReleasedAtAnySplit(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	for name, enc := range encodingsOf(echoTestValue) {
		for k := 1; k < len(enc); k++ {
			src := strings.Repeat("a", 50) + enc + strings.Repeat("b", 50)
			cut := 50 + k
			r := newEchoReader(io.NopCloser(io.MultiReader(strings.NewReader(src[:cut]), strings.NewReader(src[cut:]))), set, nil)
			got, err := io.ReadAll(r)
			if err != errEchoBlocked {
				t.Fatalf("%s split %d: err = %v, want errEchoBlocked", name, k, err)
			}
			if lp := leakedPrefix(got); lp != "" {
				t.Fatalf("%s split %d: released %s", name, k, lp)
			}
		}
	}
}

// A clean stream is released in full, held tail included, at EOF.
func TestEchoReader_ReleasesHeldTailAtCleanEOF(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	for _, src := range []string{"x", "short", strings.Repeat("clean ", 100)} {
		r := newEchoReader(io.NopCloser(strings.NewReader(src)), set, nil)
		got, err := io.ReadAll(r)
		if err != nil || string(got) != src {
			t.Fatalf("src %q: got %q err %v", src[:min(len(src), 10)], got, err)
		}
	}
}

// Monitor mode keeps passing bytes after a hit, the held tail included.
func TestEchoReader_MonitorReleasesEverything(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	src := "head " + echoTestValue + " tail"
	r := newEchoReader(io.NopCloser(oneByteReader{strings.NewReader(src)}), set, nil)
	r.monitor = true
	got, err := io.ReadAll(r)
	if err != nil || string(got) != src || !r.hit {
		t.Fatalf("monitor: got %q err %v hit %v", got, err, r.hit)
	}
}
