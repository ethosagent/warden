package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/ethosagent/warden/internal/denyreason"
)

func testFrame(flag byte, payload []byte) []byte {
	f := make([]byte, grpcFrameHeaderLen+len(payload))
	f[0] = flag
	binary.BigEndian.PutUint32(f[1:5], uint32(len(payload)))
	copy(f[5:], payload)
	return f
}

func newTestGuard(src io.Reader, max int) (*grpcFrameGuard, *[]grpcRefusal) {
	var got []grpcRefusal
	g := newGRPCFrameGuard(io.NopCloser(src), [][]byte{[]byte("{{openai}}")}, max, func(r grpcRefusal) { got = append(got, r) })
	return g, &got
}

func TestGRPCFrameGuard_CleanFramesPassThroughVerbatim(t *testing.T) {
	in := append(append(testFrame(0, []byte("hello")), testFrame(0, nil)...), testFrame(0, []byte("world"))...)
	g, got := newTestGuard(bytes.NewReader(in), 1024)
	out, err := io.ReadAll(g)
	if err != nil || !bytes.Equal(out, in) {
		t.Fatalf("out=%q err=%v, want the input verbatim", out, err)
	}
	if len(*got) != 0 || g.Refused() {
		t.Fatalf("unexpected refusal: %+v", *got)
	}
}

func TestGRPCFrameGuard_ManySmallFrames(t *testing.T) {
	var in []byte
	for i := 0; i < 500; i++ {
		in = append(in, testFrame(0, []byte{byte(i)})...)
	}
	g, _ := newTestGuard(iotest.OneByteReader(bytes.NewReader(in)), 1024)
	out, err := io.ReadAll(g)
	if err != nil || !bytes.Equal(out, in) {
		t.Fatalf("many small frames corrupted: err=%v len=%d want %d", err, len(out), len(in))
	}
}

func TestGRPCFrameGuard_EmptyBody(t *testing.T) {
	g, _ := newTestGuard(bytes.NewReader(nil), 1024)
	out, err := io.ReadAll(g)
	if err != nil || len(out) != 0 {
		t.Fatalf("out=%q err=%v, want empty and clean", out, err)
	}
}

func TestGRPCFrameGuard_Refusals(t *testing.T) {
	cases := []struct {
		name   string
		in     []byte
		max    int
		reason denyreason.Reason
		// clean is a frame that must still be forwarded before the refusal.
		clean []byte
	}{
		{"placeholder", testFrame(0, []byte("token={{openai}}")), 1024, denyreason.GRPCBodyPlaceholder, nil},
		{"placeholder after clean frame", testFrame(0, []byte("a{{openai}}")), 1024, denyreason.GRPCBodyPlaceholder, testFrame(0, []byte("ok"))},
		{"oversize", testFrame(0, bytes.Repeat([]byte("x"), 65)), 64, denyreason.GRPCFrameTooLarge, nil},
		{"oversize header only", []byte{0, 0xff, 0xff, 0xff, 0xff}, 64, denyreason.GRPCFrameTooLarge, nil},
		{"truncated header", []byte{0, 0, 0}, 1024, denyreason.GRPCFrameMalformed, nil},
		{"truncated payload", testFrame(0, []byte("hello"))[:8], 1024, denyreason.GRPCFrameMalformed, nil},
		{"bad flag", testFrame(2, []byte("x")), 1024, denyreason.GRPCFrameMalformed, nil},
		{"compressed", testFrame(1, []byte("x")), 1024, denyreason.GRPCFrameCompressed, nil},
		{"compressed empty", testFrame(1, nil), 1024, denyreason.GRPCFrameCompressed, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := append(append([]byte{}, tc.clean...), tc.in...)
			g, got := newTestGuard(bytes.NewReader(in), tc.max)
			out, err := io.ReadAll(g)
			if !errors.Is(err, errGRPCFrameRefused) {
				t.Fatalf("err = %v, want errGRPCFrameRefused", err)
			}
			if !bytes.Equal(out, tc.clean) {
				t.Fatalf("forwarded %q before the refusal, want exactly the clean frames %q", out, tc.clean)
			}
			if len(*got) != 1 || (*got)[0].reason != tc.reason {
				t.Fatalf("refusals = %+v, want exactly one %s", *got, tc.reason)
			}
			// Sticky: a later read neither forwards bytes nor refuses twice.
			if n, err := g.Read(make([]byte, 8)); n != 0 || !errors.Is(err, errGRPCFrameRefused) {
				t.Fatalf("read after refusal = %d, %v", n, err)
			}
			if len(*got) != 1 {
				t.Fatalf("refusal reported %d times, want once", len(*got))
			}
			if r, ok := g.Refusal(); !ok || r.reason != tc.reason {
				t.Fatalf("Refusal() = %+v, %v", r, ok)
			}
		})
	}
}

func TestGRPCFrameGuard_PlaceholderSplitByTransportChunks(t *testing.T) {
	// The transport may hand the frame over a byte at a time; the frame is
	// reassembled before inspection, so chunking cannot hide a placeholder.
	in := testFrame(0, []byte("token={{openai}}"))
	g, got := newTestGuard(iotest.OneByteReader(bytes.NewReader(in)), 1024)
	out, _ := io.ReadAll(g)
	if len(out) != 0 || len(*got) != 1 || (*got)[0].reason != denyreason.GRPCBodyPlaceholder {
		t.Fatalf("out=%q refusals=%+v, want the frame held and refused", out, *got)
	}
}

// A placeholder split across messages is caught at the boundary: the half that
// completes it is refused. The first half was already forwarded; it is inert,
// since a body is never swapped.
func TestGRPCFrameGuard_PlaceholderSplitAcrossFramesIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		frames [][]byte
		out    []byte // exactly what may be forwarded before the refusal
	}{
		{"two frames", [][]byte{[]byte("token={{open"), []byte("ai}}")}, testFrame(0, []byte("token={{open"))},
		{"one byte at the boundary", [][]byte{[]byte("{{openai}"), []byte("}")}, testFrame(0, []byte("{{openai}"))},
		{"three frames", [][]byte{[]byte("{{op"), []byte("en"), []byte("ai}}")}, append(testFrame(0, []byte("{{op")), testFrame(0, []byte("en"))...)},
		{"empty frame between", [][]byte{[]byte("{{open"), nil, []byte("ai}}")}, append(testFrame(0, []byte("{{open")), testFrame(0, nil)...)},
		{"long frames either side", [][]byte{append(bytes.Repeat([]byte("x"), 5000), "{{ope"...), append([]byte("nai}}"), bytes.Repeat([]byte("y"), 5000)...)}, testFrame(0, append(bytes.Repeat([]byte("x"), 5000), "{{ope"...))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var in []byte
			for _, f := range tc.frames {
				in = append(in, testFrame(0, f)...)
			}
			g, got := newTestGuard(bytes.NewReader(in), 8192)
			out, err := io.ReadAll(g)
			if !errors.Is(err, errGRPCFrameRefused) || len(*got) != 1 || (*got)[0].reason != denyreason.GRPCBodyPlaceholder {
				t.Fatalf("err=%v refusals=%+v, want one grpc_body_placeholder refusal", err, *got)
			}
			if !bytes.Equal(out, tc.out) {
				t.Fatalf("forwarded %q, want only the frames before the completing one: %q", out, tc.out)
			}
		})
	}
}

// Near misses are not refused: the tail is rolled, not accumulated forever.
func TestGRPCFrameGuard_NoFalseSplitRefusal(t *testing.T) {
	in := append(append(testFrame(0, []byte("{{open")), testFrame(0, []byte("xx}}"))...), testFrame(0, []byte("ai}}"))...)
	g, got := newTestGuard(bytes.NewReader(in), 1024)
	out, err := io.ReadAll(g)
	if err != nil || len(*got) != 0 || !bytes.Equal(out, in) {
		t.Fatalf("err=%v refusals=%+v, want a clean relay", err, *got)
	}
}

// Frames without a placeholder reach the reader as they arrive: the guard must
// not wait for the end of the stream.
func TestGRPCFrameGuard_StreamsFrameByFrame(t *testing.T) {
	pr, pw := io.Pipe()
	g, _ := newTestGuard(pr, 1024)
	first := testFrame(0, []byte("first"))
	go func() { _, _ = pw.Write(first) }()
	buf := make([]byte, len(first))
	if _, err := io.ReadFull(g, buf); err != nil || !bytes.Equal(buf, first) {
		t.Fatalf("first frame not delivered while the stream is open: %q %v", buf, err)
	}
	go func() { _, _ = pw.Write(testFrame(0, []byte("{{openai}}"))); _ = pw.Close() }()
	if n, err := g.Read(make([]byte, 64)); n != 0 || !errors.Is(err, errGRPCFrameRefused) {
		t.Fatalf("second frame: n=%d err=%v, want refusal with nothing forwarded", n, err)
	}
}

func TestGRPCFrameGuard_ReadErrorIsNotARefusal(t *testing.T) {
	boom := errors.New("client reset")
	g, got := newTestGuard(io.MultiReader(bytes.NewReader(testFrame(0, []byte("ab"))[:7]), iotest.ErrReader(boom)), 1024)
	_, err := io.ReadAll(g)
	if !errors.Is(err, boom) || len(*got) != 0 || g.Refused() {
		t.Fatalf("err=%v refusals=%+v, want the transport error passed through", err, *got)
	}
}

func TestGRPCRefusalStatus(t *testing.T) {
	for _, r := range []denyreason.Reason{denyreason.GRPCBodyPlaceholder, denyreason.GRPCFrameTooLarge, denyreason.GRPCFrameMalformed, denyreason.GRPCFrameCompressed} {
		ref := newGRPCRefusal(r)
		if !ref.reason.Declared() || ref.code == 0 || ref.message == "" {
			t.Errorf("%s: incomplete refusal %+v", r, ref)
		}
	}
	if m := newGRPCRefusal(denyreason.GRPCBodyPlaceholder).message; m != "secret placeholders must be sent in gRPC metadata" {
		t.Errorf("placeholder message = %q", m)
	}
}

func FuzzGRPCFrames(f *testing.F) {
	f.Add(testFrame(0, []byte("hello")))
	f.Add(testFrame(0, []byte("a{{openai}}b")))
	f.Add(testFrame(1, []byte("z")))
	f.Add([]byte{0, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0})
	f.Add(append(testFrame(0, []byte("{{open")), testFrame(0, []byte("ai}}"))...))
	f.Add(append(append(testFrame(0, []byte("{{o")), testFrame(0, nil)...), append(testFrame(0, []byte("penai")), testFrame(0, []byte("}}"))...)...))
	f.Fuzz(func(t *testing.T, in []byte) {
		g, got := newTestGuard(bytes.NewReader(in), 256)
		out, err := io.ReadAll(g)
		// Invariants: forwarded bytes are a prefix of the input; the output
		// never holds a placeholder inside a frame; any error is a refusal.
		if !bytes.HasPrefix(in, out) {
			t.Fatalf("output is not a prefix of the input")
		}
		if err != nil && (!errors.Is(err, errGRPCFrameRefused) || len(*got) != 1) {
			t.Fatalf("err=%v refusals=%d", err, len(*got))
		}
		if err == nil && len(out) != len(in) {
			t.Fatalf("clean end but %d of %d bytes forwarded", len(out), len(in))
		}
		// Re-walk the forwarded frames: none may carry the placeholder, alone or
		// joined with the frames before it.
		var joined []byte
		for rest := out; len(rest) >= grpcFrameHeaderLen; {
			n := int(binary.BigEndian.Uint32(rest[1:5]))
			if grpcFrameHeaderLen+n > len(rest) {
				t.Fatalf("forwarded a partial frame")
			}
			if bytes.Contains(rest[grpcFrameHeaderLen:grpcFrameHeaderLen+n], []byte("{{openai}}")) {
				t.Fatalf("forwarded a frame carrying the placeholder")
			}
			joined = append(joined, rest[grpcFrameHeaderLen:grpcFrameHeaderLen+n]...)
			rest = rest[grpcFrameHeaderLen+n:]
		}
		if bytes.Contains(joined, []byte("{{openai}}")) {
			t.Fatalf("forwarded frames jointly carry a placeholder")
		}
	})
}
