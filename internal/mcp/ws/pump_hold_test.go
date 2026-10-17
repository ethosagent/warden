package ws

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// expectNoDataFrame asserts the first frame r receives is the policy Close, not
// a data frame: the peer must never see a held, denied message.
func expectNoDataFrame(t *testing.T, r *bufio.Reader) {
	t.Helper()
	f := readFrameTimeout(t, r)
	if f.Opcode == OpcodeText || f.Opcode == OpcodeContinuation {
		t.Fatalf("denied message reached the peer (opcode %x, %q)", f.Opcode, f.Payload)
	}
	assertClose1008(t, f)
}

func TestPumpHold_DeniedClientCallNeverForwarded(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	go func() { _, _ = clientB.Write(maskedText(denyCall)) }()

	expectNoDataFrame(t, bufio.NewReader(serverB))
	assertClose1008(t, readFrameTimeout(t, bufio.NewReader(clientB)))
	if r := waitResult(t, res); !r.blocked {
		t.Fatal("expected blocked")
	}
}

func TestPumpHold_DeniedServerResultNeverForwarded(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	go func() { _, _ = serverB.Write(unmaskedText(poisonList)) }()

	expectNoDataFrame(t, bufio.NewReader(clientB))
	if r := waitResult(t, res); !r.blocked {
		t.Fatal("expected blocked")
	}
}

func TestPumpHold_FragmentedDeniedNeverForwarded(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	half := len(denyCall) / 2
	go func() {
		_, _ = clientB.Write(buildWireFrame(false, OpcodeText, []byte(denyCall[:half]), []byte{1, 2, 3, 4}))
		_, _ = clientB.Write(buildWireFrame(true, OpcodeContinuation, []byte(denyCall[half:]), []byte{5, 6, 7, 8}))
	}()

	expectNoDataFrame(t, bufio.NewReader(serverB))
	if r := waitResult(t, res); !r.blocked {
		t.Fatal("expected blocked")
	}
}

// Allowed fragmented message: ping passes immediately (before the final
// fragment), then all fragments arrive in order, byte-identical.
func TestPumpHold_FragmentedAllowedForwardedInOrderWithControl(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	half := len(allowCall) / 2
	frag1 := buildWireFrame(false, OpcodeText, []byte(allowCall[:half]), []byte{1, 2, 3, 4})
	ping := buildWireFrame(true, OpcodePing, []byte("hb"), []byte{9, 9, 9, 9})
	frag2 := buildWireFrame(true, OpcodeContinuation, []byte(allowCall[half:]), []byte{5, 6, 7, 8})

	go func() {
		_, _ = clientB.Write(frag1)
		_, _ = clientB.Write(ping)
	}()
	serverBR := bufio.NewReader(serverB)
	// The ping is forwarded while the text message is still held.
	if op := readFrameTimeout(t, serverBR).Opcode; op != OpcodePing {
		t.Fatalf("expected ping first (control not held), got %x", op)
	}
	go func() {
		_, _ = clientB.Write(frag2)
		_, _ = clientB.Write(buildClose())
	}()

	var got bytes.Buffer
	for i := 0; i < 2; i++ {
		f := readFrameTimeout(t, serverBR)
		if err := f.Write(&got); err != nil {
			t.Fatal(err)
		}
	}
	if want := append(append([]byte(nil), frag1...), frag2...); !bytes.Equal(got.Bytes(), want) {
		t.Fatal("fragments not forwarded unchanged and in order")
	}
	if r := waitResult(t, res); r.blocked {
		t.Fatal("allowed message must not block")
	}
}

func TestPumpHold_OverCapFailsClosed(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	chunk := bytes.Repeat([]byte("a"), maxReassembledMessage/2+1)
	go func() {
		_, _ = clientB.Write(buildWireFrame(false, OpcodeText, chunk, []byte{1, 2, 3, 4}))
		_, _ = clientB.Write(buildWireFrame(true, OpcodeContinuation, chunk, []byte{1, 2, 3, 4}))
	}()

	expectNoDataFrame(t, bufio.NewReader(serverB))
	if r := waitResult(t, res); !r.blocked {
		t.Fatal("over-cap message must fail closed")
	}
}

// Without Hold (monitor/off) the message is forwarded before the scan, as today.
func TestPumpHold_OffKeepsForwardThenScan(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s"}
	res := startPump(t, p, clientA, serverA)

	go func() { _, _ = clientB.Write(maskedText(denyCall)) }()
	if f := readFrameTimeout(t, bufio.NewReader(serverB)); f.Opcode != OpcodeText {
		t.Fatalf("expected forwarded text, got %x", f.Opcode)
	}
	waitResult(t, res)
}

// A new data message while one is still open is a protocol violation: nothing,
// including the already-held fragment, is forwarded.
func TestPumpHold_TextInsideOpenMessageDenied(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	go func() {
		_, _ = clientB.Write(buildWireFrame(false, OpcodeText, []byte(allowCall[:10]), []byte{1, 2, 3, 4}))
		_, _ = clientB.Write(maskedText(allowCall))
	}()

	expectNoDataFrame(t, bufio.NewReader(serverB))
	if r := waitResult(t, res); !r.blocked {
		t.Fatal("expected blocked")
	}
}

// A continuation with no open message cannot be scanned: denied, not forwarded.
func TestPumpHold_StrayContinuationDenied(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	go func() {
		_, _ = clientB.Write(buildWireFrame(true, OpcodeContinuation, []byte(denyCall), []byte{1, 2, 3, 4}))
	}()

	expectNoDataFrame(t, bufio.NewReader(serverB))
	if r := waitResult(t, res); !r.blocked {
		t.Fatal("expected blocked")
	}
}

func TestPumpHold_BinaryDeniedCallNeverForwarded(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	go func() {
		_, _ = clientB.Write(buildWireFrame(true, OpcodeBinary, []byte(denyCall), []byte{1, 2, 3, 4}))
	}()

	expectNoDataFrame(t, bufio.NewReader(serverB))
	if r := waitResult(t, res); !r.blocked {
		t.Fatal("expected blocked")
	}
}

func TestPumpHold_BinaryAllowedForwardedUnchanged(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
	res := startPump(t, p, clientA, serverA)

	wire := buildWireFrame(true, OpcodeBinary, []byte(allowCall), []byte{1, 2, 3, 4})
	go func() {
		_, _ = clientB.Write(wire)
		_, _ = clientB.Write(buildClose())
	}()

	f := readFrameTimeout(t, bufio.NewReader(serverB))
	var got bytes.Buffer
	if err := f.Write(&got); err != nil {
		t.Fatal(err)
	}
	if f.Opcode != OpcodeBinary || !bytes.Equal(got.Bytes(), wire) {
		t.Fatal("allowed binary message not forwarded unchanged")
	}
	if r := waitResult(t, res); r.blocked {
		t.Fatal("allowed binary message must not block")
	}
}

func TestPumpHold_BinaryNonJSONDenied(t *testing.T) {
	for name, payload := range map[string][]byte{
		"invalid-utf8": {0xff, 0xfe, 0x00, 0x01},
		"not-json":     []byte("hello world"),
	} {
		t.Run(name, func(t *testing.T) {
			clientA, clientB := pipePair()
			serverA, serverB := pipePair()
			p := &Pump{GW: enforceGW(t), SessionKey: "s", Hold: true}
			res := startPump(t, p, clientA, serverA)

			go func() {
				_, _ = clientB.Write(buildWireFrame(true, OpcodeBinary, payload, []byte{1, 2, 3, 4}))
			}()

			expectNoDataFrame(t, bufio.NewReader(serverB))
			if r := waitResult(t, res); !r.blocked {
				t.Fatal("unscannable binary must fail closed")
			}
		})
	}
}

// Monitor/off (no Hold) keeps binary frames forwarded unscanned.
func TestPumpHold_OffForwardsBinary(t *testing.T) {
	clientA, clientB := pipePair()
	serverA, serverB := pipePair()
	p := &Pump{GW: enforceGW(t), SessionKey: "s"}
	res := startPump(t, p, clientA, serverA)

	go func() {
		_, _ = clientB.Write(buildWireFrame(true, OpcodeBinary, []byte(denyCall), []byte{1, 2, 3, 4}))
		_, _ = clientB.Write(buildClose())
	}()
	if f := readFrameTimeout(t, bufio.NewReader(serverB)); f.Opcode != OpcodeBinary {
		t.Fatalf("expected forwarded binary, got %x", f.Opcode)
	}
	waitResult(t, res)
}

// allowScanner allows everything at zero cost, isolating the pump's own hold
// overhead from the (dominant) gateway scan cost.
type allowScanner struct{}

func (allowScanner) OnRequest(string, string, string, http.Header, []byte) gateway.Verdict {
	return gateway.Verdict{}
}

func (allowScanner) OnResponse(string, int, http.Header, []byte) gateway.Verdict {
	return gateway.Verdict{}
}

// BenchmarkPumpDir compares the hold path with forward-then-scan on an allowed
// message of several sizes: with the real gateway (scan cost dominates) and with
// a free scanner (the pump's own overhead).
func BenchmarkPumpDir(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 64 << 10} {
		pad := strings.Repeat("a", size)
		msg := `{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x","pad":"` + pad + `"}}}`
		wire := buildWireFrame(true, OpcodeText, []byte(msg), []byte{1, 2, 3, 4})
		for _, gw := range []string{"gateway", "free"} {
			for _, hold := range []bool{false, true} {
				b.Run(fmt.Sprintf("%dB/%s/hold=%v", size, gw, hold), func(b *testing.B) {
					var sc Scanner = allowScanner{}
					if gw == "gateway" {
						sc = enforceGW(b)
					}
					p := &Pump{GW: sc, SessionKey: "s", Hold: hold, Log: slog.Default()}
					b.ReportAllocs()
					b.SetBytes(int64(len(wire)))
					for i := 0; i < b.N; i++ {
						err := p.pumpDir(context.Background(), bytes.NewReader(wire),
							func(Frame) error { return nil }, dirRequest, func() {})
						if err != io.EOF {
							b.Fatalf("unexpected err %v", err)
						}
					}
				})
			}
		}
	}
}
