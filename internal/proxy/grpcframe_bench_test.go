package proxy

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

// BenchmarkGRPCFrameGuard is the per-message cost of the gRPC body guard (#418)
// on the live h2 path: a clean message of 1 KiB or 64 KiB checked against one or
// ten in-scope placeholders (the scan, the boundary join and the frame copy).
func BenchmarkGRPCFrameGuard(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10} {
		for _, nph := range []int{1, 10} {
			b.Run(fmt.Sprintf("%dKiB/%dph", size>>10, nph), func(b *testing.B) {
				phs := make([][]byte, nph)
				for i := range phs {
					phs[i] = []byte(fmt.Sprintf("WARDEN_PLACEHOLDER_%03d", i))
				}
				frame := testFrame(0, bytes.Repeat([]byte("a"), size))
				b.SetBytes(int64(len(frame)))
				b.ReportAllocs()
				for b.Loop() {
					g := newGRPCFrameGuard(io.NopCloser(bytes.NewReader(frame)), phs, maxGRPCFrameBytes, nil)
					if _, err := io.Copy(io.Discard, g); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
