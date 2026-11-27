package proxy

import (
	"io"
	"sync/atomic"
)

// countingReadCloser counts the bytes actually read through a message body so
// recordAllowEvent can price a streamed message (chunked, SSE, gRPC) whose
// Content-Length is unknown. It lives by value inside requestScope (one per
// direction), so wrapping a body costs no allocation beyond the scope itself;
// the hot path adds one atomic add per Read and never inspects, copies or logs
// the bytes. The count is atomic because the h2 transport reads a request body
// on its own goroutine while the handler goroutine reads the total afterwards.
type countingReadCloser struct {
	rc io.ReadCloser
	n  atomic.Int64
}

// wrap installs rc as the counted body and returns the reader to use in its
// place. It resets the count.
func (c *countingReadCloser) wrap(rc io.ReadCloser) io.ReadCloser {
	c.rc = rc
	c.n.Store(0)
	return c
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

func (c *countingReadCloser) Close() error { return c.rc.Close() }

// count returns the bytes read so far.
func (c *countingReadCloser) count() int64 { return c.n.Load() }
