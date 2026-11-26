package identityclient

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// Tunnel limits and the drain schedule.
const (
	// defaultMaxTunnels is the cap on CONNECTs served at once.
	defaultMaxTunnels = 512
	// drainIdle is how long a tunnel opened with an older token may carry no
	// bytes, in either direction, before the forwarder closes it.
	drainIdle = 2 * time.Second
	// drainTick is how often the drain loop looks at the open tunnels.
	drainTick = 250 * time.Millisecond
	// spliceBufSize is the buffer of each copy direction.
	spliceBufSize = 32 << 10
)

// TokenSource is the Warden token a Forwarder injects: a *WardenTokenSource.
type TokenSource interface {
	Token(ctx context.Context) (WardenToken, error)
	Refresh(ctx context.Context) (WardenToken, error)
	Current() (WardenToken, bool)
	OnRotate(fn func())
}

var _ TokenSource = (*WardenTokenSource)(nil)

// splicePool holds the copy buffers: two per open tunnel, reused across them.
var splicePool = sync.Pool{New: func() any { b := make([]byte, spliceBufSize); return &b }}

// tunnel is one spliced CONNECT.
type tunnel struct {
	fp   string    // token fingerprint, "none" for an anonymous (challenge) tunnel
	exp  time.Time // exp of the token it was opened with; zero when not tracked
	last atomic.Int64
	clk  clock.Clock
	// up counts bytes from the client to the worker, down the other way.
	up, down  atomic.Int64
	closeOnce sync.Once
	closeFn   func()
}

func (t *tunnel) touch() { t.last.Store(t.clk.Now().UnixNano()) }

func (t *tunnel) close() { t.closeOnce.Do(t.closeFn) }

// tunnelRegistry counts the CONNECTs being served, holds the open tunnels and
// closes the ones that must not outlive their token: after a rotation a tunnel
// opened with the old token is closed once it has been idle for drainIdle, and
// every tunnel is closed at its token's exp.
type tunnelRegistry struct {
	clk    clock.Clock
	max    int64
	active atomic.Int64
	// newest reports the fingerprint of the newest valid token, if any.
	newest func() (string, bool)
	wakeCh chan struct{}

	mu  sync.Mutex
	set map[*tunnel]struct{}
}

func newTunnelRegistry(clk clock.Clock, limit int, newest func() (string, bool)) *tunnelRegistry {
	if clk == nil {
		clk = clock.Real()
	}
	if limit <= 0 {
		limit = defaultMaxTunnels
	}
	return &tunnelRegistry{clk: clk, max: int64(limit), newest: newest, wakeCh: make(chan struct{}, 1), set: map[*tunnel]struct{}{}}
}

// reserve takes one of the slots; false when all are taken.
func (r *tunnelRegistry) reserve() bool {
	for {
		n := r.active.Load()
		if n >= r.max {
			return false
		}
		if r.active.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (r *tunnelRegistry) release() { r.active.Add(-1) }

// wake asks the drain loop to look now.
func (r *tunnelRegistry) wake() {
	select {
	case r.wakeCh <- struct{}{}:
	default:
	}
}

// run is the drain loop; it returns when ctx ends.
func (r *tunnelRegistry) run(ctx context.Context) {
	tm := r.clk.NewTimer(drainTick)
	defer tm.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tm.C():
		case <-r.wakeCh:
			tm.Stop()
		}
		r.sweep(r.clk.Now())
		tm.Reset(drainTick)
	}
}

// sweep closes the tunnels that are past their token's exp, or that were opened
// with a token older than the newest and have been idle for drainIdle.
func (r *tunnelRegistry) sweep(now time.Time) {
	newest, haveNewest := "", false
	if r.newest != nil {
		newest, haveNewest = r.newest()
	}
	var doomed []*tunnel
	r.mu.Lock()
	for t := range r.set {
		idle := now.Sub(time.Unix(0, t.last.Load()))
		switch {
		case !t.exp.IsZero() && !now.Before(t.exp):
			doomed = append(doomed, t)
		case haveNewest && t.fp != "none" && t.fp != newest && idle >= drainIdle:
			doomed = append(doomed, t)
		}
	}
	r.mu.Unlock()
	for _, t := range doomed {
		t.close()
	}
}

// serve registers a tunnel for an established CONNECT, splices both ways until
// it ends and logs its open and close.
func (r *tunnelRegistry) serve(log *slog.Logger, target string, status int, fp string, exp time.Time, client net.Conn, cbr *bufio.Reader, worker net.Conn, wbr *bufio.Reader) {
	t := &tunnel{fp: fp, exp: exp, clk: r.clk, closeFn: func() { _ = client.Close(); _ = worker.Close() }}
	start := r.clk.Now()
	t.last.Store(start.UnixNano())
	r.mu.Lock()
	r.set[t] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.set, t)
		r.mu.Unlock()
	}()
	log.Info("tunnel_open", "target", target, "status", status, "token_fp", fp)
	t.splice(client, cbr, worker, wbr)
	log.Info("tunnel_close", "target", target, "status", status, "token_fp", fp,
		"bytes_up", t.up.Load(), "bytes_down", t.down.Load(), "duration", r.clk.Now().Sub(start))
}

// splice copies both ways. EOF on one side half-closes the other's write side
// so a response can still finish; an error on either side, or both sides
// ending, closes both connections. Bytes the readers had already buffered are
// forwarded first.
func (t *tunnel) splice(client net.Conn, cbr *bufio.Reader, worker net.Conn, wbr *bufio.Reader) {
	var wg sync.WaitGroup
	pipe := func(dst net.Conn, src io.Reader, n *atomic.Int64) {
		defer wg.Done()
		if err := t.copy(dst, src, n); err != nil {
			t.close()
			return
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		t.close()
	}
	wg.Add(2)
	go pipe(worker, cbr, &t.up)
	go pipe(client, wbr, &t.down)
	wg.Wait()
	t.close()
}

// copy moves src to dst through a pooled buffer, counting bytes and noting the
// activity the drain looks at. It returns nil on EOF.
func (t *tunnel) copy(dst io.Writer, src io.Reader, n *atomic.Int64) error {
	bp := splicePool.Get().(*[]byte)
	defer splicePool.Put(bp)
	buf := *bp
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			t.touch()
			n.Add(int64(nr))
			if _, werr := dst.Write(buf[:nr]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}
