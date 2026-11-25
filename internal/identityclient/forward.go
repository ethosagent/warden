package identityclient

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// Timings of RunForwarder.
const (
	// maintainTick is how often the run loop asks for a token, so a rotation
	// does not wait for the next CONNECT and /healthz tracks the exchange.
	// WardenTokenSource keeps its own backoff, so this never hammers the
	// control plane.
	maintainTick = time.Second
	// DefaultShutdownGrace is how long open tunnels may finish after SIGTERM.
	DefaultShutdownGrace = 5 * time.Second
	// healthHeaderTimeout bounds a /healthz client's request headers.
	healthHeaderTimeout = 5 * time.Second
)

// ForwardRun is one long-lived `warden identity forward`.
type ForwardRun struct {
	// Forwarder is the configured forwarder; Listener is the one it serves on.
	Forwarder *Forwarder
	Listener  net.Listener
	// Health, when set, serves GET /healthz from State.
	Health net.Listener
	// State reports the health of the token (Source.State, ClientState.State).
	State func() State
	// Poke asks for a token on each tick; its result is ignored. It keeps the
	// token fresh and State current while no CONNECT arrives.
	Poke func(ctx context.Context)
	Log  *slog.Logger
	// Clock times the run loop; nil is the real clock.
	Clock clock.Clock
	// Grace is how long open tunnels may finish once ctx ends; zero selects
	// DefaultShutdownGrace.
	Grace time.Duration
}

// RunForwarder serves until ctx ends, then stops accepting, lets open tunnels
// finish for Grace and closes the rest. A token that cannot be had (login
// required, control plane down or still signing its first key, agent denied) is
// a state to report, never a reason to exit.
func RunForwarder(ctx context.Context, r ForwardRun) error {
	log := r.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	clk := r.Clock
	if clk == nil {
		clk = clock.Real()
	}
	grace := r.Grace
	if grace <= 0 {
		grace = DefaultShutdownGrace
	}

	hard, hardStop := context.WithCancel(context.WithoutCancel(ctx))
	defer hardStop()
	serveDone := make(chan error, 1)
	go func() { serveDone <- r.Forwarder.Serve(hard, r.Listener) }()

	var aux sync.WaitGroup
	auxCtx, auxStop := context.WithCancel(hard)
	defer func() { auxStop(); aux.Wait() }()
	if r.Health != nil && r.State != nil {
		srv := &http.Server{Handler: HealthHandler(r.State, clk.Now), ReadHeaderTimeout: healthHeaderTimeout, MaxHeaderBytes: 8 << 10}
		aux.Add(1)
		go func() {
			defer aux.Done()
			if err := srv.Serve(r.Health); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("health listener stopped", "error_type", "serve")
			}
		}()
		aux.Add(1)
		go func() { defer aux.Done(); <-auxCtx.Done(); _ = srv.Close() }()
	}
	if r.State != nil {
		aux.Add(1)
		go func() { defer aux.Done(); maintain(auxCtx, clk, r.State, r.Poke, log) }()
	}

	select {
	case err := <-serveDone:
		return err // accept failed
	case <-ctx.Done():
	}
	// Stop accepting; handlers keep running until their tunnels end.
	_ = r.Listener.Close()
	timer := clk.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-serveDone:
		return err
	case <-timer.C():
		hardStop()
		return <-serveDone
	}
}

// maintain asks for a token each tick and logs every change of the token state
// once.
func maintain(ctx context.Context, clk clock.Clock, state func() State, poke func(context.Context), log *slog.Logger) {
	var last StateReason
	observe := func() {
		st := state()
		if st.Reason == last {
			return
		}
		if st.Reason == ReasonLoginRequired {
			log.Warn("login_required", "from", string(last))
		} else {
			log.Info("exchange", "state", string(st.Reason), "from", string(last), "last_error", st.LastError)
		}
		last = st.Reason
	}
	tm := clk.NewTimer(maintainTick)
	defer tm.Stop()
	for {
		if poke != nil {
			poke(ctx)
		}
		observe()
		select {
		case <-ctx.Done():
			return
		case <-tm.C():
			tm.Reset(maintainTick)
		}
	}
}
