package identityclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Schedule of the Warden token source.
const (
	// The source exchanges again after refreshNum/refreshDen (2/3) of the token
	// lifetime, measured from the local receipt time.
	refreshNum, refreshDen = 2, 3
	// refreshJitter is the largest share of the refresh point shaved off at
	// random, so a fleet started together does not exchange together.
	refreshJitter = 0.10
	// Backoff after a failed re-exchange while the current token is valid.
	minBackoff = time.Second
	maxBackoff = 60 * time.Second
	// maxInlineWait is the longest Retry-After a call with no valid token
	// waits for; a longer one is returned to the caller.
	maxInlineWait = 30 * time.Second
	// defaultAttempts is how many requests a call with no valid token makes
	// when the control plane answers 429 or 503.
	defaultAttempts = 3
	// refreshFloor is the shortest time between a successful receipt and a
	// forced re-exchange, so a burst of 407s does not hammer the control plane.
	refreshFloor = 2 * time.Second
)

// SubjectSource supplies the user's ID token for an exchange. It never
// prompts: an unusable login is ErrLoginRequired. *Client (the P1 login cache)
// and FileSubject implement it.
type SubjectSource interface {
	Subject(ctx context.Context) (string, error)
}

// Subject returns the ID token from the shared login cache, refreshing it when
// due. A Client is therefore a SubjectSource.
func (c *Client) Subject(ctx context.Context) (string, error) {
	res, err := c.Token(ctx)
	if err != nil {
		return "", err
	}
	return res.IDToken, nil
}

// FileSubject reads the ID token from a file for harness platforms and CI. The
// file must be 0600 or tighter and is re-read on every call, so an outer
// process may rotate it.
type FileSubject struct{ Path string }

// Subject implements SubjectSource.
func (f FileSubject) Subject(context.Context) (string, error) {
	raw, err := readCappedFile(f.Path, "subject token file", maxTokenFile)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", errors.New("identityclient: the subject token file " + f.Path + " is empty")
	}
	return tok, nil
}

const maxTokenFile = 64 << 10

// TokenExchanger is what the source needs from an Exchanger.
type TokenExchanger interface {
	Exchange(ctx context.Context, subject string) (WardenToken, error)
}

// WardenTokenSource hands out a valid Warden token for one agent. The token is
// held in memory only, never written to disk. It re-exchanges at 2/3 of the
// lifetime (up to 10% earlier, at random), shares one request between
// concurrent callers, and keeps serving the current token until its exp when a
// re-exchange fails: login required, control plane unreachable or throttled.
// It never prompts. It is safe for concurrent use; build it with
// NewWardenTokenSource.
type WardenTokenSource struct {
	Exchanger TokenExchanger
	Subject   SubjectSource
	// AgentID is only used in log lines.
	AgentID string
	Now     func() time.Time
	Log     *slog.Logger
	// Sleep waits d or until ctx ends (tests replace it).
	Sleep func(ctx context.Context, d time.Duration) error
	// Jitter returns a value in [0,1); tests pin it.
	Jitter func() float64
	// Attempts is how many requests a call makes, when no token is valid, if
	// the control plane answers 429 or 503; zero means 3. invalid_client and
	// the other refusals are never retried.
	Attempts int

	mu          sync.Mutex
	cur         WardenToken
	have        bool
	refreshAt   time.Time
	nextAttempt time.Time
	lastErr     error
	failures    int
	flight      *tokenFlight
	rotate      []func()

	// joinHook, set only by tests, runs once per caller that has joined a
	// flight and is about to wait for it.
	joinHook func()
}

type tokenFlight struct {
	done chan struct{}
	err  error
	cbs  []func() // OnRotate callbacks to run once the flight is over
}

// StateReason is the coarse health of a WardenTokenSource.
type StateReason string

// The reasons State reports.
const (
	// ReasonValid: a token is held and no refresh is due or failing.
	ReasonValid StateReason = "valid"
	// ReasonExpiring: a token is held but its refresh is due or failing, or no
	// token is held yet and no failure has been recorded (an exchange is due).
	ReasonExpiring StateReason = "expiring"
	// ReasonLoginRequired: no valid token and the user's login is unusable (or
	// the issuer cannot be reached to refresh it).
	ReasonLoginRequired StateReason = "login_required"
	// ReasonCPUnreachable: no valid token; the control plane is unreachable,
	// throttled, unavailable or answered nonsense.
	ReasonCPUnreachable StateReason = "cp_unreachable"
	// ReasonExchangeDenied: no valid token; the control plane refused.
	ReasonExchangeDenied StateReason = "exchange_denied"
)

// State is a snapshot for a health endpoint. It holds no token material.
type State struct {
	Reason StateReason
	// LastError is a short code for the last failed exchange (for example
	// "exchange_denied:invalid_client" or "cp_unreachable"); empty when the
	// last exchange succeeded. It may be set while Reason is valid or expiring.
	LastError string
	// Expiry is the exp of the held token; zero when none is held.
	Expiry time.Time
}

// State reports the source's health without any I/O.
func (s *WardenTokenSource) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	st := State{}
	if s.have {
		st.Expiry = s.cur.Expiry
	}
	if s.lastErr != nil {
		st.LastError = errorKind(s.lastErr)
	}
	if s.have && now.Before(s.cur.Expiry) {
		st.Reason = ReasonValid
		if s.lastErr != nil || !now.Before(s.refreshAt) {
			st.Reason = ReasonExpiring
		}
		return st
	}
	st.Reason = ReasonExpiring
	if s.lastErr != nil {
		st.Reason = reasonFor(s.lastErr)
	}
	return st
}

func reasonFor(err error) StateReason {
	var de ErrExchangeDenied
	switch {
	case errors.As(err, &de):
		return ReasonExchangeDenied
	case errors.Is(err, ErrLoginRequired), errors.Is(err, ErrIssuerUnreachable):
		return ReasonLoginRequired
	}
	return ReasonCPUnreachable
}

// String, GoString and LogValue show the agent id, a token fingerprint and the
// expiry, never the token, so formatting or logging the source cannot leak it.
func (s *WardenTokenSource) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp, exp := "", time.Time{}
	if s.have {
		fp, exp = Fingerprint(s.cur.AccessToken), s.cur.Expiry
	}
	return "identityclient.WardenTokenSource(agent=" + s.AgentID + " token_fp=" + fp + " exp=" + exp.Format(time.RFC3339) + ")"
}

// GoString implements fmt.GoStringer.
func (s *WardenTokenSource) GoString() string { return s.String() }

// LogValue implements slog.LogValuer.
func (s *WardenTokenSource) LogValue() slog.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp, exp := "", time.Time{}
	if s.have {
		fp, exp = Fingerprint(s.cur.AccessToken), s.cur.Expiry
	}
	return slog.GroupValue(slog.String("agent_id", s.AgentID), slog.String("token_fp", fp), slog.Time("exp", exp))
}

// NewWardenTokenSource returns a source over ex and subject.
func NewWardenTokenSource(ex TokenExchanger, subject SubjectSource) *WardenTokenSource {
	return &WardenTokenSource{Exchanger: ex, Subject: subject}
}

func (s *WardenTokenSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *WardenTokenSource) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (s *WardenTokenSource) jitter() float64 {
	if s.Jitter != nil {
		return s.Jitter()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

func (s *WardenTokenSource) sleep(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// OnRotate registers fn to run after every successful exchange (the first one
// included), once the exchange's flight has completed and with no lock held, so
// fn may call Token or Refresh. Callers of Token may see the new token slightly
// before fn has run. The forwarder uses it to drain tunnels
// opened with the old token.
func (s *WardenTokenSource) OnRotate(fn func()) {
	s.mu.Lock()
	s.rotate = append(s.rotate, fn)
	s.mu.Unlock()
}

// Current returns the held token if it has not expired. It does no I/O.
func (s *WardenTokenSource) Current() (WardenToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.have && s.now().Before(s.cur.Expiry) {
		return s.cur, true
	}
	return WardenToken{}, false
}

// Token returns a valid Warden token, exchanging first when there is none or
// the refresh point has passed. When a re-exchange fails and the held token is
// still valid, that token is returned and the failure is retried with a
// jittered backoff from 1s to 60s (a 429's or 503's Retry-After when longer).
// With no valid token the failure is returned as a typed error:
// ErrLoginRequired, ErrIssuerUnreachable, ErrExchangeDenied, ErrRateLimited,
// ErrUnavailable or ErrCPUnreachable.
func (s *WardenTokenSource) Token(ctx context.Context) (WardenToken, error) {
	return s.token(ctx, false)
}

// Refresh exchanges now, ahead of the schedule (the forwarder's answer to a
// 407). Concurrent callers share one request. It is still bound by two limits:
// no exchange within 2s of the last successful receipt (the held token is
// returned with a nil error), and none while the cooldown after a failure,
// denial or 429 runs.
//
// Unlike Token, Refresh reports a failure even when it can still serve: the
// error is non-nil whenever the exchange failed or was held back by a
// cooldown, and the returned token is then the held one if it is still valid
// (and the zero token otherwise). A caller must check the error first and may
// use a non-zero token that comes with it.
func (s *WardenTokenSource) Refresh(ctx context.Context) (WardenToken, error) {
	return s.token(ctx, true)
}

func (s *WardenTokenSource) token(ctx context.Context, force bool) (WardenToken, error) {
	s.mu.Lock()
	now := s.now()
	valid := s.have && now.Before(s.cur.Expiry)
	if !force {
		if valid && now.Before(s.refreshAt) {
			tok := s.cur
			s.mu.Unlock()
			return tok, nil
		}
		// A failed exchange keeps its backoff, or the Retry-After it was
		// given, so a flood of callers does not hammer the control plane.
		if s.lastErr != nil && now.Before(s.nextAttempt) {
			if valid {
				tok := s.cur
				s.mu.Unlock()
				return tok, nil
			}
			err := s.lastErr
			s.mu.Unlock()
			return WardenToken{}, err
		}
	} else {
		if valid && s.lastErr == nil && now.Sub(s.cur.ReceivedAt) < refreshFloor {
			tok := s.cur
			s.mu.Unlock()
			return tok, nil
		}
		if s.lastErr != nil && now.Before(s.nextAttempt) {
			err := s.lastErr
			var tok WardenToken
			if valid {
				tok = s.cur
			}
			s.mu.Unlock()
			return tok, err
		}
	}
	f := s.flight
	if f == nil {
		f = &tokenFlight{done: make(chan struct{})}
		s.flight = f
		// The exchange outlives the caller that started it: others share it.
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		go func() {
			defer cancel()
			f.cbs, f.err = s.exchange(bg)
			s.mu.Lock()
			s.flight = nil
			s.mu.Unlock()
			close(f.done)
			// OnRotate callbacks run after the flight is over and with no lock
			// held, so one may call Token or Refresh.
			for _, fn := range f.cbs {
				fn()
			}
		}()
	}
	s.mu.Unlock()
	if s.joinHook != nil {
		s.joinHook()
	}

	select {
	case <-f.done:
	case <-ctx.Done():
		return WardenToken{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.have && s.now().Before(s.cur.Expiry) {
		if force {
			return s.cur, f.err
		}
		return s.cur, nil
	}
	if f.err != nil {
		return WardenToken{}, f.err
	}
	return WardenToken{}, ErrBadExchangeResponse
}

// exchange runs one scheduled exchange: subject, request, and for a call that
// holds no valid token a few retries of 429 and 503.
func (s *WardenTokenSource) exchange(ctx context.Context) ([]func(), error) {
	attempts := s.Attempts
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	for n := 1; ; n++ {
		subject, err := s.Subject.Subject(ctx)
		var tok WardenToken
		if err == nil {
			tok, err = s.Exchanger.Exchange(ctx, subject)
		}
		if err == nil {
			return s.store(tok), nil
		}
		wait, retryable := retryDelay(err)
		s.mu.Lock()
		valid := s.have && s.now().Before(s.cur.Expiry)
		s.mu.Unlock()
		if !valid && retryable && n < attempts && wait <= maxInlineWait {
			if wait <= 0 {
				wait = s.backoff(n)
			}
			if serr := s.sleep(ctx, wait); serr != nil {
				return nil, serr
			}
			continue
		}
		s.fail(err, wait)
		return nil, err
	}
}

// retryDelay classifies err: the Retry-After it carries and whether it is
// worth retrying at once (only 429 and 503).
func retryDelay(err error) (time.Duration, bool) {
	var rl ErrRateLimited
	if errors.As(err, &rl) {
		return rl.RetryAfter, true
	}
	var un ErrUnavailable
	if errors.As(err, &un) {
		return un.RetryAfter, true
	}
	return 0, false
}

// backoff is 1s doubling to 60s, shaved by up to half at random.
func (s *WardenTokenSource) backoff(failures int) time.Duration {
	d := maxBackoff
	if failures < 7 {
		d = min(minBackoff<<max(failures-1, 0), maxBackoff)
	}
	return time.Duration(float64(d) * (1 - 0.5*s.jitter()))
}

// store keeps tok and returns the OnRotate callbacks the caller runs once it
// holds no lock.
func (s *WardenTokenSource) store(tok WardenToken) []func() {
	life := tok.Expiry.Sub(tok.ReceivedAt)
	at := tok.ReceivedAt.Add(time.Duration(float64(life*refreshNum/refreshDen) * (1 - refreshJitter*s.jitter())))
	s.mu.Lock()
	s.cur, s.have, s.refreshAt = tok, true, at
	s.nextAttempt, s.lastErr, s.failures = time.Time{}, nil, 0
	cbs := append([]func(){}, s.rotate...)
	s.mu.Unlock()
	s.log().Debug("warden token stored", "agent_id", s.AgentID, "exp", tok.Expiry, "token_fp", Fingerprint(tok.AccessToken))
	return cbs
}

func (s *WardenTokenSource) fail(err error, retryAfter time.Duration) {
	s.mu.Lock()
	s.failures++
	wait := max(s.backoff(s.failures), retryAfter)
	s.lastErr, s.nextAttempt = err, s.now().Add(wait)
	valid := s.have && s.now().Before(s.cur.Expiry)
	s.mu.Unlock()
	s.log().Debug("warden token exchange failed", "agent_id", s.AgentID, "serving_current", valid,
		"error_type", errorKind(err), "retry_in", wait)
}

// errorKind names a failure without its text.
func errorKind(err error) string {
	var de ErrExchangeDenied
	switch {
	case errors.As(err, &de):
		return "exchange_denied:" + de.Code
	case errors.Is(err, ErrLoginRequired):
		return "login_required"
	case errors.Is(err, ErrIssuerUnreachable):
		return "issuer_unreachable"
	case errors.Is(err, ErrCPUnreachable):
		return "cp_unreachable"
	}
	var rl ErrRateLimited
	if errors.As(err, &rl) {
		return "rate_limited"
	}
	var un ErrUnavailable
	if errors.As(err, &un) {
		return "unavailable"
	}
	return "error"
}
