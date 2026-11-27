package offboard

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/portal"
)

// LinkStore is the part of portal.LinkStore the job uses. Every write is a
// compare-and-swap on the row's generation under the per-user lock the
// portal callback shares, so a verdict about an older token never lands on a
// row a newer login wrote.
type LinkStore interface {
	List(ctx context.Context) ([]portal.IdPLink, error)
	// TokenAt reads the row and its stored token as one locked snapshot;
	// portal.ErrLinkInconsistent when they disagree (a split login write).
	TokenAt(ctx context.Context, iss, sub string) (string, portal.IdPLink, error)
	// Rotate writes a refreshed token if the generation is unchanged;
	// portal.ErrStaleGeneration (nothing written) when a login won.
	Rotate(ctx context.Context, iss, sub string, expectedGeneration int64, token string) (portal.IdPLink, error)
	// SetState writes the refresh columns under the same compare-and-swap.
	SetState(ctx context.Context, iss, sub string, expectedGeneration int64, st portal.RefreshState) error
	// Ref is a token's Reference, as idp_links stores it.
	Ref(token string) string
}

var _ LinkStore = (*portal.LinkStore)(nil)

// TokenClient is the IdP's token endpoint, called as the warden-portal
// client with grant_type=refresh_token. An error means no answer (transport
// failure, timeout, discovery not done yet); every HTTP answer is a Result.
// The error never carries the token.
type TokenClient interface {
	Refresh(ctx context.Context, refreshToken string) (Result, error)
}

// Defaults the controlplane does not override.
const (
	// DefaultFirstRunDelay is how long after Start the first run begins.
	DefaultFirstRunDelay = time.Minute
	// rotateAttempts bounds the Rotate retries while the rotated token is
	// held only in memory.
	rotateAttempts = 3
	// tokenReadAttempts bounds the re-reads of an inconsistent snapshot.
	tokenReadAttempts = 3
	// rotateTimeout bounds the rotation phase, which runs detached from the
	// run deadline: the IdP has already consumed the old token.
	rotateTimeout = 30 * time.Second
	// spreadFraction of the interval holds every link's refresh offset, so a
	// run ends well inside its interval/2 deadline.
	spreadNum, spreadDen = 2, 5
)

// Refresh statuses written to idp_links.last_refresh_status by the job
// (Rotate writes portal.RefreshStatusRotated itself).
const (
	refreshStatusOK     = "refreshed"
	refreshStatusFailed = "failed"
)

// Outcomes counted in warden_cp_offboarding_refresh_total{outcome}: the
// Class values plus the ones below.
const (
	// OutcomeStale: a portal login won the race; the verdict was dropped.
	OutcomeStale = "stale"
	// OutcomeStoreError: the token could not be read from consent.store.
	OutcomeStoreError = "store_error"
	// OutcomeInconsistent: the stored token and its row kept disagreeing.
	OutcomeInconsistent = "inconsistent"
	// OutcomeSkipped: offboarded, gone, or in a state only a login revives.
	OutcomeSkipped = "skipped"
)

// ErrPaused is RunOnce's answer while the job is paused by a config error.
var ErrPaused = errors.New("offboard: refresh job paused after offboarding_config_error")

// JobConfig builds a Job. Links, Client, Verifier, Now and After are
// required.
type JobConfig struct {
	Links    LinkStore
	Client   TokenClient
	Verifier identity.Verifier
	// Now and After are the control plane's clock (clock.Clock's Now and
	// After); tests drive them with a fake.
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
	// Leader defaults to AlwaysLeader.
	Leader Leader
	// Findings may be nil (Findings are dropped).
	Findings FindingPublisher
	// Metrics may be nil.
	Metrics *Metrics
	Logger  *slog.Logger
	// Mode is observe or enforce (enforce behaves as observe until
	// W-P3-OFFB-05); it labels the run log line.
	Mode           string
	Interval       time.Duration
	Concurrency    int
	RequestTimeout time.Duration
	MaxFailures    int
	ReauthWarning  time.Duration
	// FirstRunDelay defaults to DefaultFirstRunDelay.
	FirstRunDelay time.Duration
	// RotateBackoff is the wait between Rotate attempts (0: none).
	RotateBackoff time.Duration
}

// Job is the IdP refresh job. It has no Offboarder: in this ticket nothing
// it decides can offboard a user.
type Job struct {
	cfg    JobConfig
	leader Leader
	logger *slog.Logger
	paused atomic.Bool
}

// NewJob validates cfg and returns the job.
func NewJob(cfg JobConfig) (*Job, error) {
	switch {
	case cfg.Links == nil:
		return nil, errors.New("offboard: refresh job needs the link store")
	case cfg.Client == nil:
		return nil, errors.New("offboard: refresh job needs a token client")
	case cfg.Verifier == nil:
		return nil, errors.New("offboard: refresh job needs an ID token verifier")
	case cfg.Now == nil || cfg.After == nil:
		return nil, errors.New("offboard: refresh job needs a clock")
	case cfg.Interval <= 0 || cfg.Concurrency < 1 || cfg.RequestTimeout <= 0 || cfg.MaxFailures < 1 || cfg.ReauthWarning <= 0:
		return nil, errors.New("offboard: refresh job needs a positive interval, concurrency, request timeout, max failures and reauth warning")
	}
	if cfg.FirstRunDelay <= 0 {
		cfg.FirstRunDelay = DefaultFirstRunDelay
	}
	j := &Job{cfg: cfg, leader: cfg.Leader, logger: cfg.Logger}
	if j.leader == nil {
		j.leader = AlwaysLeader{}
	}
	if j.logger == nil {
		j.logger = slog.Default()
	}
	return j, nil
}

// Paused reports whether a 401 invalid_client paused the job.
func (j *Job) Paused() bool { return j.paused.Load() }

// Resume clears a config-error pause (a config reload that fixed the client).
func (j *Job) Resume() { j.paused.Store(false) }

// Start runs the job in a goroutine until ctx is done: the first run begins
// FirstRunDelay after Start, then one run per interval. In each run every
// link is refreshed at its own hash(iss, sub) offset inside the first 2/5 of
// the interval, with at most Concurrency refreshes in flight and a run
// deadline of interval/2.
func (j *Job) Start(ctx context.Context) {
	go j.loop(ctx)
}

func (j *Job) loop(ctx context.Context) {
	wait := j.cfg.FirstRunDelay
	for {
		select {
		case <-ctx.Done():
			return
		case <-j.cfg.After(wait):
		}
		start := j.cfg.Now()
		if !j.paused.Load() && j.leader.IsLeader(ctx) {
			if _, err := j.run(ctx, true); err != nil && !errors.Is(err, ErrPaused) && ctx.Err() == nil {
				j.logger.Warn("offboarding_job_run_failed", "error_type", fmt.Sprintf("%T", err))
			}
		}
		wait = j.cfg.Interval - j.cfg.Now().Sub(start)
		if wait <= 0 {
			wait = time.Second
		}
	}
}

// RunStats summarizes one run.
type RunStats struct {
	// Checked counts the links the run decided on (refreshed, or marked
	// reauth_required by date); Skipped the rest.
	Checked, OK, Transient, Expired, TokenLost, Suspect, Refused, ConfigError int
	Stale, StoreError, Inconsistent, Skipped                                  int
	// Issuers holds the per-issuer counts the issuer-wide Findings use.
	Issuers map[string]IssuerStats
}

// IssuerStats counts one issuer's refresh calls in a run.
type IssuerStats struct {
	// Attempted counts the token-endpoint calls; OK and Transient their
	// successful and transient results.
	Attempted, OK, Transient int
}

// RunOnce runs one run now, without the per-link offsets: every link is
// refreshed at once (bounded by Concurrency). Tests drive the job with it.
func (j *Job) RunOnce(ctx context.Context) (RunStats, error) {
	return j.run(ctx, false)
}

// outcome is one link's result in a run.
type outcome struct {
	iss, sub string
	name     string // the refresh_total outcome
	class    Class  // set when the token endpoint was called
	called   bool
	failures int64
}

func (j *Job) run(ctx context.Context, spread bool) (RunStats, error) {
	if j.paused.Load() {
		return RunStats{}, ErrPaused
	}
	start := j.cfg.Now()
	rctx, cancel := context.WithTimeout(ctx, j.cfg.Interval/2)
	defer cancel()
	links, err := j.cfg.Links.List(rctx)
	if err != nil {
		return RunStats{}, fmt.Errorf("offboard: list idp links: %w", err)
	}
	window := j.cfg.Interval * spreadNum / spreadDen
	if spread {
		sort.SliceStable(links, func(a, b int) bool {
			return offset(links[a], window) < offset(links[b], window)
		})
	}
	var (
		mu   sync.Mutex
		outs []outcome
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, j.cfg.Concurrency)
dispatch:
	for _, l := range links {
		if spread {
			if !j.waitUntil(rctx, start.Add(offset(l, window))) {
				break dispatch
			}
		}
		if j.paused.Load() {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-rctx.Done():
			break dispatch
		}
		wg.Add(1)
		go func(l portal.IdPLink) {
			defer wg.Done()
			defer func() { <-sem }()
			o := j.refreshOne(rctx, l)
			j.cfg.Metrics.incRefresh(o.name)
			mu.Lock()
			outs = append(outs, o)
			mu.Unlock()
		}(l)
	}
	wg.Wait()
	stats := j.finish(outs)
	end := j.cfg.Now()
	j.cfg.Metrics.setLastRun(end)
	j.logger.Info("offboarding_job_run", "mode", j.cfg.Mode,
		"checked", stats.Checked, "ok", stats.OK, "transient", stats.Transient, "expired", stats.Expired,
		"token_lost", stats.TokenLost, "suspect", stats.Suspect, "upstream_refused", stats.Refused,
		"stale", stats.Stale, "store_error", stats.StoreError, "skipped", stats.Skipped,
		"duration_ms", end.Sub(start).Milliseconds())
	return stats, nil
}

// offset is the link's place in the run: sha256(iss, sub) modulo the window.
func offset(l portal.IdPLink, window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(l.Iss + "\x00" + l.Sub))
	return time.Duration(binary.BigEndian.Uint64(sum[:8]) % uint64(window))
}

// waitUntil waits on the job's clock until at, or returns false when ctx ends.
func (j *Job) waitUntil(ctx context.Context, at time.Time) bool {
	d := at.Sub(j.cfg.Now())
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-j.cfg.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// finish counts the outcomes and publishes the run-level Findings: one
// idp_refresh_unavailable per issuer where more than half the calls were
// transient, and otherwise one idp_refresh_failing per user whose transient
// failures reached MaxFailures, only when the issuer also answered at least
// one refresh successfully in this run.
func (j *Job) finish(outs []outcome) RunStats {
	st := RunStats{Issuers: map[string]IssuerStats{}}
	for _, o := range outs {
		switch o.name {
		case string(ClassOK):
			st.OK++
		case string(ClassTransient):
			st.Transient++
		case string(ClassExpired):
			st.Expired++
		case string(ClassTokenLost):
			st.TokenLost++
		case string(ClassSuspect):
			st.Suspect++
		case string(ClassUpstreamRefused):
			st.Refused++
		case string(ClassConfigError):
			st.ConfigError++
		case OutcomeStale:
			st.Stale++
		case OutcomeStoreError:
			st.StoreError++
		case OutcomeInconsistent:
			st.Inconsistent++
		case OutcomeSkipped:
			st.Skipped++
		}
		if o.name != OutcomeSkipped {
			st.Checked++
		}
		if o.called {
			is := st.Issuers[o.iss]
			is.Attempted++
			switch o.class {
			case ClassOK:
				is.OK++
			case ClassTransient:
				is.Transient++
			}
			st.Issuers[o.iss] = is
		}
	}
	now := j.cfg.Now()
	issuers := make([]string, 0, len(st.Issuers))
	for iss := range st.Issuers {
		issuers = append(issuers, iss)
	}
	sort.Strings(issuers)
	for _, iss := range issuers {
		is := st.Issuers[iss]
		if is.Transient*2 > is.Attempted {
			j.publish(Finding{
				RuleID: RuleRefreshUnavailable, Severity: SeverityMedium,
				Summary:  "Most IdP refreshes in the last offboarding run failed with transient errors; link state is not being updated",
				Evidence: fmt.Sprintf("transient=%d attempted=%d", is.Transient, is.Attempted),
				DedupKey: RuleRefreshUnavailable + ":" + SubHash(iss), Ts: now,
			})
		}
	}
	for _, o := range outs {
		is := st.Issuers[o.iss]
		if o.class != ClassTransient || o.failures < int64(j.cfg.MaxFailures) || is.Transient*2 > is.Attempted || is.OK == 0 {
			continue
		}
		j.publish(Finding{
			RuleID: RuleRefreshFailing, Severity: SeverityMedium, Sub: o.sub,
			Summary:  "A user's IdP refresh keeps failing while other refreshes succeed",
			Evidence: fmt.Sprintf("consecutive_failures=%d", o.failures),
			DedupKey: RuleRefreshFailing + ":" + SubHash(o.sub), Ts: now,
		})
	}
	return st
}

func (j *Job) publish(f Finding) {
	if j.cfg.Findings != nil {
		j.cfg.Findings.PublishFinding(f)
	}
}

// terminal reports a state only a portal login revives: the job does not
// call the IdP for it.
func terminal(state string) bool {
	switch state {
	case portal.LinkReauthRequired, portal.LinkTokenLost, portal.LinkSuspect, portal.LinkOffboarded:
		return true
	}
	return false
}

// lifetimeState is active, or expiring within ReauthWarning of RelinkDueAt.
func (j *Job) lifetimeState(l portal.IdPLink, now time.Time) string {
	if !now.Before(l.RelinkDueAt.Add(-j.cfg.ReauthWarning)) {
		return portal.LinkExpiring
	}
	return portal.LinkActive
}

// refreshOne refreshes one link and records its state.
func (j *Job) refreshOne(ctx context.Context, listed portal.IdPLink) outcome {
	o := outcome{iss: listed.Iss, sub: listed.Sub, name: OutcomeSkipped}
	if !listed.OffboardedAt.IsZero() || terminal(listed.State) {
		return o
	}
	now := j.cfg.Now()
	if !now.Before(listed.RelinkDueAt) {
		return j.markDue(ctx, listed, now)
	}
	tok, row, name := j.readToken(ctx, listed)
	if name != "" {
		o.name = name
		return o
	}
	// The snapshot is authoritative; re-check what the listing showed.
	if !row.OffboardedAt.IsZero() || terminal(row.State) {
		return o
	}
	if !now.Before(row.RelinkDueAt) {
		return j.markDue(ctx, row, now)
	}
	cctx, cancel := context.WithTimeout(ctx, j.cfg.RequestTimeout)
	res, err := j.cfg.Client.Refresh(cctx, tok)
	cancel()
	o.called = true
	class, code := classifyResponse(res, err)
	var claims identity.Claims
	if class == ClassOK {
		claims, class, code = j.verify(ctx, row, res)
	}
	o.class = class
	now = j.cfg.Now()
	st := row.RefreshState()
	switch class {
	case ClassOK:
		return j.rotate(ctx, o, row, tok, res.RefreshToken, claims, now)
	case ClassConfigError:
		if j.paused.CompareAndSwap(false, true) {
			j.logger.Error("offboarding_config_error", "class", string(class))
			j.publish(Finding{
				RuleID: RuleConfigError, Severity: SeverityCritical,
				Summary:  "The IdP rejected the warden-portal client (invalid_client); the offboarding refresh job is paused until restart",
				Evidence: "status=401 error=invalid_client",
				DedupKey: RuleConfigError + ":" + SubHash(row.Iss), Ts: now,
			})
		}
		o.name = string(class)
		return o
	case ClassTransient, ClassUpstreamRefused:
		// No verdict on the user: count it and keep the lifetime state.
		st.ConsecutiveFailures++
		st.State = j.lifetimeState(row, now)
	case ClassExpired:
		st.State = portal.LinkReauthRequired
	case ClassTokenLost:
		st.State = portal.LinkTokenLost
	case ClassSuspect:
		st.State = portal.LinkSuspect
	}
	st.LastErrorCode, st.LastRefreshAt, st.LastRefreshStatus = code, now, refreshStatusFailed
	o.failures = st.ConsecutiveFailures
	o.name = j.record(ctx, row, st, string(class))
	if class == ClassTokenLost || class == ClassSuspect {
		j.logger.Warn("offboarding_refresh_"+string(class), "sub_hash", SubHash(row.Sub), "class", string(class), "code", code)
	}
	return o
}

// readToken takes the token + row snapshot, re-reading an inconsistent one
// (a split login write is never classified). A non-empty name is the outcome
// when no token is usable.
func (j *Job) readToken(ctx context.Context, l portal.IdPLink) (string, portal.IdPLink, string) {
	for range tokenReadAttempts {
		tok, row, err := j.cfg.Links.TokenAt(ctx, l.Iss, l.Sub)
		switch {
		case err == nil:
			return tok, row, ""
		case errors.Is(err, portal.ErrLinkInconsistent):
			continue
		case errors.Is(err, portal.ErrLinkNotFound):
			return "", portal.IdPLink{}, OutcomeSkipped
		default:
			j.logger.Warn("offboarding_token_read_failed", "sub_hash", SubHash(l.Sub), "error_type", fmt.Sprintf("%T", err))
			return "", portal.IdPLink{}, OutcomeStoreError
		}
	}
	j.logger.Warn("offboarding_token_inconsistent", "sub_hash", SubHash(l.Sub))
	return "", portal.IdPLink{}, OutcomeInconsistent
}

// markDue marks a link whose relink_due_at has passed reauth_required,
// without calling the IdP.
func (j *Job) markDue(ctx context.Context, l portal.IdPLink, now time.Time) outcome {
	o := outcome{iss: l.Iss, sub: l.Sub, name: string(ClassExpired), class: ClassExpired}
	st := l.RefreshState()
	st.State, st.LastErrorCode = portal.LinkReauthRequired, "relink_due"
	o.name = j.record(ctx, l, st, string(ClassExpired))
	return o
}

// verify checks the refreshed ID token: valid for the portal client (the
// Verifier pins iss and aud; no nonce on a refresh) and naming this row's
// issuer and subject.
func (j *Job) verify(ctx context.Context, row portal.IdPLink, res Result) (identity.Claims, Class, string) {
	if res.IDToken == "" {
		return identity.Claims{}, ClassSuspect, "id_token_missing"
	}
	claims, status, _ := j.cfg.Verifier.Verify(ctx, res.IDToken)
	switch status {
	case identity.StatusValid:
	case identity.StatusUnverified:
		// The keys could not be fetched. The IdP has already rotated the
		// token, but an unverified one is never written: the chain is lost.
		return identity.Claims{}, ClassTokenLost, "id_token_unverified"
	default:
		return identity.Claims{}, ClassSuspect, "id_token_invalid"
	}
	if claims.Issuer != row.Iss || claims.Sub != row.Sub {
		return identity.Claims{}, ClassSuspect, "sub_mismatch"
	}
	return claims, ClassOK, ""
}

// rotate writes a verified refresh back. Without a new refresh token (an IdP
// that does not rotate) only the state is written. Otherwise
// rotation_pending_ref is set first, then Rotate is tried up to three times
// while the token is held only in memory; a newer login (ErrStaleGeneration)
// drops it, and a final failure marks the link token_lost.
func (j *Job) rotate(ctx context.Context, o outcome, row portal.IdPLink, old, fresh string, claims identity.Claims, now time.Time) outcome {
	ok := func(st portal.RefreshState) portal.RefreshState {
		st.State = j.lifetimeState(row, now)
		st.LastOKAt, st.ConsecutiveFailures, st.LastErrorCode, st.RotationPendingRef = now, 0, "", ""
		if claims.Email != "" {
			st.Email = claims.Email
		}
		st.EmailVerified = claims.EmailVerified
		return st
	}
	if fresh == "" || fresh == old {
		st := ok(row.RefreshState())
		st.LastRefreshAt, st.LastRefreshStatus = now, refreshStatusOK
		o.name = j.record(ctx, row, st, string(ClassOK))
		return o
	}
	// The IdP has consumed the old token: finish the write even if the run
	// deadline passes.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rotateTimeout)
	defer cancel()
	pending := row.RefreshState()
	pending.RotationPendingRef = j.cfg.Links.Ref(fresh)
	if err := j.cfg.Links.SetState(wctx, row.Iss, row.Sub, row.Generation, pending); errors.Is(err, portal.ErrStaleGeneration) {
		o.name = OutcomeStale
		return o
	}
	var (
		rotated portal.IdPLink
		err     error
	)
	for attempt := range rotateAttempts {
		if attempt > 0 && j.cfg.RotateBackoff > 0 && !j.waitUntil(wctx, j.cfg.Now().Add(j.cfg.RotateBackoff)) {
			break
		}
		rotated, err = j.cfg.Links.Rotate(wctx, row.Iss, row.Sub, row.Generation, fresh)
		if err == nil || errors.Is(err, portal.ErrStaleGeneration) || errors.Is(err, portal.ErrLinkNotFound) {
			break
		}
	}
	switch {
	case err == nil:
		o.name = j.record(wctx, rotated, ok(rotated.RefreshState()), string(ClassOK))
		return o
	case errors.Is(err, portal.ErrStaleGeneration):
		o.name = OutcomeStale
		return o
	case errors.Is(err, portal.ErrLinkNotFound):
		o.name = OutcomeSkipped
		return o
	}
	j.logger.Warn("offboarding_rotate_failed", "sub_hash", SubHash(row.Sub), "class", string(ClassTokenLost), "error_type", fmt.Sprintf("%T", err))
	lost := row.RefreshState()
	lost.State, lost.LastErrorCode, lost.RotationPendingRef = portal.LinkTokenLost, "rotate_failed", ""
	lost.LastRefreshAt, lost.LastRefreshStatus = now, refreshStatusFailed
	o.class = ClassTokenLost
	o.name = j.record(wctx, row, lost, string(ClassTokenLost))
	return o
}

// record writes st for row (generation compare-and-swap) and returns the
// outcome name: name itself, or OutcomeStale when a login won. A move into
// expiring, reauth_required or token_lost publishes one
// offboarding_reauth_required Finding.
func (j *Job) record(ctx context.Context, row portal.IdPLink, st portal.RefreshState, name string) string {
	err := j.cfg.Links.SetState(ctx, row.Iss, row.Sub, row.Generation, st)
	switch {
	case errors.Is(err, portal.ErrStaleGeneration):
		return OutcomeStale
	case err != nil:
		j.logger.Warn("offboarding_state_write_failed", "sub_hash", SubHash(row.Sub), "error_type", fmt.Sprintf("%T", err))
		return name
	}
	if st.State != row.State {
		switch st.State {
		case portal.LinkExpiring, portal.LinkReauthRequired, portal.LinkTokenLost:
			j.publish(Finding{
				RuleID: RuleReauthRequired, Severity: SeverityMedium, Sub: row.Sub,
				Summary:  "A user must sign in to the consent portal again to keep their IdP link",
				Evidence: "link_state=" + st.State,
				// One per user, state and chain (a login starts a new window).
				DedupKey: fmt.Sprintf("%s:%s:%s:%d", RuleReauthRequired, SubHash(row.Sub), st.State, row.RelinkDueAt.Unix()),
				Ts:       j.cfg.Now(),
			})
		}
	}
	return name
}
