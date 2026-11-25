package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/keys"
)

// Staged bundle key rotation (W-P2-SBND-07). Workers pin bundle keys in static
// config, so a bundle key never rotates on a schedule. The operator moves it in
// steps, each safe on its own:
//
//  1. export the public JWKS (active and next) and pin it on every worker;
//  2. stage: the control plane signs every envelope with both keys, so a worker
//     that pins either one verifies it;
//  3. activate: the next key becomes the only signer and the old one stays
//     published for keys.bundle.overlap, refused unless every online worker
//     reports the next kid in its heartbeat pinnedKids (or --force);
//  4. drop the old pin from the workers once the overlap has passed.
//
// No step makes a worker accept a bundle signed only by a key it does not pin:
// verification is the worker's, against its own pins, and the control plane
// only ever adds a signature (stage) or stops adding one (activate, gated).

// ErrBundleKeyMissing is a staged-rotation command run against a state dir
// whose bundle purpose has no active key.
var ErrBundleKeyMissing = errors.New("keys: the bundle purpose has no key in this state dir")

// PinGateError is an activation refused because the worker pins could not be
// shown to cover the next key. Missing lists the proxy ids of the online
// workers that do not report NextKID in pinnedKids; it is empty when the pins
// could not be read at all (Cause says why).
type PinGateError struct {
	NextKID string
	Missing []string
	Cause   error
}

func (e *PinGateError) Error() string {
	if len(e.Missing) > 0 {
		return fmt.Sprintf("keys: refusing to activate bundle key %s: %d online worker(s) do not report it in pinnedKids: %s "+
			"(pin it on them, or --force to override and audit the override)", e.NextKID, len(e.Missing), strings.Join(e.Missing, ", "))
	}
	return fmt.Sprintf("keys: refusing to activate bundle key %s: the workers' pins could not be read (%v); "+
		"point --admin-url at the running control plane, or --force to override and audit the override", e.NextKID, e.Cause)
}

func (e *PinGateError) Unwrap() error { return e.Cause }

// PinReport is what the pin check found among the registered workers.
type PinReport struct {
	// Missing are the online, bundle-verifying workers that do not report the
	// kid: activating would leave them rejecting every bundle.
	Missing []string
	// Offline are known workers that were not heard from recently and do not
	// report the kid. They cannot be asked, so they do not block; they are
	// listed because they will reject bundles until pinned.
	Offline []string
	// Unpinned are online workers that advertise no bundle verification
	// (no pins): they apply the legacy wire and are not affected.
	Unpinned []string
	// Checked is how many online, bundle-verifying workers were examined.
	Checked int
}

// CheckBundlePins applies the activation rule to a fleet view: every online
// worker that verifies signed bundles (it advertises config.CapBundleV1, which
// it does only with pins) must report kid in its pinnedKids. A worker reports at
// most config.MaxHeartbeatPinnedKIDs kids, so an unlisted kid is read as
// missing: the check fails closed.
func CheckBundlePins(workers []dashboard.WorkerView, kid string) PinReport {
	var r PinReport
	for _, w := range workers {
		pinned := slices.Contains(w.PinnedKIDs, kid)
		verifies := slices.Contains(w.Caps, config.CapBundleV1)
		switch {
		case !w.Online && verifies && !pinned:
			r.Offline = append(r.Offline, w.ProxyID)
		case !w.Online:
		case !verifies:
			r.Unpinned = append(r.Unpinned, w.ProxyID)
		default:
			r.Checked++
			if !pinned {
				r.Missing = append(r.Missing, w.ProxyID)
			}
		}
	}
	slices.Sort(r.Missing)
	slices.Sort(r.Offline)
	slices.Sort(r.Unpinned)
	return r
}

// WorkersSource lists the fleet as the running control plane sees it: the
// heartbeat pins live in its memory, not in the state dir, so the activate gate
// reads them through the admin API.
type WorkersSource func(ctx context.Context) ([]dashboard.WorkerView, error)

// maxWorkersBody bounds the fleet list the gate reads.
const maxWorkersBody = 8 << 20

// AdminAPIWorkers returns a WorkersSource reading GET /dashboard/api/workers of
// the control plane at baseURL with an API key (scope traffic:read). caFile, if
// not empty, adds a PEM certificate authority to the system roots. The key is
// sent only in the Authorization header and never appears in an error.
func AdminAPIWorkers(baseURL, apiKey, caFile string) (WorkersSource, error) {
	if baseURL == "" || apiKey == "" {
		return nil, errors.New("keys: an admin URL and an API key are both needed to read the workers' pins")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("keys: read --ca-cert: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("keys: --ca-cert holds no PEM certificate")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	endpoint := strings.TrimRight(baseURL, "/") + "/dashboard/api/workers"
	return func(ctx context.Context) ([]dashboard.WorkerView, error) {
		defer tr.CloseIdleConnections()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, errors.New("keys: the admin URL is not valid")
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("keys: reach the control plane admin API: %s", errText(err))
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("keys: the admin API answered %d to GET /dashboard/api/workers (the API key needs the traffic:read scope)", resp.StatusCode)
		}
		var ws []dashboard.WorkerView
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxWorkersBody)).Decode(&ws); err != nil {
			return nil, errors.New("keys: the admin API's worker list is not valid JSON")
		}
		return ws, nil
	}, nil
}

// errText is err's text without the request URL, which may carry an operator's
// host but never the key (the key is a header); kept short for the audit row.
func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}

// Audit detail values for the bundle rotation steps. The row action is the
// rotation request's (keys.rotate_requested), the op detail tells the steps
// apart.
const (
	opBundleStage             = "stage"
	opBundleActivate          = "activate"
	opBundleEmergencyActivate = "emergency_activate"
)

// OfflineStageResult is the outcome of staging.
type OfflineStageResult struct {
	ActiveKID string
	NextKID   string
	// Already is set when the next key was staged before and nothing changed.
	Already bool
	// Created is set when no next key existed and one was generated.
	Created bool
}

// StageBundle starts a staged bundle key rotation: the control plane signs
// every envelope with both the active and the next key from the moment it
// picks the change up (within about 2 seconds), and a worker that pins either
// key verifies them. It changes nothing a worker can reject. One admin audit
// row names the kids; staging again is a no-op with no second row.
func (o *OfflineKeys) StageBundle(ctx context.Context) (OfflineStageResult, error) {
	actor := keys.Actor{Subject: adminaudit.CLIActor(), AuthMethod: adminaudit.AuthMethodCLI}
	res, err := o.mgr.StageBundle(ctx, actor)
	if err != nil {
		if errors.Is(err, keys.ErrNoActiveKey) {
			return OfflineStageResult{}, fmt.Errorf("%w: %w", ErrBundleKeyMissing, err)
		}
		return OfflineStageResult{}, err
	}
	out := OfflineStageResult{ActiveKID: res.ActiveKID, NextKID: res.NextKID, Already: res.Already, Created: res.Created}
	if res.Already {
		return out, nil
	}
	o.logger.Info("bundle key staged", "active_kid", out.ActiveKID, "staged_kid", out.NextKID, "created", out.Created)
	if err := o.record(ctx, actionKeysRotate, keys.PurposeBundle, map[string]string{
		adminaudit.DetailOp: opBundleStage, "purpose": keys.PurposeBundle, "kid": out.ActiveKID, "next_kid": out.NextKID,
	}); err != nil {
		return out, fmt.Errorf("keys: the bundle key %s is staged but the admin audit append failed: %w", out.NextKID, err)
	}
	return out, nil
}

// ActivateBundleOptions are the inputs of ActivateBundle.
type ActivateBundleOptions struct {
	// Workers reads the fleet's heartbeat pins. nil means they cannot be read:
	// the activation is refused unless Force is set.
	Workers WorkersSource
	// Force activates despite missing or unreadable pins, and writes what was
	// missing to the admin audit row.
	Force bool
	// Emergency promotes the next key at once and revokes the current one (a
	// compromise): it needs no stage and no prepublish wait, but the pin check
	// still applies — a worker that does not pin the next key is cut off.
	Emergency bool
}

// OfflineActivateResult is the outcome of an activation.
type OfflineActivateResult struct {
	// KID is the new signing key; Previous the key that stopped signing.
	KID, Previous string
	Emergency     bool
	// Forced is set when the pin gate was overridden; Report is what the check
	// found (zero when the pins were unreadable).
	Forced bool
	Report PinReport
	// PinsUnread is set when the pins could not be read and Force went on.
	PinsUnread bool
}

// ActivateBundle completes a staged bundle key rotation: it makes the staged
// next key the only signer and retires the old one, which stays published for
// keys.bundle.overlap. It is refused, listing the proxy ids, unless every
// online worker that verifies bundles reports the next kid in pinnedKids, and
// refused when the pins cannot be read; Force overrides both and records the
// missing ids in the one admin audit row it writes. A non-emergency activation
// also needs the key staged and its prepublish window (keys.bundle.prepublish,
// counted from the stage) served with both signatures.
func (o *OfflineKeys) ActivateBundle(ctx context.Context, opt ActivateBundleOptions) (OfflineActivateResult, error) {
	rows, err := o.Rows(ctx, keys.PurposeBundle)
	if err != nil {
		return OfflineActivateResult{}, err
	}
	var active, next keys.Record
	for _, r := range rows {
		switch r.State {
		case keys.StateActive:
			active = r
		case keys.StateNext:
			next = r
		}
	}
	switch {
	case active.KID == "":
		return OfflineActivateResult{}, ErrBundleKeyMissing
	case next.KID == "":
		return OfflineActivateResult{}, fmt.Errorf("%w: stage first (it creates the next key)", keys.ErrNoNextKey)
	}
	if _, staged := keys.StagedNext(rows); !staged && !opt.Emergency {
		return OfflineActivateResult{}, fmt.Errorf("%w (next key %s)", keys.ErrNotStaged, next.KID)
	}

	res := OfflineActivateResult{KID: next.KID, Previous: active.KID, Emergency: opt.Emergency}
	gate, err := o.pinGate(ctx, next.KID, opt)
	res.Report, res.PinsUnread = gate.report, gate.unread
	if err != nil {
		return res, err
	}
	res.Forced = gate.forced

	actor := keys.Actor{Subject: adminaudit.CLIActor(), AuthMethod: adminaudit.AuthMethodCLI}
	rotErr := o.mgr.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{Emergency: opt.Emergency, ConfirmPinned: true, Actor: actor})
	stood := errors.Is(rotErr, keys.ErrRotationStood)
	if rotErr != nil && !stood {
		return res, rotErr
	}
	o.logger.Info("bundle key activated", "kid", next.KID, "previous_kid", active.KID, "emergency", opt.Emergency, "forced", res.Forced)

	op := opBundleActivate
	if opt.Emergency {
		op = opBundleEmergencyActivate
	}
	details := map[string]string{
		adminaudit.DetailOp: op, "purpose": keys.PurposeBundle, "kid": next.KID, "previous_kid": active.KID,
	}
	if res.Forced {
		details["forced"] = "true"
		if len(res.Report.Missing) > 0 {
			details["missing"] = boundDetail(strings.Join(res.Report.Missing, ","))
		}
		if res.PinsUnread {
			details["pins_unverified"] = "true"
		}
	}
	if len(res.Report.Offline) > 0 {
		details["offline_missing"] = boundDetail(strings.Join(res.Report.Offline, ","))
	}
	outcome := adminaudit.OutcomeOK
	if stood {
		outcome = adminaudit.OutcomeError
		details["stood"] = "true"
		details["error"] = boundDetail(rotErr.Error())
	}
	if recErr := o.recordOutcome(ctx, actionKeysRotate, keys.PurposeBundle, details, outcome); recErr != nil {
		if stood {
			return res, fmt.Errorf("%w (the admin audit append failed too: %v)", rotErr, recErr)
		}
		return res, fmt.Errorf("keys: bundle key %s is active but the admin audit append failed: %w", next.KID, recErr)
	}
	return res, rotErr
}

// pinGateResult is the outcome of the pin check.
type pinGateResult struct {
	report PinReport
	forced bool
	unread bool
}

// pinGate applies the activation rule to nextKID. It returns a *PinGateError
// when the activation must not go on. With Force a failing gate is overridden
// and reported in the result, to be written to the audit row.
func (o *OfflineKeys) pinGate(ctx context.Context, nextKID string, opt ActivateBundleOptions) (pinGateResult, error) {
	var res pinGateResult
	var workers []dashboard.WorkerView
	var readErr error
	if opt.Workers == nil {
		readErr = errors.New("no --admin-url given")
	} else {
		workers, readErr = opt.Workers(ctx)
	}
	if readErr != nil {
		if !opt.Force {
			return res, &PinGateError{NextKID: nextKID, Cause: readErr}
		}
		res.forced, res.unread = true, true
		return res, nil
	}
	res.report = CheckBundlePins(workers, nextKID)
	if len(res.report.Missing) > 0 {
		if !opt.Force {
			return res, &PinGateError{NextKID: nextKID, Missing: res.report.Missing}
		}
		res.forced = true
	}
	return res, nil
}
