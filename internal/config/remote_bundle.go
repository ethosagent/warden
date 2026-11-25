package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/keys"
)

// Signed bundles on the worker (W-P2-SBND-04). When SetBundleTrust has been
// called the provider asks the control plane for the signed envelope, verifies
// it with bundle.Verify before decoding anything, and applies a verified bundle
// as one snapshot. Without it none of this code runs and the request, the size
// limit and the parse path are the legacy ones.
//
// The rule that matters: once pins are set the provider never applies the
// unsigned wire. A legacy 200 is a rejection (unsigned), as is every other
// failure, and a rejection changes nothing that was applied, so the worker
// keeps enforcing its last-known-good policy (and a disabled agent stays
// disabled).

// BundleMediaType is the Accept header value that asks the control plane for
// the signed envelope. It must equal controlplane.BundleMediaType.
const BundleMediaType = "application/vnd.warden.bundle.v1+json"

// BundleSectionTokenJWKS is the bundle section that carries the token JWKS the
// worker verifies Warden tokens against (W-P2-WBND-01).
const BundleSectionTokenJWKS = "tokenJWKS"

// BundleReasonInvalidPolicy is the rejection reason for a bundle whose
// signature verified but whose policy bytes the worker cannot accept (a bad
// blocked-user or registeredAgents list, an invalid allowlist). It is in
// addition to the bundle.Reason values.
const BundleReasonInvalidPolicy = "invalid_policy"

// BundleRejectError is a rejected bundle response. It carries the reason, seq
// and kid only; Unwrap exposes the bundle error for errors.Is.
type BundleRejectError struct {
	Reason string
	Seq    int64
	KID    string
	err    error
}

func (e *BundleRejectError) Error() string {
	return "config: remote: bundle rejected (" + e.Reason + "): " + e.err.Error()
}
func (e *BundleRejectError) Unwrap() error { return e.err }

// IsBundleRejection reports whether err is a rejected bundle, which the
// provider has already logged.
func IsBundleRejection(err error) bool {
	var b *BundleRejectError
	return errors.As(err, &b)
}

// maxLoggedRejects bounds the set of rejections already warned about.
const maxLoggedRejects = 64

// BundleTrust is what a worker needs to verify bundles. The package reads no
// clock itself: Now is the worker's clock.
type BundleTrust struct {
	// Pins are the pinned bundle public keys (at least one).
	Pins []keys.JWK
	// Skew is the tolerance on issuedAt and expiresAt.
	Skew time.Duration
	// Issuer, when set, must equal the bundle's cpID.
	Issuer string
	// Expiry is what an expired applied bundle means (see BundleExpiryDeny).
	Expiry BundleExpiry
	// Now is the clock used for verification and expiry.
	Now func() time.Time
	// Logger receives one WARN per distinct rejection and one INFO per applied
	// bundle. nil logs nothing.
	Logger *slog.Logger
}

// VerifiedBundle is the verified bundle the provider currently enforces: the
// facts later tickets read (token verification, status reporting, the on-disk
// cache). It carries no policy and never the credential.
type VerifiedBundle struct {
	Seq int64
	// ID is the bundle's contentSha256, which names its content.
	ID  string
	KID string
	// CPID is the issuing control plane's id (the payload cpID).
	CPID      string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Sections are the signed payload's extra sections, by name (a copy).
	Sections map[string]json.RawMessage
}

// TokenJWKS returns the token JWKS section, nil when the bundle carries none.
func (v VerifiedBundle) TokenJWKS() json.RawMessage {
	return append(json.RawMessage(nil), v.Sections[BundleSectionTokenJWKS]...)
}

func (v VerifiedBundle) clone() VerifiedBundle {
	c := v
	c.Sections = make(map[string]json.RawMessage, len(v.Sections))
	for k, s := range v.Sections {
		c.Sections[k] = append(json.RawMessage(nil), s...)
	}
	return c
}

// BundleStatus is the worker's signed-bundle state in one value, for the
// metrics, heartbeat and fleet view (W-P2-SBND-05) and the expiry loop.
type BundleStatus struct {
	// Enabled is true when pins are set.
	Enabled bool
	// Applied is true once a bundle has been verified and applied.
	Applied bool
	// Seq, ID, KID, IssuedAt and ExpiresAt describe the applied bundle.
	Seq       int64
	ID        string
	KID       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Expired is true when the applied bundle is past expiresAt plus the skew.
	Expired bool
	// Expiry is the configured behaviour once the applied bundle expires.
	Expiry BundleExpiry
	// LastRejectReason is the reason of the newest rejection since the last
	// apply ("" when none): a bundle.Reason value or BundleReasonInvalidPolicy.
	LastRejectReason string
	// LastRejectAt is when the newest rejection happened (zero when none yet).
	// It is kept after a later apply, unlike LastRejectReason.
	LastRejectAt time.Time
	// PinnedKIDs are the kids of the pinned keys, in pin order.
	PinnedKIDs []string
	// Rejected counts rejections by reason since the provider was created.
	Rejected map[string]int64
}

// SetBundleTrust turns signed-bundle verification on. Call it before the first
// Pull. It fails on an empty pin set or a missing clock.
func (r *RemoteProvider) SetBundleTrust(t BundleTrust) error {
	if len(t.Pins) == 0 {
		return errors.New("config: remote: bundle trust needs at least one pinned key")
	}
	if t.Now == nil {
		return errors.New("config: remote: bundle trust needs a clock")
	}
	if t.Expiry == "" {
		t.Expiry = BundleExpiryKeep
	}
	t.Pins = append([]keys.JWK(nil), t.Pins...)
	r.mu.Lock()
	r.trust = &t
	r.mu.Unlock()
	return nil
}

// Bundle returns a copy of the verified bundle the provider enforces. ok is
// false when no pins are set or nothing has been verified yet, so a legacy-wire
// policy never exposes sections or token keys.
func (r *RemoteProvider) Bundle() (VerifiedBundle, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.trust == nil || r.bundle == nil {
		return VerifiedBundle{}, false
	}
	return r.bundle.clone(), true
}

// BundleStatus returns the signed-bundle state; the zero value (Enabled false)
// when no pins are set.
func (r *RemoteProvider) BundleStatus() BundleStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.trust == nil {
		return BundleStatus{}
	}
	st := BundleStatus{
		Enabled:          true,
		Expiry:           r.trust.Expiry,
		LastRejectReason: r.lastReject,
		LastRejectAt:     r.lastRejectAt,
		Rejected:         make(map[string]int64, len(r.rejects)),
	}
	for _, j := range r.trust.Pins {
		kid := j.Kid
		if kid == "" {
			kid, _ = keys.Thumbprint(j)
		}
		st.PinnedKIDs = append(st.PinnedKIDs, kid)
	}
	for k, n := range r.rejects {
		st.Rejected[k] = n
	}
	if b := r.bundle; b != nil {
		st.Applied = true
		st.Seq, st.ID, st.KID, st.IssuedAt, st.ExpiresAt = b.Seq, b.ID, b.KID, b.IssuedAt, b.ExpiresAt
		st.Expired = r.trust.Now().After(b.ExpiresAt.Add(r.trust.Skew))
	}
	return st
}

// applyBundleBody verifies and applies one 200 response body in bundle mode.
// It returns changed=true when the enforced policy changed. A rejection
// returns an error wrapping the bundle error and changes nothing applied.
func (r *RemoteProvider) applyBundleBody(t *BundleTrust, resp *http.Response) (bool, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, bundle.MaxEnvelopeBytes+1))
	if err != nil {
		return false, r.setErr(fmt.Errorf("config: remote: read body: %w", err))
	}
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)

	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.RLock()
	var applied bundle.State
	if b := r.bundle; b != nil {
		applied = bundle.State{Seq: b.Seq, ContentSHA256: b.ID, IssuedAt: b.IssuedAt}
	}
	r.mu.RUnlock()

	opt := bundle.Options{Now: t.Now(), Skew: t.Skew, Issuer: t.Issuer}
	v, err := bundle.Verify(body, t.Pins, applied, opt)
	switch {
	case errors.Is(err, bundle.ErrUnchanged):
		r.mu.Lock()
		r.pollETag = etag
		r.lastErr = nil
		r.mu.Unlock()
		return false, nil
	case err != nil:
		seq, kid, digest := bundle.FactsOf(err)
		return false, r.reject(t, err, bundle.Reason(err), seq, kid, digest, body, etag)
	}

	p, settings, perr := parseRemotePolicy(v.Bundle.Policy)
	if perr != nil {
		// The signature is good but the wire is not one this worker can
		// enforce (for example an invalid registeredAgents list): reject it
		// whole so the last-known-good policy, and a disabled agent, stay.
		// The decode error is dropped on purpose: it can quote ids and domains
		// from the payload, which belong in no log.
		return false, r.reject(t, errors.New("policy is not enforceable by this worker"), BundleReasonInvalidPolicy, v.Seq, v.KID, "", body, etag)
	}
	if c := v.Credentials; c != nil {
		// In memory only: the sidecar never reaches disk or a log.
		if settings == nil {
			settings = &SettingsWire{}
		}
		sec := SecretsSettings{}
		if settings.Secrets != nil {
			sec = *settings.Secrets
		}
		sec.AccessKeyID, sec.SecretAccessKey = c.AccessKeyID, c.SecretAccessKey
		settings.Secrets = &sec
	}
	vb := &VerifiedBundle{
		Seq: v.Seq, ID: v.ContentSHA256, KID: v.KID, CPID: v.Bundle.CPID,
		IssuedAt: v.Bundle.IssuedAt, ExpiresAt: v.Bundle.ExpiresAt,
		Sections: v.Bundle.Sections,
	}
	if v.Refresh {
		// Same content, newer issuedAt: only the validity window moves.
		r.mu.Lock()
		r.bundle = vb
		r.etag, r.pollETag = etag, etag
		r.lastErr, r.lastReject = nil, ""
		r.mu.Unlock()
		return false, nil
	}
	r.mu.Lock()
	r.policy, r.settings, r.bundle = p, settings, vb
	r.etag, r.pollETag = etag, etag
	r.lastErr, r.lastReject = nil, ""
	r.mu.Unlock()
	if t.Logger != nil {
		t.Logger.Info("bundle applied", "seq", v.Seq, "kid", v.KID)
	}
	return true, nil
}

// reject records a rejected response: nothing applied changes, the rejection
// is counted and warned about once per distinct (reason, digest), and the
// rejected ETag becomes the next long-poll's If-None-Match so the same bad
// bundle is not downloaded again. A "future" or "expired" bundle is the exception:
// both depend on the clock, which can move without the envelope changing, so
// it is fetched again.
func (r *RemoteProvider) reject(t *BundleTrust, err error, reason string, seq int64, kid, digest string, body []byte, etag string) error {
	if digest == "" {
		sum := sha256.Sum256(body)
		digest = hex.EncodeToString(sum[:8])
	}
	wrapped := &BundleRejectError{Reason: reason, Seq: seq, KID: kid, err: err}

	r.mu.Lock()
	r.lastErr = wrapped
	r.lastReject = reason
	if r.rejects == nil {
		r.rejects = map[string]int64{}
	}
	r.rejects[reason]++
	if !errors.Is(err, bundle.ErrFuture) && !errors.Is(err, bundle.ErrExpired) {
		r.pollETag = etag
	}
	r.lastRejectAt = t.Now()
	key := reason + "/" + digest
	first := !r.loggedRejects[key]
	if first {
		if len(r.loggedRejects) >= maxLoggedRejects {
			r.loggedRejects = nil
		}
		if r.loggedRejects == nil {
			r.loggedRejects = map[string]bool{}
		}
		r.loggedRejects[key] = true
	}
	r.mu.Unlock()
	if first && t.Logger != nil {
		t.Logger.Warn("bundle rejected; keeping last-known-good policy",
			"reason", reason, "seq", seq, "kid", kid, "digest", digest)
	}
	return wrapped
}
