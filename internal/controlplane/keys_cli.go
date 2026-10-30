package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/filestore"
	"github.com/ethosagent/warden/internal/keys/adapters/metastore"
)

// Admin audit actions of the keys CLI; the console's rotate route records the
// same rotation action (target keys, target_ref keys:<purpose>).
const (
	actionKeysRotate = "keys.rotate_requested"
	actionKeysReset  = "keys.reset"
)

// StagedRotationError is a `keys rotate --purpose bundle` refusal: workers pin
// bundle keys out of band, so a rotation is a staged operator flow — export the
// next key, pin it on every worker, and only then activate (W-P2-SBND-07 adds
// the --stage/--activate flow). NextKID is the key to pin; it is empty when the
// purpose has no next key yet.
type StagedRotationError struct {
	Purpose string
	NextKID string
}

func (e *StagedRotationError) Error() string {
	if e.NextKID == "" {
		return "keys: " + e.Purpose + " rotation is staged and no next key is published yet; " +
			"start the control plane with keys.enabled to publish one, then pin it on every worker"
	}
	return "keys: " + e.Purpose + " rotation is staged: pin the next key " + e.NextKID +
		" on every worker before activating (docs/runbooks/key-rotation.md)"
}

// KeysCLIOptions are the inputs the keys CLI commands share.
type KeysCLIOptions struct {
	// ConfigPath is --config ("" = the keys defaults: the file store under
	// <state-dir>/keys and the default rotation timings). Like the control
	// plane, only the operator-owned file is read, never the served copy.
	ConfigPath string
	// Clock is the time source (nil: the real clock). The control plane
	// injects its own — in the L1 harness the fake one — so the CLI's
	// prepublish and overlap windows are measured on the same clock as the
	// rows the running manager wrote.
	Clock clock.Clock
	// AuditKeyFile is the admin audit signing key ("" =
	// <state-dir>/cp-audit.key).
	AuditKeyFile string
}

// OfflineKeys is the signing-key CLI's handle on a state dir: the state
// database's signing_keys table and the private-key store opened directly, so
// `warden control-plane keys` works with the control plane running or stopped.
// A running control plane picks a rotation or reset up within about 2 seconds
// through the metadata store's data-version poll. Only Reset may run against a
// live control plane's dir: it takes the instance lock and refuses while the
// control plane holds it.
type OfflineKeys struct {
	db         *cpstate.DB
	meta       keys.MetaStore
	mgr        *keys.Manager
	rec        adminaudit.Recorder // nil: admin audit was never enabled here
	closeAudit func() error
	kc         config.KeysConfig
	clk        clock.Clock
	stateDir   string
}

// OpenKeysOffline opens the state dir read-write for rotate and reset. The
// state database must exist and hold the signing_keys table: the control
// plane creates both, and a keys CLI run against anything else would work on
// timings and a key directory that are not the control plane's.
func OpenKeysOffline(ctx context.Context, stateDir string, opt KeysCLIOptions) (*OfflineKeys, error) {
	return openKeys(ctx, stateDir, opt, false)
}

// OpenKeysOfflineReadOnly opens the state dir for list and export: the
// database is opened read-only and never written or created.
func OpenKeysOfflineReadOnly(ctx context.Context, stateDir string, opt KeysCLIOptions) (*OfflineKeys, error) {
	return openKeys(ctx, stateDir, opt, true)
}

func openKeys(ctx context.Context, stateDir string, opt KeysCLIOptions, readOnly bool) (*OfflineKeys, error) {
	if stateDir == "" {
		return nil, errors.New("keys: --state-dir is required")
	}
	dbPath := filepath.Join(stateDir, adminaudit.StateDBFileName)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("keys: no control plane state database at %s (start the control plane with --state-dir and keys.enabled once): %w", dbPath, err)
	}
	kc, err := resolveKeys(opt.ConfigPath, stateDir)
	if err != nil {
		return nil, err
	}
	if kc.Store.Backend != config.KeysBackendFile {
		return nil, fmt.Errorf("keys: the CLI supports the %q store backend, not %q", config.KeysBackendFile, kc.Store.Backend)
	}
	var db *cpstate.DB
	var rec adminaudit.Recorder
	var closeAudit func() error
	if readOnly {
		db, err = cpstate.OpenReadOnly(ctx, dbPath, StateMigrations())
	} else {
		// The admin audit recorder is opened first, so a missing or
		// mismatching key (with audit rows present) fails here, before
		// anything is written.
		rec, closeAudit, err = adminaudit.OpenForCLI(ctx, stateDir, opt.AuditKeyFile, StateMigrations())
		if err != nil {
			return nil, fmt.Errorf("admin audit: %w", err)
		}
		db, err = cpstate.Open(ctx, dbPath, StateMigrations())
	}
	if err != nil {
		if closeAudit != nil {
			_ = closeAudit()
		}
		return nil, err
	}
	fail := func(err error) error {
		_ = db.Close()
		if closeAudit != nil {
			_ = closeAudit()
		}
		return err
	}
	if !tableExists(ctx, db.SQL(), "signing_keys") {
		return nil, fail(errors.New("keys: the state database has no signing_keys table (the control plane has not run here with keys.enabled)"))
	}
	store, err := filestore.New(kc.Store.File.Dir)
	if err != nil {
		return nil, fail(err)
	}
	clk := opt.Clock
	if clk == nil {
		clk = clock.Real()
	}
	mgr, err := newKeyManager(kc, db, store, clk, slog.New(slog.DiscardHandler), rec, nil)
	if err != nil {
		return nil, fail(err)
	}
	return &OfflineKeys{
		db: db, meta: metastore.New(db), mgr: mgr, rec: rec, closeAudit: closeAudit,
		kc: kc, clk: clk, stateDir: stateDir,
	}, nil
}

// AuditEnabled reports whether rotate and reset append admin audit rows.
func (o *OfflineKeys) AuditEnabled() bool { return o.rec != nil }

// Close releases every handle.
func (o *OfflineKeys) Close() error {
	err := o.db.Close()
	if o.closeAudit != nil {
		if cerr := o.closeAudit(); err == nil {
			err = cerr
		}
	}
	return err
}

// List returns every signing_keys row, oldest first: public metadata only,
// never key material.
func (o *OfflineKeys) List(ctx context.Context) ([]keys.Record, error) { return o.meta.List(ctx) }

// Rows returns one purpose's rows, oldest first.
func (o *OfflineKeys) Rows(ctx context.Context, purpose string) ([]keys.Record, error) {
	all, err := o.meta.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("keys: list signing keys: %w", err)
	}
	var out []keys.Record
	for _, r := range all {
		if r.Purpose == purpose {
			out = append(out, r)
		}
	}
	return out, nil
}

// JWKS rebuilds the published key set of purpose from the stored rows — the
// document a verifier fetching /.well-known/jwks.json holds (token), or the
// keys an operator pins (bundle). It needs no running control plane and
// carries public members only.
func (o *OfflineKeys) JWKS(ctx context.Context, purpose string) (keys.JWKS, error) {
	rows, err := o.Rows(ctx, purpose)
	if err != nil {
		return keys.JWKS{}, err
	}
	return keys.PublishedJWKS(rows, o.clk.Now(), o.overlapOf(purpose)), nil
}

func (o *OfflineKeys) overlapOf(purpose string) (overlap time.Duration) {
	switch purpose {
	case keys.PurposeToken:
		return o.kc.Token.Overlap
	case keys.PurposeBundle:
		return o.kc.Bundle.Overlap
	default:
		return 0
	}
}

// OfflineRotateResult is the outcome of a rotation: the purpose's new active
// key.
type OfflineRotateResult struct {
	Purpose   string
	KID       string
	Emergency bool
}

// Rotate promotes purpose's next key — at once, past its prepublish window,
// when emergency is set, revoking the previous key instead of retiring it. The
// manager applies the state changes as compare-and-swap writes, so a rotation
// that races the running control plane's own scheduler loses cleanly instead
// of forking the lifecycle. The bundle purpose is always refused: its rotation
// is staged (StagedRotationError). One admin audit row names the request; the
// manager's own rows name each transition. A rotation whose promotion
// committed but whose fresh next key could not be published (ErrRotationStood)
// stands anyway — the old key left the slot (revoked under --emergency,
// retired otherwise): the result still says what the rotation changed, and the
// audit row is appended with outcome error and the failure text — a refused
// rotation, which changed nothing, appends none. The row is also appended when
// the post-commit read-back of the rows fails, before that error is returned.
func (o *OfflineKeys) Rotate(ctx context.Context, purpose string, emergency bool) (OfflineRotateResult, error) {
	if purpose == keys.PurposeBundle {
		rows, err := o.Rows(ctx, purpose)
		if err != nil {
			return OfflineRotateResult{}, err
		}
		e := &StagedRotationError{Purpose: purpose}
		for _, r := range rows {
			if r.State == keys.StateNext {
				e.NextKID = r.KID
			}
		}
		return OfflineRotateResult{}, e
	}
	actor := keys.Actor{Subject: adminaudit.CLIActor(), AuthMethod: adminaudit.AuthMethodCLI}
	if err := o.mgr.Rotate(ctx, purpose, keys.RotateOpts{Emergency: emergency, Actor: actor}); err != nil {
		// A standing rotation changed the rows, so its audit row must exist
		// even though the command fails: it is the operator's record that the
		// compromised key was revoked, with the error as the outcome.
		if errors.Is(err, keys.ErrRotationStood) {
			res := o.activeResult(ctx, purpose, emergency)
			if recErr := o.recordOutcome(ctx, actionKeysRotate, purpose, map[string]string{
				"purpose": purpose, "kid": res.KID, "emergency": fmt.Sprintf("%t", emergency),
				"stood": "true", "error": boundDetail(err.Error()),
			}, adminaudit.OutcomeError); recErr != nil {
				return res, fmt.Errorf("%w (the admin audit append failed too: %v)", err, recErr)
			}
			return res, err
		}
		return OfflineRotateResult{}, err
	}
	rows, readErr := o.Rows(ctx, purpose)
	res := OfflineRotateResult{Purpose: purpose, Emergency: emergency}
	for _, r := range rows { // nil when the read-back failed
		if r.State == keys.StateActive {
			res.KID = r.KID
		}
	}
	// The rotation stands; a failed audit append is reported, not rolled back
	// (a rotation cannot be un-rotated). The row is appended even when the
	// read-back above failed: the request applied, whatever the rows say now.
	if err := o.record(ctx, actionKeysRotate, purpose, map[string]string{
		"purpose": purpose, "kid": res.KID, "emergency": fmt.Sprintf("%t", emergency),
	}); err != nil {
		return res, fmt.Errorf("keys: %s rotation to %s is applied but the admin audit append failed: %w", purpose, res.KID, err)
	}
	if readErr != nil {
		return OfflineRotateResult{}, fmt.Errorf("keys: the %s rotation is applied but its rows could not be read back: %w", purpose, readErr)
	}
	return res, nil
}

// activeResult reads the purpose's active kid after a write. Best effort: an
// empty KID says only that the rows could not be read back.
func (o *OfflineKeys) activeResult(ctx context.Context, purpose string, emergency bool) OfflineRotateResult {
	res := OfflineRotateResult{Purpose: purpose, Emergency: emergency}
	if rows, err := o.Rows(ctx, purpose); err == nil {
		for _, r := range rows {
			if r.State == keys.StateActive {
				res.KID = r.KID
			}
		}
	}
	return res
}

// OfflineResetResult is the outcome of a reset: how many rows the purpose had
// and the fresh active key, when one was generated.
type OfflineResetResult struct {
	Purpose string
	Removed int
	KID     string // the new active key (token and bundle); empty for ca
}

// Reset replaces purpose's keys after a restore that lost their material. It
// takes the state dir's instance lock first and refuses while a control plane
// holds it: a live control plane must never see a purpose half-reset. One
// admin audit row names the request; the manager's own rows name the fresh
// keys. A reset whose row delete committed but whose material delete or
// regeneration failed partially applied: the result still says how many rows
// were removed, and the audit row is appended with outcome error and the
// failure text.
func (o *OfflineKeys) Reset(ctx context.Context, purpose string) (OfflineResetResult, error) {
	release, err := cpstate.AcquireDirLock(o.stateDir)
	if errors.Is(err, cpstate.ErrLocked) {
		return OfflineResetResult{}, fmt.Errorf("control plane is running; stop it before resetting its signing keys")
	}
	if err != nil {
		return OfflineResetResult{}, err
	}
	defer func() { _ = release() }()
	actor := keys.Actor{Subject: adminaudit.CLIActor(), AuthMethod: adminaudit.AuthMethodCLI}
	res, err := o.mgr.Reset(ctx, purpose, actor)
	if err != nil {
		// Removed > 0 is the manager's evidence the row delete committed: the
		// reset partially applied, so its audit row must exist even though the
		// command fails, with the error as the outcome.
		if res.Removed > 0 {
			out := OfflineResetResult{Purpose: purpose, Removed: res.Removed}
			if recErr := o.recordOutcome(ctx, actionKeysReset, purpose, map[string]string{
				"purpose": purpose, "removed": fmt.Sprintf("%d", out.Removed), "error": boundDetail(err.Error()),
			}, adminaudit.OutcomeError); recErr != nil {
				return out, fmt.Errorf("%w (the admin audit append failed too: %v)", err, recErr)
			}
			return out, err
		}
		return OfflineResetResult{}, err
	}
	out := OfflineResetResult{Purpose: purpose, Removed: res.Removed, KID: res.ActiveKID}
	if err := o.record(ctx, actionKeysReset, purpose, map[string]string{
		"purpose": purpose, "kid": out.KID, "removed": fmt.Sprintf("%d", out.Removed),
	}); err != nil {
		return out, fmt.Errorf("keys: %s reset to %s is applied but the admin audit append failed: %w", purpose, out.KID, err)
	}
	return out, nil
}

// boundDetail fits a detail value inside the chain's per-value limit: the row
// keeps the head of a free-form text (an error's own words, whole runes only —
// a split one would not be valid UTF-8), the command's output the whole text.
func boundDetail(s string) string {
	if len(s) <= adminaudit.MaxDetailValueLen {
		return s
	}
	for len(s) > adminaudit.MaxDetailValueLen-3 {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s + "..."
}

// record appends one audit row with outcome ok; the details name the purpose
// and kid only, never key material. Without an admin audit chain the caller
// prints a notice instead.
func (o *OfflineKeys) record(ctx context.Context, action, purpose string, details map[string]string) error {
	return o.recordOutcome(ctx, action, purpose, details, adminaudit.OutcomeOK)
}

// recordOutcome is record with an explicit outcome: the ok rows name completed
// requests, the error rows name one that partially applied. The details are
// public metadata — a purpose, a kid, a count, an error's own text — never key
// material.
func (o *OfflineKeys) recordOutcome(ctx context.Context, action, purpose string, details map[string]string, outcome string) error {
	if o.rec == nil {
		return nil
	}
	_, err := o.rec.Record(ctx, adminaudit.Input{
		Action:    action,
		Target:    auditTargetKeys,
		TargetRef: "keys:" + purpose,
		Details:   details,
		Outcome:   outcome,
	})
	return err
}

// WriteKeysList renders signing-key rows for the CLI: the console API's
// KeyView shape as JSON, or a table. Public metadata only, never key material.
func WriteKeysList(w io.Writer, rows []keys.Record, asJSON bool) error {
	views := make([]dashboard.KeyView, 0, len(rows))
	for _, r := range rows {
		views = append(views, keyView(r))
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(views)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "KID\tPURPOSE\tSTATE\tALG\tCREATED\tPUBLISHED\tACTIVATED\tCREATED BY")
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	for _, r := range rows {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.KID, r.Purpose, string(r.State), r.Alg,
			dash(rfc3339(r.CreatedAt)), dash(rfc3339(r.PublishAt)), dash(rfc3339(r.ActivateAt)), r.CreatedBy)
	}
	return tw.Flush()
}

// WriteKeysJWKS writes published JWKS documents: the one document for purpose
// when it names one, otherwise a document per purpose that has keys.
func WriteKeysJWKS(w io.Writer, docs map[string]keys.JWKS, purpose string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if purpose != "" {
		doc, ok := docs[purpose]
		if !ok {
			return fmt.Errorf("keys: no published keys for %s", purpose)
		}
		return enc.Encode(doc)
	}
	return enc.Encode(docs)
}
