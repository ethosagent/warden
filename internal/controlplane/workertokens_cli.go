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
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Admin audit actions of the worker token CLI; the dashboard API records the
// same ones (target worker_tokens, target_ref token:<id>).
const (
	actionWorkerTokenCreate = "worker_token.create"
	actionWorkerTokenRevoke = "worker_token.revoke"
)

// OfflineWorkerTokens is the worker token store opened straight on
// <state-dir>/warden-cp.db for `warden control-plane token`, with the control
// plane running or stopped. A running control plane sees its writes through
// the store's data_version reload. The CLI stays thin (rule C1): validation,
// the audit row and the plaintext handling live here.
type OfflineWorkerTokens struct {
	db         *cpstate.DB
	st         *WorkerTokenStore
	rec        adminaudit.Recorder // nil: admin audit was never enabled here
	closeAudit func() error
	actor      string
}

// OpenWorkerTokensOffline opens the state dir read-write for create and
// revoke. The admin audit recorder is opened first, so a missing or
// mismatching key (with audit rows present) fails here, before anything is
// written. The database file is created when absent: the first tokens can be
// minted before the control plane has ever run. keyFile "" means
// <stateDir>/cp-audit.key.
func OpenWorkerTokensOffline(ctx context.Context, stateDir, keyFile string) (*OfflineWorkerTokens, error) {
	if stateDir == "" {
		return nil, errors.New("worker tokens: --state-dir is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("worker tokens: state dir: %w", err)
	}
	rec, closeAudit, err := adminaudit.OpenForCLI(ctx, stateDir, keyFile, StateMigrations())
	if err != nil {
		return nil, fmt.Errorf("admin audit: %w", err)
	}
	db, err := cpstate.Open(ctx, filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		if closeAudit != nil {
			_ = closeAudit()
		}
		return nil, err
	}
	return newOfflineWorkerTokens(db, rec, closeAudit)
}

// OpenWorkerTokensOfflineReadOnly opens the state dir for list: the database
// is opened read-only and never written or created.
func OpenWorkerTokensOfflineReadOnly(ctx context.Context, stateDir string) (*OfflineWorkerTokens, error) {
	if stateDir == "" {
		return nil, errors.New("worker tokens: --state-dir is required")
	}
	path := filepath.Join(stateDir, adminaudit.StateDBFileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("worker tokens: no control plane state database at %s: %w", path, err)
	}
	db, err := cpstate.OpenReadOnly(ctx, path, StateMigrations())
	if err != nil {
		return nil, err
	}
	return newOfflineWorkerTokens(db, nil, nil)
}

func newOfflineWorkerTokens(db *cpstate.DB, rec adminaudit.Recorder, closeAudit func() error) (*OfflineWorkerTokens, error) {
	st, err := NewWorkerTokenStore(db, StoreOptions{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		_ = db.Close()
		if closeAudit != nil {
			_ = closeAudit()
		}
		if strings.Contains(err.Error(), "no such table") {
			return nil, errors.New("worker tokens: the state database has no worker_tokens table (start the control plane with this --state-dir once, or run `token create`)")
		}
		return nil, err
	}
	return &OfflineWorkerTokens{db: db, st: st, rec: rec, closeAudit: closeAudit, actor: adminaudit.CLIActor()}, nil
}

// AuditEnabled reports whether create and revoke append admin audit rows.
func (o *OfflineWorkerTokens) AuditEnabled() bool { return o.rec != nil }

// Close releases both database handles.
func (o *OfflineWorkerTokens) Close() error {
	err := o.db.Close()
	if o.closeAudit != nil {
		if cerr := o.closeAudit(); err == nil {
			err = cerr
		}
	}
	return err
}

// OfflineCreate describes one `token create`.
type OfflineCreate struct {
	Name, ProxyID string
	ExpiresIn     time.Duration // 0: never expires
	// Plaintext, when set, is an imported value (--from-env, --from-file).
	Plaintext string
	// OutFile, when set, receives a generated plaintext with mode 0600.
	// Importing and OutFile are mutually exclusive.
	OutFile string
}

// OfflineCreateResult is the outcome of Create. Plaintext is set only for a
// generated token that was not written to OutFile.
type OfflineCreateResult struct {
	Token     Token
	Plaintext string
	// Unchanged: an import of a name and value that already exist (no row, no
	// audit entry).
	Unchanged bool
}

// Create mints or imports a token and appends the worker_token.create audit
// row. If the audit append fails the new token is revoked again, so no
// credential exists without its audit entry.
func (o *OfflineWorkerTokens) Create(ctx context.Context, c OfflineCreate) (OfflineCreateResult, error) {
	imported := c.Plaintext != ""
	if imported && c.OutFile != "" {
		return OfflineCreateResult{}, fmt.Errorf("%w: --out writes a generated token; it cannot be combined with an imported value", ErrInvalidInput)
	}
	opts := CreateOpts{Name: c.Name, ProxyID: c.ProxyID, Actor: o.actor, Plaintext: c.Plaintext}
	if c.ExpiresIn < 0 {
		return OfflineCreateResult{}, fmt.Errorf("%w: expiry is not in the future", ErrInvalidInput)
	}
	if c.ExpiresIn > 0 {
		opts.ExpiresAt = time.Now().Add(c.ExpiresIn)
	}
	existed := false
	if imported {
		toks, err := o.st.List(ctx)
		if err != nil {
			return OfflineCreateResult{}, err
		}
		for _, t := range toks {
			if t.Name == c.Name {
				existed = true
			}
		}
	}
	// Reserve the output file first, so a path that cannot be written never
	// leaves an unretrievable token behind.
	var out *os.File
	if c.OutFile != "" {
		f, err := os.OpenFile(c.OutFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return OfflineCreateResult{}, fmt.Errorf("worker tokens: --out: %w", err)
		}
		out = f
	}
	fail := func(err error) (OfflineCreateResult, error) {
		if out != nil {
			_ = out.Close()
			_ = os.Remove(c.OutFile)
		}
		return OfflineCreateResult{}, err
	}
	plaintext, tok, err := o.st.Create(ctx, opts)
	if err != nil {
		return fail(err)
	}
	if existed {
		// An import of an existing active name and value: nothing changed.
		return OfflineCreateResult{Token: tok, Unchanged: true}, nil
	}
	if err := o.record(ctx, actionWorkerTokenCreate, tok); err != nil {
		if rerr := o.st.Revoke(ctx, tok.ID, o.actor); rerr != nil {
			err = fmt.Errorf("%w (and revoking the unaudited token %s failed: %v)", err, tok.ID, rerr)
		}
		return fail(fmt.Errorf("worker tokens: admin audit append failed, token not kept: %w", err))
	}
	res := OfflineCreateResult{Token: tok}
	switch {
	case out != nil:
		_, werr := io.WriteString(out, plaintext+"\n")
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(c.OutFile)
			_ = o.st.Revoke(ctx, tok.ID, o.actor)
			return OfflineCreateResult{}, fmt.Errorf("worker tokens: write --out: %w (token %s was revoked)", werr, tok.ID)
		}
	case !imported:
		res.Plaintext = plaintext
	}
	return res, nil
}

// Revoke revokes a token and appends the worker_token.revoke audit row. It
// returns the token and changed=false, with no audit row, when it was already
// revoked. An unknown id is ErrWorkerTokenNotFound.
func (o *OfflineWorkerTokens) Revoke(ctx context.Context, id string) (tok Token, changed bool, err error) {
	toks, err := o.st.List(ctx)
	if err != nil {
		return Token{}, false, err
	}
	found := false
	for _, t := range toks {
		if t.ID == id {
			tok, found = t, true
		}
	}
	if !found {
		return Token{}, false, ErrWorkerTokenNotFound
	}
	if !tok.RevokedAt.IsZero() {
		return tok, false, nil
	}
	if err := o.st.Revoke(ctx, id, o.actor); err != nil {
		return Token{}, false, err
	}
	if err := o.record(ctx, actionWorkerTokenRevoke, tok); err != nil {
		return tok, true, fmt.Errorf("worker tokens: %s is revoked but the admin audit append failed: %w", id, err)
	}
	return tok, true, nil
}

// List returns every token's metadata, oldest first.
func (o *OfflineWorkerTokens) List(ctx context.Context) ([]Token, error) { return o.st.List(ctx) }

// record appends one audit row; details hold the id, name and binding only.
func (o *OfflineWorkerTokens) record(ctx context.Context, action string, t Token) error {
	if o.rec == nil {
		return nil
	}
	_, err := o.rec.Record(ctx, adminaudit.Input{
		Action:    action,
		Target:    auditTargetWorkerTokens,
		TargetRef: workerTokenRef(t.ID),
		Details:   map[string]string{"id": t.ID, "name": t.Name, "proxy_id": t.ProxyID},
		Outcome:   adminaudit.OutcomeOK,
	})
	return err
}

// tokenStatus is active, revoked or expired at now.
func tokenStatus(t Token, now time.Time) string {
	switch {
	case !t.RevokedAt.IsZero():
		return "revoked"
	case !t.ExpiresAt.IsZero() && !t.ExpiresAt.After(now):
		return "expired"
	}
	return "active"
}

// WriteWorkerTokenList prints toks as a table, or as the dashboard API's JSON
// shape with asJSON. Never a plaintext or hash.
func WriteWorkerTokenList(w io.Writer, toks []Token, asJSON bool) error {
	if asJSON {
		views := make([]map[string]string, 0, len(toks))
		for _, t := range toks {
			v := map[string]string{"id": t.ID, "name": t.Name, "proxyID": t.ProxyID, "createdBy": t.CreatedBy,
				"createdAt": rfc3339(t.CreatedAt), "status": tokenStatus(t, time.Now())}
			for k, ts := range map[string]time.Time{"expiresAt": t.ExpiresAt, "lastUsedAt": t.LastUsedAt, "revokedAt": t.RevokedAt} {
				if s := rfc3339(ts); s != "" {
					v[k] = s
				}
			}
			views = append(views, v)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(views)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tPROXY ID\tSTATUS\tCREATED\tEXPIRES\tLAST USED")
	dash := func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return rfc3339(t)
	}
	now := time.Now()
	for _, t := range toks {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.ProxyID, tokenStatus(t, now),
			rfc3339(t.CreatedAt), dash(t.ExpiresAt), dash(t.LastUsedAt))
	}
	return tw.Flush()
}
