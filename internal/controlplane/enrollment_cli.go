package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Admin audit target and actions of the enrollment token CLI; the admin API of
// W-P2-WCA-08 records the same ones.
const (
	auditTargetWorkerEnrollments = "worker_enrollments"
	actionEnrollTokenCreate      = "worker_enroll_token.create"
	actionEnrollTokenRevoke      = "worker_enroll_token.revoke"
)

// OfflineEnrollTokens is the enrollment token store opened straight on
// <state-dir>/warden-cp.db for `warden control-plane enroll-token`, with the
// control plane running or stopped (a running one sees the write within about
// 2 s through the data_version reload). The CLI stays thin (rule C1): the
// validation, the audit row and the plaintext handling live here.
type OfflineEnrollTokens struct {
	db         *cpstate.DB
	st         *EnrollmentStore
	rec        adminaudit.Recorder // nil: admin audit was never enabled here
	closeAudit func() error
	actor      string
}

// OpenEnrollTokensOffline opens the state dir read-write for create and
// revoke; see OpenWorkerTokensOffline for the audit and file rules. The TTLs
// are workerCA.enrollTokenTTL and enrollTokenMaxTTL (0 for the defaults).
func OpenEnrollTokensOffline(ctx context.Context, stateDir, keyFile string, defaultTTL, maxTTL time.Duration) (*OfflineEnrollTokens, error) {
	if stateDir == "" {
		return nil, errors.New("enrollment tokens: --state-dir is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("enrollment tokens: state dir: %w", err)
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
	return newOfflineEnrollTokens(db, rec, closeAudit, defaultTTL, maxTTL)
}

// OpenEnrollTokensOfflineReadOnly opens the state dir for list: read-only,
// never written or created.
func OpenEnrollTokensOfflineReadOnly(ctx context.Context, stateDir string) (*OfflineEnrollTokens, error) {
	if stateDir == "" {
		return nil, errors.New("enrollment tokens: --state-dir is required")
	}
	path := filepath.Join(stateDir, adminaudit.StateDBFileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("enrollment tokens: no control plane state database at %s: %w", path, err)
	}
	db, err := cpstate.OpenReadOnly(ctx, path, StateMigrations())
	if err != nil {
		return nil, err
	}
	return newOfflineEnrollTokens(db, nil, nil, 0, 0)
}

func newOfflineEnrollTokens(db *cpstate.DB, rec adminaudit.Recorder, closeAudit func() error, defaultTTL, maxTTL time.Duration) (*OfflineEnrollTokens, error) {
	st, err := NewEnrollmentStore(db, EnrollmentOptions{Logger: slog.New(slog.DiscardHandler), DefaultTTL: defaultTTL, MaxTTL: maxTTL})
	if err != nil {
		_ = db.Close()
		if closeAudit != nil {
			_ = closeAudit()
		}
		if strings.Contains(err.Error(), "no such table") {
			return nil, errors.New("enrollment tokens: the state database has no worker_enroll_tokens table (start the control plane with this --state-dir once, or run `enroll-token create`)")
		}
		return nil, err
	}
	return &OfflineEnrollTokens{db: db, st: st, rec: rec, closeAudit: closeAudit, actor: adminaudit.CLIActor()}, nil
}

// AuditEnabled reports whether create and revoke append admin audit rows.
func (o *OfflineEnrollTokens) AuditEnabled() bool { return o.rec != nil }

// Close releases both database handles.
func (o *OfflineEnrollTokens) Close() error {
	err := o.db.Close()
	if o.closeAudit != nil {
		if cerr := o.closeAudit(); err == nil {
			err = cerr
		}
	}
	return err
}

// OfflineEnrollCreate describes one `enroll-token create`.
type OfflineEnrollCreate struct {
	// Name is optional: an import defaults to enroll-<binding> (so running the
	// same command twice is a no-op), a minted token to that plus a random
	// suffix.
	Name           string
	WorkerID       string
	WorkerIDPrefix string
	MaxUses        int
	ExpiresIn      time.Duration // 0: workerCA.enrollTokenTTL
	// Plaintext, when set, is an imported value (--from-env, --from-file).
	Plaintext string
	// OutFile receives a minted plaintext with mode 0600. Not with an import.
	OutFile string
}

// OfflineEnrollResult is the outcome of Create. Plaintext is set only for a
// minted token that was not written to OutFile.
type OfflineEnrollResult struct {
	Token     EnrollToken
	Plaintext string
	// Unchanged: an import of a name and value that already exist (no row, no
	// audit entry).
	Unchanged bool
}

// Create mints or imports a token and appends the create audit row. If the
// audit append fails the new token is revoked again, so no credential exists
// without its audit entry.
func (o *OfflineEnrollTokens) Create(ctx context.Context, c OfflineEnrollCreate) (OfflineEnrollResult, error) {
	imported := c.Plaintext != ""
	if imported && c.OutFile != "" {
		return OfflineEnrollResult{}, fmt.Errorf("%w: --out writes a minted token; it cannot be combined with an imported value", ErrInvalidInput)
	}
	if c.ExpiresIn < 0 {
		return OfflineEnrollResult{}, fmt.Errorf("%w: expiry is not in the future", ErrInvalidInput)
	}
	name := c.Name
	if name == "" {
		name = defaultEnrollName(c.WorkerID, c.WorkerIDPrefix)
		if !imported {
			var b [3]byte
			if _, err := rand.Read(b[:]); err != nil {
				return OfflineEnrollResult{}, err
			}
			name = truncName(name, maxWorkerTokenName-7) + "-" + hex.EncodeToString(b[:])
		}
	}
	// Reserve the output file first, so a path that cannot be written never
	// leaves an unretrievable token behind.
	var out *os.File
	if c.OutFile != "" {
		f, err := os.OpenFile(c.OutFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return OfflineEnrollResult{}, fmt.Errorf("enrollment tokens: --out: %w", err)
		}
		out = f
	}
	fail := func(err error) (OfflineEnrollResult, error) {
		if out != nil {
			_ = out.Close()
			_ = os.Remove(c.OutFile)
		}
		return OfflineEnrollResult{}, err
	}
	plaintext, tok, created, err := o.st.Create(ctx, EnrollCreateOpts{
		Name: name, WorkerID: c.WorkerID, WorkerIDPrefix: c.WorkerIDPrefix, MaxUses: c.MaxUses,
		TTL: c.ExpiresIn, Actor: o.actor, Plaintext: c.Plaintext,
	})
	if err != nil {
		return fail(err)
	}
	if !created {
		return OfflineEnrollResult{Token: tok, Unchanged: true}, nil
	}
	if err := o.record(ctx, actionEnrollTokenCreate, tok); err != nil {
		if rerr := o.st.Revoke(ctx, tok.ID, o.actor); rerr != nil {
			err = fmt.Errorf("%w (and revoking the unaudited token %s failed: %v)", err, tok.ID, rerr)
		}
		return fail(fmt.Errorf("enrollment tokens: admin audit append failed, token not kept: %w", err))
	}
	res := OfflineEnrollResult{Token: tok}
	switch {
	case out != nil:
		_, werr := io.WriteString(out, plaintext+"\n")
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(c.OutFile)
			_ = o.st.Revoke(ctx, tok.ID, o.actor)
			return OfflineEnrollResult{}, fmt.Errorf("enrollment tokens: write --out: %w (token %s was revoked)", werr, tok.ID)
		}
	case !imported:
		res.Plaintext = plaintext
	}
	return res, nil
}

// Revoke revokes a token and appends the revoke audit row. It returns
// changed=false, with no audit row, when the token was already revoked; an
// unknown id is ErrEnrollNotFound.
func (o *OfflineEnrollTokens) Revoke(ctx context.Context, id string) (tok EnrollToken, changed bool, err error) {
	toks, err := o.st.List(ctx)
	if err != nil {
		return EnrollToken{}, false, err
	}
	found := false
	for _, t := range toks {
		if t.ID == id {
			tok, found = t, true
		}
	}
	if !found {
		return EnrollToken{}, false, ErrEnrollNotFound
	}
	if !tok.RevokedAt.IsZero() {
		return tok, false, nil
	}
	if err := o.st.Revoke(ctx, id, o.actor); err != nil {
		return EnrollToken{}, false, err
	}
	if err := o.record(ctx, actionEnrollTokenRevoke, tok); err != nil {
		return tok, true, fmt.Errorf("enrollment tokens: %s is revoked but the admin audit append failed: %w", id, err)
	}
	return tok, true, nil
}

// List returns every token's metadata, oldest first.
func (o *OfflineEnrollTokens) List(ctx context.Context) ([]EnrollToken, error) { return o.st.List(ctx) }

// record appends one audit row; details hold the id, name and binding only.
func (o *OfflineEnrollTokens) record(ctx context.Context, action string, t EnrollToken) error {
	if o.rec == nil {
		return nil
	}
	d := map[string]string{"id": t.ID, "name": t.Name, "max_uses": strconv.Itoa(t.MaxUses)}
	if t.WorkerID != "" {
		d["worker_id"] = t.WorkerID
	} else {
		d["worker_id_prefix"] = t.WorkerIDPrefix
	}
	_, err := o.rec.Record(ctx, adminaudit.Input{
		Action: action, Target: auditTargetWorkerEnrollments, TargetRef: "enroll_token:" + t.ID,
		Details: d, Outcome: adminaudit.OutcomeOK,
	})
	return err
}

// defaultEnrollName is enroll-id-<id> or enroll-prefix-<prefix>, so an id and a
// prefix that spell alike never collide. A binding too long for the 64
// character name limit is cut and followed by a hash of the whole binding.
func defaultEnrollName(workerID, prefix string) string {
	kind, v := "id", workerID
	if workerID == "" {
		kind, v = "prefix", prefix
	}
	name := "enroll-" + kind + "-" + v
	if len(name) <= maxWorkerTokenName {
		return name
	}
	sum := sha256.Sum256([]byte(kind + "\x00" + v))
	return truncName(name, maxWorkerTokenName-9) + "-" + hex.EncodeToString(sum[:4])
}

func truncName(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// EnrollStatus is active, used up, expired or revoked at now.
func EnrollStatus(t EnrollToken, now time.Time) string {
	return enrollStatus(t, now)
}

func enrollStatus(t EnrollToken, now time.Time) string {
	switch {
	case !t.RevokedAt.IsZero():
		return "revoked"
	case !now.Before(t.ExpiresAt):
		return "expired"
	case t.Uses >= t.MaxUses:
		return "used up"
	}
	return "active"
}

// WriteEnrollTokenList prints toks as a table, or as JSON with asJSON. Never a
// plaintext or hash.
func WriteEnrollTokenList(w io.Writer, toks []EnrollToken, asJSON bool) error {
	now := time.Now()
	if asJSON {
		views := make([]map[string]any, 0, len(toks))
		for _, t := range toks {
			v := map[string]any{"id": t.ID, "name": t.Name, "maxUses": t.MaxUses, "uses": t.Uses, "createdBy": t.CreatedBy,
				"createdAt": rfc3339(t.CreatedAt), "expiresAt": rfc3339(t.ExpiresAt), "status": enrollStatus(t, now)}
			if t.WorkerID != "" {
				v["workerId"] = t.WorkerID
			} else {
				v["workerIdPrefix"] = t.WorkerIDPrefix
			}
			if s := rfc3339(t.RevokedAt); s != "" {
				v["revokedAt"] = s
			}
			views = append(views, v)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(views)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tWORKER\tUSES\tSTATUS\tCREATED\tEXPIRES")
	for _, t := range toks {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d/%d\t%s\t%s\t%s\n", t.ID, t.Name, t.Binding(), t.Uses, t.MaxUses,
			enrollStatus(t, now), rfc3339(t.CreatedAt), rfc3339(t.ExpiresAt))
	}
	return tw.Flush()
}
