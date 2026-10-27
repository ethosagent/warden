package controlplane

// policycli.go is the business side of `warden policy import` and `warden
// policy export` (W-P1-PVER-06). The commands open the CP state DB directly,
// with the control plane running or stopped: import goes through the same
// compare-and-swap Create as the CP, so a running CP serves the new head on its
// next reload tick, and appends its admin audit row itself because no HTTP
// middleware sees it. cmd/proxy only parses flags and prints.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// actionPolicyImport is the admin audit action of a CLI import.
const actionPolicyImport = "policy.import"

// PolicyDoc is a validated policy doc (policy, settings and llmProviders)
// loaded from a config YAML file, its credential already replaced by the
// fingerprint. Build it with ValidatePolicyDocFile.
type PolicyDoc struct {
	path string
	wire policyWire
}

// ValidatePolicyDocFile loads the config YAML at path with the strict config
// loader (unknown keys are errors), projects it to a policy doc the way the
// served YAML is projected, replaces the credential with its fingerprint and
// checks the doc with validateDoc against the file itself. An error names the
// file and carries the loader message only, never a credential value.
func ValidatePolicyDocFile(path string) (PolicyDoc, error) {
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		return PolicyDoc{}, fmt.Errorf("policy file %s: %w", path, err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		return PolicyDoc{}, fmt.Errorf("policy file %s: %w", path, err)
	}
	doc := RedactCredentials(policyWire{
		Allowlist: p.Allowlist,
		Denylist:  p.Denylist,
		Settings:  config.SettingsWireFromPolicy(p),
	})
	if err := validateDocAgainst(path, "", doc); err != nil {
		return PolicyDoc{}, fmt.Errorf("policy file %s: %w", path, err)
	}
	return PolicyDoc{path: path, wire: doc}, nil
}

// OfflinePolicyStore is the versioned policy store of a state dir, opened by
// an offline CLI. Close it when done.
type OfflinePolicyStore struct {
	db         *cpstate.DB
	st         *sqlitePolicyStore
	stateDir   string
	servedPath string
}

// OpenPolicyStore opens the versioned policy store in <stateDir>/warden-cp.db
// for writing, with the control plane's full migration list. The store must
// already exist (a control plane of this build has run with --state-dir);
// otherwise it is an error and nothing is created.
func OpenPolicyStore(ctx context.Context, stateDir string) (*OfflinePolicyStore, error) {
	return openOfflinePolicyStore(ctx, stateDir, false)
}

// OpenPolicyStoreReadOnly is OpenPolicyStore for readers: the database is
// opened read-only and never written.
func OpenPolicyStoreReadOnly(ctx context.Context, stateDir string) (*OfflinePolicyStore, error) {
	return openOfflinePolicyStore(ctx, stateDir, true)
}

func openOfflinePolicyStore(ctx context.Context, stateDir string, readOnly bool) (*OfflinePolicyStore, error) {
	if stateDir == "" {
		return nil, errors.New("policy store: --state-dir is required")
	}
	path := filepath.Join(stateDir, adminaudit.StateDBFileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("policy store: no control plane state database at %s (start the control plane with --state-dir %s once): %w",
			path, stateDir, err)
	}
	// Probe read-only first so a state dir without the store is left untouched.
	if err := checkPolicyStoreTables(ctx, path); err != nil {
		return nil, err
	}
	var (
		db  *cpstate.DB
		err error
	)
	if readOnly {
		db, err = cpstate.OpenReadOnly(ctx, path, StateMigrations())
	} else {
		db, err = cpstate.Open(ctx, path, StateMigrations())
	}
	if err != nil {
		return nil, err
	}
	o := &OfflinePolicyStore{
		db:         db,
		st:         newSQLitePolicyStore(db.SQL(), time.Now, slog.New(slog.DiscardHandler)),
		stateDir:   stateDir,
		servedPath: filepath.Join(stateDir, "config.yaml"),
	}
	if _, err := os.Stat(o.servedPath); err == nil {
		// Record the ETag the CP will serve, as the CP does: the credential
		// overlay puts the served YAML's live value back.
		cred := credentialOverlay(o.servedPath)
		o.st.etagOf = func(ctx context.Context, doc policyWire) (string, error) {
			w := doc
			if _, err := cred.apply(ctx, &w); err != nil {
				return "", err
			}
			return etagFor(w), nil
		}
	}
	return o, nil
}

// checkPolicyStoreTables reports an error unless the database at path holds
// the policy store tables.
func checkPolicyStoreTables(ctx context.Context, path string) error {
	ro, err := cpstate.OpenReadOnly(ctx, path, StateMigrations())
	if err != nil {
		return err
	}
	defer func() { _ = ro.Close() }()
	var n int
	if err := ro.SQL().QueryRowContext(ctx,
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('policy_versions', 'policy_head')").Scan(&n); err != nil {
		return fmt.Errorf("policy store: inspect %s: %w", path, err)
	}
	if n != 2 {
		return fmt.Errorf("policy store: %s has no versioned policy store (start a control plane of this version with --state-dir once)", path)
	}
	return nil
}

// Close closes the database.
func (o *OfflinePolicyStore) Close() error { return o.db.Close() }

// Head returns the head version; 0 means the store is empty.
func (o *OfflinePolicyStore) Head(ctx context.Context) (int64, error) { return o.st.Head(ctx) }

// PolicyImportResult is what an import did. Changed is false when the doc
// equals the head's (Version is then the head).
type PolicyImportResult struct {
	Version, Parent int64
	Changed         bool
}

// Import stores doc as a new version authored adminaudit.CLIActor() (kind
// cli, source import) if the head is still expectedHead (a negative value
// means the current head), then appends a policy.import admin audit row
// through rec (nil skips it). The doc is first checked with validateDoc
// against the served config in the state dir when there is one, as the CP
// checks its writes. A moved head returns an error wrapping ErrConflict that
// names the current head; nothing is written.
func (o *OfflinePolicyStore) Import(ctx context.Context, doc PolicyDoc, msg string, expectedHead int64, rec adminaudit.Recorder) (PolicyImportResult, error) {
	if _, err := os.Stat(o.servedPath); err == nil {
		if err := validateDocAgainst(o.servedPath, o.stateDir, doc.wire); err != nil {
			return PolicyImportResult{}, fmt.Errorf("policy file %s does not validate against the served config %s: %w", doc.path, o.servedPath, err)
		}
		if err := o.checkCredential(ctx, doc); err != nil {
			return PolicyImportResult{}, err
		}
	}
	if expectedHead < 0 {
		head, err := o.st.Head(ctx)
		if err != nil {
			return PolicyImportResult{}, err
		}
		expectedHead = head
	}
	if msg == "" {
		msg = "import from " + doc.path
	}
	author := PolicyAuthor{Sub: adminaudit.CLIActor(), Kind: AuthorKindCLI}
	version, changed, err := o.st.Create(ctx, doc.wire, author, msg, SourceImport, expectedHead)
	if errors.Is(err, ErrConflict) {
		head, herr := o.st.Head(ctx)
		if herr != nil {
			return PolicyImportResult{}, err
		}
		return PolicyImportResult{}, fmt.Errorf("%w: the head is now v%d (expected v%d); nothing was imported", ErrConflict, head, expectedHead)
	}
	if err != nil {
		return PolicyImportResult{}, err
	}
	if !changed {
		return PolicyImportResult{Version: version, Parent: version}, nil
	}
	res := PolicyImportResult{Version: version, Parent: expectedHead, Changed: true}
	if rec == nil {
		return res, nil
	}
	if err := o.recordImport(ctx, rec, expectedHead, version); err != nil {
		return res, fmt.Errorf("version %d was created but its admin audit row was not appended: %w", version, err)
	}
	return res, nil
}

// checkCredential refuses a doc whose credential fingerprint differs from the
// served config's live value. A version keeps only the fingerprint and the
// control plane serves the served config's value, so importing a rotated
// credential would silently drop it. Only fingerprints are compared or named.
func (o *OfflinePolicyStore) checkCredential(ctx context.Context, doc PolicyDoc) error {
	w := doc.wire
	if w.Settings == nil || w.Settings.Secrets == nil || !isRedactedCredential(w.Settings.Secrets.SecretAccessKey) {
		return nil
	}
	want := w.Settings.Secrets.SecretAccessKey
	live, err := credentialOverlay(o.servedPath).apply(ctx, &w)
	if err != nil {
		return fmt.Errorf("policy import: read the served config %s: %w", o.servedPath, err)
	}
	if live != want {
		return fmt.Errorf("policy file %s: secretStore.aws.secretAccessKey (%s) differs from the served config %s (%s); "+
			"a policy version stores only the fingerprint, so change the credential in the served config instead",
			doc.path, want, o.servedPath, fingerprintOrNone(live))
	}
	return nil
}

func fingerprintOrNone(fp string) string {
	if fp == "" {
		return "none"
	}
	return fp
}

// recordImport appends the policy.import admin audit row: before
// v<parent>:<doc_sha256> (empty for an empty store), after
// v<version>:<doc_sha256>.
func (o *OfflinePolicyStore) recordImport(ctx context.Context, rec adminaudit.Recorder, parent, version int64) error {
	before := ""
	if parent > 0 {
		pv, err := o.st.Get(ctx, parent)
		if err != nil {
			return err
		}
		before = fmt.Sprintf("v%d:%s", pv.Version, pv.DocSHA256)
	}
	nv, err := o.st.Get(ctx, version)
	if err != nil {
		return err
	}
	_, err = rec.Record(ctx, adminaudit.Input{
		Action:     actionPolicyImport,
		Target:     auditTargetPolicy,
		Outcome:    adminaudit.OutcomeOK,
		BeforeHash: before,
		AfterHash:  fmt.Sprintf("v%d:%s", nv.Version, nv.DocSHA256),
	})
	return err
}

// PolicyExport is an exported version: the config YAML and what was left out.
type PolicyExport struct {
	Version int64
	YAML    []byte
	// CredentialOmitted is set when the version carried an AWS credential
	// (stored as its fingerprint): secretStore.aws.accessKeyId and
	// secretAccessKey are left out so the file loads; re-add them by hand.
	CredentialOmitted bool
}

// Export renders version (0 = the head) as a config YAML holding its policy,
// settings and llmProviders blocks, the same encoders the CP writes the served
// YAML with. The credential fingerprint is never written. The result is
// checked with the config loader, so it always loads.
func (o *OfflinePolicyStore) Export(ctx context.Context, version int64) (PolicyExport, error) {
	if version <= 0 {
		head, err := o.st.Head(ctx)
		if err != nil {
			return PolicyExport{}, err
		}
		if head == 0 {
			return PolicyExport{}, errors.New("policy store: the store is empty; nothing to export")
		}
		version = head
	}
	v, err := o.st.Get(ctx, version)
	if err != nil {
		return PolicyExport{}, err
	}
	doc, omitted := withoutCredential(v.Doc)
	root := map[string]yaml.Node{}
	if err := renderDocToRoot(root, doc); err != nil {
		return PolicyExport{}, err
	}
	tmpName, err := writeValidatedTempIn("", root)
	if err != nil {
		return PolicyExport{}, fmt.Errorf("policy store: version %d does not render as a loadable config: %w", version, err)
	}
	_ = os.Remove(tmpName)
	body, err := yaml.Marshal(root)
	if err != nil {
		return PolicyExport{}, fmt.Errorf("policy store: marshal version %d: %w", version, err)
	}
	header := fmt.Sprintf("# warden policy export: version %d (doc_sha256 %s)\n", v.Version, v.DocSHA256)
	return PolicyExport{Version: v.Version, YAML: append([]byte(header), body...), CredentialOmitted: omitted}, nil
}

// withoutCredential returns doc with the AWS credential pair removed, and
// whether there was one. doc is not modified.
func withoutCredential(doc policyWire) (policyWire, bool) {
	if doc.Settings == nil || doc.Settings.Secrets == nil || doc.Settings.Secrets.SecretAccessKey == "" {
		return doc, false
	}
	settings := *doc.Settings
	secrets := *settings.Secrets
	secrets.SecretAccessKey = ""
	secrets.AccessKeyID = ""
	settings.Secrets = &secrets
	doc.Settings = &settings
	return doc, true
}
