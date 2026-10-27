package controlplane

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// StateMigrations is every cpstate migration the control plane registers,
// whatever its config says, so switching a feature off never trips the
// downgrade guard. Run, the harness and the offline CLIs (through
// adminaudit.OpenForCLI) all open warden-cp.db with this one list; a feature
// that adds tables appends its migrations here.
func StateMigrations() []cpstate.Migration {
	migs := append(SessionMigrations(), OIDCPendingMigrations()...)
	migs = append(migs, adminaudit.Migrations()...)
	return append(migs, WorkerTokenMigrations()...)
}

// checkAdminAuditFlags validates the admin audit config against the flags
// before anything is opened: enabled needs a state dir, and the rotation flag
// is meaningless (so refused) with audit off.
func checkAdminAuditFlags(cc config.ConsoleConfig, stateDir string, p Params) error {
	if cc.AdminAudit.Enabled && stateDir == "" {
		return errors.New("control-plane: console.adminAudit.enabled needs --state-dir")
	}
	if !cc.AdminAudit.Enabled && p.AdminAuditNewSegment != "" {
		return fmt.Errorf("control-plane: %s needs console.adminAudit.enabled: true", adminaudit.NewSegmentFlag)
	}
	return nil
}

// openAdminAudit builds the admin audit store on the CP state database: it
// loads (or, on an empty chain, creates) the signing key and the HMAC key,
// runs the fail-closed key check, starts a new segment when asked, writes
// genesis on first use, and logs the key_id and public key. Key material is
// never logged.
func openAdminAudit(ctx context.Context, logger *slog.Logger, state *cpstate.DB, stateDir string, p Params, clk clock.Clock) (*adminaudit.Store, error) {
	keyFile := p.AdminAuditKeyFile
	if keyFile == "" {
		keyFile = adminaudit.DefaultKeyPath(stateDir)
	}
	keyFile = filepath.Clean(keyFile)
	s, err := adminaudit.Open(ctx, state, adminaudit.OpenOptions{
		KeyFile:    keyFile,
		NewSegment: p.AdminAuditNewSegment,
		Clock:      clk,
	})
	if err != nil {
		return nil, fmt.Errorf("control-plane: admin audit: %w", err)
	}
	logger.Info("admin audit enabled",
		"key_id", s.KeyID(),
		"public_key", base64.StdEncoding.EncodeToString(s.PublicKey()),
		"key_file", keyFile)
	return s, nil
}
