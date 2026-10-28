package controlplane

import (
	"context"
	"os"
	"slices"
	"sync"

	"github.com/ethosagent/warden/internal/adminaudit"
)

// File-mode external edits (W-P1-AAUD-08). In --policy-store=file mode the CP
// serves the YAML on disk and re-reads it every policyReloadInterval, so
// anyone with write access to it can change policy without an admin request.
// Each CP writer records the sha256 of the bytes it wrote; a re-read that
// finds a hash no CP writer produced appends one config.external_change row.
// Only hashes are recorded or logged, never the file's content, path or diff.
const (
	actionConfigExternalChange = "config.external_change"
	externalChangeTarget       = "policy"
	externalChangeActor        = "system"
	// externalSeenMax bounds the per-process set of after hashes already
	// recorded, so the same content is not recorded twice.
	externalSeenMax = 64
)

// externalEdits tracks the served file's hashes. mu is held across a CP
// writer's rename and across the re-read's file read, so the re-read never
// sees a CP write before its hash is recorded.
type externalEdits struct {
	mu          sync.Mutex
	lastWritten string // sha256 of the bytes the last CP writer renamed into place
	lastLoaded  string // sha256 of the served file at the last re-read

	auditMu sync.Mutex
	seen    []string // after hashes recorded, oldest first, at most externalSeenMax
}

// persist renames tmp (holding data) over dst and records data's hash as the
// last CP write.
func (x *externalEdits) persist(tmp, dst string, data []byte) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	x.lastWritten = sha256Hex(string(data))
	return nil
}

// observe hashes the served file. It reports a change when the hash differs
// from the last re-read and from the last CP write; a change clears the CP
// write so reverting a hand edit to the CP's bytes is caught too. An
// unreadable file reports nothing (Refresh already logs it).
func (x *externalEdits) observe(path string) (before, after string, external bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	sum := sha256Hex(string(data))
	if sum == x.lastLoaded {
		return "", "", false
	}
	before, x.lastLoaded = x.lastLoaded, sum
	if sum == x.lastWritten {
		return "", "", false
	}
	x.lastWritten = ""
	return before, sum, true
}

// primeExternalEdit records the served file's hash at startup, so the first
// re-read compares against what the CP began serving.
func (s *Server) primeExternalEdit() {
	s.ext.observe(s.cfg.PolicyPath)
}

// reloadPolicy is one tick of the policy re-read: reload the served policy
// (served exactly as before). In file mode it then audits a change no CP
// writer made. In versioned mode the file is not served, so the mirror's
// drift check (checkMirror, W-P1-PVER-05) replaces that check.
func (s *Server) reloadPolicy(ctx context.Context) {
	s.policy.Refresh()
	if s.versions != nil {
		s.checkMirror(ctx)
		return
	}
	if s.auditRec == nil {
		return
	}
	if before, after, ok := s.ext.observe(s.cfg.PolicyPath); ok {
		s.auditExternalChange(ctx, externalChangeTarget, "file:"+before, "file:"+after)
	}
}

// auditExternalChange appends one config.external_change row (actor and
// auth_method system) for a change to target that no admin request made.
// before and after are "<source>:<sha256>" state hashes: file:<hash> in file
// mode; W-P1-PVER-05 passes v<head>:<doc_sha256> as before. It is a no-op
// with admin audit disabled, records each distinct after hash once (within the
// last externalSeenMax), and logs a Recorder error at ERROR without retrying.
func (s *Server) auditExternalChange(ctx context.Context, target, before, after string) {
	if s.auditRec == nil {
		return
	}
	s.ext.auditMu.Lock()
	defer s.ext.auditMu.Unlock()
	if slices.Contains(s.ext.seen, after) {
		return
	}
	_, err := s.auditRec.Record(ctx, adminaudit.Input{
		Actor:      adminaudit.Actor{Sub: externalChangeActor},
		ActorRole:  externalChangeActor,
		AuthMethod: adminaudit.AuthMethodSystem,
		Action:     actionConfigExternalChange,
		Target:     target,
		Outcome:    adminaudit.OutcomeOK,
		BeforeHash: before,
		AfterHash:  after,
	})
	if err != nil {
		s.cfg.Logger.Error("control plane: admin audit of an external config change failed",
			"before_hash", before, "after_hash", after, "error", err)
		return
	}
	if len(s.ext.seen) == externalSeenMax {
		s.ext.seen = slices.Delete(s.ext.seen, 0, 1)
	}
	s.ext.seen = append(s.ext.seen, after)
	s.cfg.Logger.Warn("control plane: served config changed outside the control plane",
		"before_hash", before, "after_hash", after)
}
