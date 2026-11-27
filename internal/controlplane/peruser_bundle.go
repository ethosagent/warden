package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/config"
)

// The per-user signed-bundle sections (W-P3-PUS-08). With perUserSecrets
// enabled the envelope carries two sections beside tokenJWKS:
//   - perUserSecrets: the value-free mappings and workerCacheTTL
//     (bundle.PerUserSecretsSection), built from the CP-local block;
//   - userGrantEpochs: {userKey: epoch}, the revocation channel (grant_epochs.go).
//
// Both are absent when the block is absent or disabled, so the payload bytes,
// the content fingerprint, the publish log and the ETag are exactly what they
// were before this feature. They are never on the legacy wire: GET /policy
// without the bundle Accept header does not see them.

// perUserSource reads the live perUserSecrets block and re-checks it. The
// publisher calls both on every build, so a block that was edited in the served
// config (a settings write, an external edit, a restored copy) is never served
// before it passed the same checks the control plane runs at startup.
type perUserSource struct {
	// load returns the block as it stands in the served config now. The loader
	// validates an enabled block (validatePerUserSecrets).
	load func() (config.PerUserSecretsConfig, error)
	// check is checkPerUserSecretsStartup bound to this control plane's consent
	// store, token service and bundle mode. An enabled block it refuses is not
	// served.
	check func(config.PerUserSecretsConfig) error
}

// perUserState is what the publisher serves for the feature: the encoded
// perUserSecrets section (nil = the feature is off) and its workerCacheTTL.
// Guarded by policyServer.refreshMu.
type perUserState struct {
	raw json.RawMessage
	ttl time.Duration
}

// resolvePerUser reloads the block and updates b.pu. A block that cannot be read
// or does not pass the check leaves the last served state in place (never a
// section built from an unchecked block); a block that loads and is disabled or
// absent turns the feature off. The caller holds refreshMu.
func (ps *policyServer) resolvePerUser() {
	b := ps.bundles
	src := b.perUserSrc
	if src == nil || src.load == nil {
		return
	}
	cfg, err := src.load()
	if err != nil {
		b.logger.Warn("control plane: perUserSecrets could not be read; keeping the section last served", "error", boundedErr(err))
		return
	}
	if !cfg.Enabled {
		b.pu = perUserState{}
		return
	}
	if src.check == nil {
		b.logger.Error("control plane: perUserSecrets is enabled but this control plane has no startup check for it; not serving the section")
		return
	}
	if err := src.check(cfg); err != nil {
		b.logger.Error("control plane: perUserSecrets is enabled but does not pass the startup checks; keeping the section last served",
			"error", boundedErr(err))
		return
	}
	raw, err := perUserSectionJSON(cfg)
	if err != nil {
		b.logger.Error("control plane: perUserSecrets section not encoded; keeping the section last served", "error", boundedErr(err))
		return
	}
	b.pu = perUserState{raw: raw, ttl: cfg.WorkerCacheTTL}
}

// perUserSectionJSON encodes cfg as the perUserSecrets section. Slices are never
// null, so the section decodes the same everywhere.
func perUserSectionJSON(cfg config.PerUserSecretsConfig) (json.RawMessage, error) {
	sec := bundle.PerUserSecretsSection{
		WorkerCacheTTLSeconds: int(cfg.WorkerCacheTTL.Seconds()),
		Mappings:              make([]bundle.PerUserMappingSection, 0, len(cfg.Mappings)),
	}
	for _, m := range cfg.Mappings {
		sec.Mappings = append(sec.Mappings, bundle.PerUserMappingSection{
			Placeholder: m.Placeholder,
			Provider:    m.Provider,
			Scopes:      nonNil(m.Scopes),
			Domains:     nonNil(m.Domains),
			In:          nonNil(m.In),
			Agents:      nonNil(m.Agents),
		})
	}
	raw, err := json.Marshal(sec)
	if err != nil {
		return nil, fmt.Errorf("encode perUserSecrets: %w", err)
	}
	return raw, nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return append([]string(nil), v...)
}

// perUserFingerprint extends the content fingerprint fp with the per-user
// sections. It is called only when the feature is on, so a control plane
// without it keeps the fingerprint it persisted before this feature.
//
// The userGrantEpochs entries are fingerprinted by the newest epoch ever
// recorded (hwm), not by their list: every Bump takes a seq of its own and
// moves hwm, while a prune (which takes none) only drops entries older than
// 2 x workerCacheTTL, which no worker can still need, so a re-sign after a
// prune is the same content for the seq.
func perUserFingerprint(fp string, section json.RawMessage, hwm int64) string {
	h := sha256.New()
	_, _ = h.Write([]byte(fp))
	_, _ = h.Write([]byte("\x00perUserSecrets\x00"))
	_, _ = h.Write(section)
	_, _ = h.Write([]byte("\x00userGrantEpochs\x00" + strconv.FormatInt(hwm, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// perUserSections returns the sections to sign and the fingerprint input: both
// nil when the feature is off. The caller holds refreshMu.
func (ps *policyServer) perUserSections(ctx context.Context) (perUser, epochs json.RawMessage, hwm int64, err error) {
	b := ps.bundles
	if b.pu.raw == nil {
		return nil, nil, 0, nil
	}
	t := grantEpochTable{db: b.state.db}
	entries, err := t.all(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	if hwm, err = t.hwm(ctx); err != nil {
		return nil, nil, 0, err
	}
	epochs, err = epochSection(entries)
	if err != nil {
		return nil, nil, 0, err
	}
	return b.pu.raw, epochs, hwm, nil
}
