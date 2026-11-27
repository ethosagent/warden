package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
// section built from an unchecked block) and marks the feature stale (/healthz,
// one log line per transition); a block that loads and is disabled or absent
// turns the feature off. When a newly served mapping adds an agent whose
// connected worker lacks usersecrets/v1 it logs one WARN naming the workers (a
// file edit cannot be refused the way WritePerUserSecrets can). The caller holds
// refreshMu.
func (ps *policyServer) resolvePerUser() {
	b := ps.bundles
	src := b.perUserSrc
	if src == nil || src.load == nil {
		return
	}
	cfg, err := src.load()
	if err != nil {
		b.puStale("the block could not be read", err)
		return
	}
	if !cfg.Enabled {
		b.pu, b.puPairs = perUserState{}, nil
		b.puRecovered()
		return
	}
	if src.check == nil {
		b.puStale("no startup check is wired", nil)
		return
	}
	if err := src.check(cfg); err != nil {
		b.puStale("the block does not pass the startup checks", err)
		return
	}
	raw, err := perUserSectionJSON(cfg)
	if err != nil {
		b.puStale("the section could not be encoded", err)
		return
	}
	b.puRecovered()
	if !bytes.Equal(raw, b.pu.raw) {
		ps.warnWorkersLackUserSecrets(b.puPairs, perUserPairs(cfg))
	}
	b.pu = perUserState{raw: raw, ttl: cfg.WorkerCacheTTL}
	b.puPairs = perUserPairs(cfg)
}

// puStale marks the served per-user section stale: the block in the config is
// not served. It logs once per transition into the state.
func (b *bundlePublisher) puStale(why string, err error) {
	if b.pustale.Swap(true) {
		return
	}
	attrs := []any{"reason", why}
	if err != nil {
		attrs = append(attrs, "error", boundedErr(err))
	}
	b.logger.Error("control plane: perUserSecrets is stale: the section last served stays in force", attrs...)
}

// puRecovered clears the stale mark, logging the transition once.
func (b *bundlePublisher) puRecovered() {
	if b.pustale.Swap(false) {
		b.logger.Info("control plane: perUserSecrets is serving the block in the config again")
	}
}

// perUserStale reports whether an enabled or unreadable block in the config is
// not being served (/healthz).
func (ps *policyServer) perUserStale() bool {
	return ps.bundles != nil && ps.bundles.pustale.Load()
}

// warnWorkersLackUserSecrets logs the connected workers that serve an agent a
// mapping was just added for and lack usersecrets/v1.
func (ps *policyServer) warnWorkersLackUserSecrets(have, want map[string]map[string]bool) {
	if ps.registry == nil {
		return
	}
	lacking, total := ps.registry.WorkersLackingCap(config.CapUserSecretsV1, perUserAffected(have, want))
	if len(lacking) > 0 {
		ps.bundles.logger.Warn("per_user_secrets_workers_lack_capability: workers serving an agent with a new per-user mapping lack usersecrets/v1 and will forward the placeholder",
			"workers", lacking, "total", total)
	}
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
// sections' actual bytes. It is called only when the feature is on, so a
// control plane without it keeps the fingerprint it persisted before this
// feature.
func perUserFingerprint(fp string, section, epochs json.RawMessage) string {
	h := sha256.New()
	_, _ = h.Write([]byte(fp))
	_, _ = h.Write([]byte("\x00perUserSecrets\x00"))
	_, _ = h.Write(section)
	_, _ = h.Write([]byte("\x00userGrantEpochs\x00"))
	_, _ = h.Write(epochs)
	return hex.EncodeToString(h.Sum(nil))
}

// epochsFor returns the userGrantEpochs section to sign for seq. Bytes already
// signed for seq (frozen, also across a restart) are reused as they are:
// a worker's ContentSHA256 covers every section byte, so a re-sign of one seq
// must not differ, whatever a prune removed since. A new seq builds the section
// from the table, which is where pruned entries disappear. The caller holds
// refreshMu.
func (ps *policyServer) epochsFor(ctx context.Context, seq int64) (json.RawMessage, error) {
	b := ps.bundles
	if b.frozenSeq == seq && b.frozenEpochs != nil {
		return b.frozenEpochs, nil
	}
	entries, err := (grantEpochTable{db: b.state.db}).all(ctx)
	if err != nil {
		return nil, err
	}
	return epochSection(entries)
}

// freezeEpochs records the section signed for seq. It runs before the signed
// record is stored and the envelope published.
func (ps *policyServer) freezeEpochs(ctx context.Context, seq int64, raw json.RawMessage) error {
	b := ps.bundles
	if b.frozenSeq == seq && b.frozenEpochs != nil {
		return nil
	}
	if err := b.state.put(ctx, stateGrantSection, strconv.FormatInt(seq, 10)+":"+string(raw)); err != nil {
		return err
	}
	b.frozenSeq, b.frozenEpochs = seq, raw
	return nil
}

// loadFrozenEpochs reads the frozen section at startup.
func (b *bundlePublisher) loadFrozenEpochs(ctx context.Context) error {
	v, ok, err := b.state.get(ctx, stateGrantSection)
	if err != nil || !ok {
		return err
	}
	seq, raw, found := strings.Cut(v, ":")
	n, perr := strconv.ParseInt(seq, 10, 64)
	if !found || perr != nil || n < 1 || !json.Valid([]byte(raw)) {
		return errors.New("bundle_state has an unreadable userGrantEpochs record")
	}
	b.frozenSeq, b.frozenEpochs = n, json.RawMessage(raw)
	return nil
}
