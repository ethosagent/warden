package secrets

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// ReservedKeyNamespace is the logical key namespace reserved for control-plane
// only material (the worker CA, W-P2-WCA-01). Real CP key material lives in the
// separate keys.PrivateKeyStore, which no placeholder can reach; reserving the
// namespace in the shared secret store is defense in depth so nothing CP-only
// can ever be added under a name a worker or a human route could reach.
const ReservedKeyNamespace = config.ReservedSecretNamespace

// ErrReservedKey is returned, before any backend call, for a key in the
// reserved namespace. A worker treats it like any unresolvable placeholder, so
// the request keeps the default-deny outcome.
var ErrReservedKey = errors.New("secrets: reserved key")

// IsReservedKey reports whether key is in a reserved namespace: the
// control-plane namespace cp/ (W-P2-WCA-01), or one of the per-user credential
// namespaces users/, idp/, revoking/ and oauth-clients/ that only the CP-only
// consent.store holds (W-P3-CSIG-06; see userkey.go). It applies the
// normalization every entry point applies to a key (surrounding whitespace is
// trimmed, leading slashes dropped), so a padded key cannot slip past a guard
// the store would then accept. storeFetcher.Fetch, the worker Cache,
// /central/secrets and the dashboard secret store all refuse such keys, and
// config validation rejects a placeholder under one.
func IsReservedKey(key string) bool {
	return config.IsReservedSecretKey(key)
}

// reservedLogInterval is how often one source may log a refusal.
const reservedLogInterval = time.Minute

// reservedLogMaxSources bounds the per-source map so a flood of distinct
// sources cannot grow it without limit.
const reservedLogMaxSources = 1024

// ReservedKeyLog logs "reserved secret key refused" at most once a minute per
// source (a route or an agent). It logs the source and the key PREFIX only,
// never the rest of the key. The zero value is not usable; build it with
// NewReservedKeyLog. It is safe for concurrent use.
type ReservedKeyLog struct {
	logger *slog.Logger
	now    func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
}

// NewReservedKeyLog builds a ReservedKeyLog over logger (slog.Default when nil)
// and the time source now (time.Now when nil).
func NewReservedKeyLog(logger *slog.Logger, now func() time.Time) *ReservedKeyLog {
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &ReservedKeyLog{logger: logger, now: now, last: make(map[string]time.Time)}
}

// Refused records a refused attempt by source on key. A nil receiver is a no-op
// so callers need no guard.
func (l *ReservedKeyLog) Refused(source, key string) {
	if l == nil {
		return
	}
	t := l.now()
	l.mu.Lock()
	if prev, ok := l.last[source]; ok && t.Sub(prev) < reservedLogInterval {
		l.mu.Unlock()
		return
	}
	if len(l.last) >= reservedLogMaxSources {
		for s, at := range l.last {
			if t.Sub(at) >= reservedLogInterval {
				delete(l.last, s)
			}
		}
		if len(l.last) >= reservedLogMaxSources {
			l.mu.Unlock()
			return
		}
	}
	l.last[source] = t
	l.mu.Unlock()
	ns, ok := config.ReservedSecretNamespaceOf(key)
	if !ok {
		ns = ReservedKeyNamespace
	}
	l.logger.Warn("reserved secret key refused", "source", source, "keyPrefix", ns+"/")
}
