package worker

import (
	"log/slog"

	"github.com/ethosagent/warden/internal/config"
)

// secretScopes extracts the placeholder→matchHosts map for the proxy and warns
// (by placeholder NAME only) about every unscoped entry: it is swapped on every
// allowed host, which can carry its real value to an unintended destination.
// Unscoped is the legacy behavior kept for migration; a future release is
// expected to require matchHosts.
func secretScopes(entries []config.SecretMapping, logger *slog.Logger) map[string][]string {
	scopes := make(map[string][]string, len(entries))
	for _, m := range entries {
		if len(m.MatchHosts) == 0 {
			logger.Warn("secret has no matchHosts: it will be swapped on EVERY allowed host; scope it to its intended destinations (will be required in a future release)",
				"placeholder", m.Placeholder)
			continue
		}
		scopes[m.Placeholder] = append([]string(nil), m.MatchHosts...)
	}
	return scopes
}
