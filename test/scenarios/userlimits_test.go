package scenarios

import (
	"slices"
	"testing"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
)

// The control plane's rollup books an anonymous request under the rule name
// analytics.AnonymousLimitRule; config reserves the same name for the
// anonymousLimit rule and the worker stamps it as limit_rule. If the two drift,
// the usage view's unattributed row and the cost recompute silently lose the
// anonymous bucket, so the equality is pinned here, where both packages are
// importable (W-P3-PUL-10, deferred from W-P3-PUL-07/04/09).
func TestUserLimits_AnonymousRuleNameEquality(t *testing.T) {
	if config.UserLimitNameAnonymous != analytics.AnonymousLimitRule {
		t.Fatalf("config.UserLimitNameAnonymous = %q, analytics.AnonymousLimitRule = %q; they must be equal",
			config.UserLimitNameAnonymous, analytics.AnonymousLimitRule)
	}
	for _, name := range []string{config.UserLimitNameAnonymous, config.UserLimitNameDefault} {
		if err := agentid.ValidID(name); err != nil {
			t.Errorf("reserved rule name %q is not a valid rule name for the rollup: %v", name, err)
		}
	}
}

// The three limit deny reasons are in the declared reason set the decision log
// schema enumerates.
func TestUserLimits_DenyReasonsDeclared(t *testing.T) {
	for _, r := range []denyreason.Reason{denyreason.UserRateLimited, denyreason.UserCostLimited, denyreason.UserCostUnmeasurable} {
		if !slices.Contains(denyreason.Declared(), r) {
			t.Errorf("deny reason %q is not in the declared set", r)
		}
	}
}
