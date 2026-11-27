package scenarios

import (
	"slices"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock/clocktest"
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

// The midnight guard jumps a fake clock that starts within G of UTC midnight to
// one minute past it, and leaves any other start alone.
func TestJumpPastUTCMidnightIfWithin(t *testing.T) {
	day := func(h, m int) time.Time { return time.Date(2026, 3, 4, h, m, 0, 0, time.UTC) }
	cases := []struct {
		name     string
		start    time.Time
		wantJump bool
		want     time.Time
	}{
		{"23:50 jumps", day(23, 50), true, time.Date(2026, 3, 5, 0, 1, 0, 0, time.UTC)},
		{"23:31 jumps", day(23, 31), true, time.Date(2026, 3, 5, 0, 1, 0, 0, time.UTC)},
		{"23:30 is outside the guard", day(23, 30), false, day(23, 30)},
		{"noon is untouched", day(12, 0), false, day(12, 0)},
		{"month end jumps", time.Date(2026, 1, 31, 23, 55, 0, 0, time.UTC), true, time.Date(2026, 2, 1, 0, 1, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		c := clocktest.NewFake(tc.start)
		if got := jumpPastUTCMidnightIfWithin(c, midnightGuard); got != tc.wantJump {
			t.Errorf("%s: jumped = %v, want %v", tc.name, got, tc.wantJump)
		}
		if !c.Now().Equal(tc.want) {
			t.Errorf("%s: now = %v, want %v", tc.name, c.Now(), tc.want)
		}
	}
}
