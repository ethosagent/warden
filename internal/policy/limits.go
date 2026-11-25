package policy

import "time"

// ParseRateLimit parses an allow entry's rateLimit ("N/second|minute|hour")
// with the exact rules the evaluator enforces, so a caller that compares two
// limits (the approvals widening classifier, W-P2-APPR-02) cannot disagree
// with enforcement about what a value means.
func ParseRateLimit(s string) (limit int, window time.Duration, err error) {
	rl, err := parseRateLimit(s)
	if err != nil {
		return 0, 0, err
	}
	return rl.limit, rl.window, nil
}

// TimeWindowHours parses an allow entry's timeWindow ("HH-HH") with the
// evaluator's rules and returns the set of hours of day it admits as a bitmask
// (bit h set = hour h admitted). A start after the end wraps midnight; an equal
// start and end admits no hour, exactly as the evaluator does.
func TimeWindowHours(s string) (uint32, error) {
	tw, err := parseTimeWindow(s)
	if err != nil {
		return 0, err
	}
	var mask uint32
	for h := 0; h < 24; h++ {
		if tw.admits(h) {
			mask |= 1 << uint(h)
		}
	}
	return mask, nil
}

// RateBucketKeys returns the rate bucket key(s) an unscoped rate-limited
// allow entry draws on, normalised exactly as the evaluator does (case and
// trailing dots on non-regex patterns; the scheme default port when the entry
// has none, which is both 443 and 80). Unscoped entries with equal keys share
// ONE bucket and whichever opens it sets the window; scoped entries each own a
// bucket and never share. The approvals classifier uses this to tell when a
// change to one entry can change another's effective rate.
func RateBucketKeys(domain string, port int) []string {
	if port != 0 {
		return []string{rateBucketKey(domain, port)}
	}
	return []string{
		rateBucketKey(domain, inferredPort(0, SchemeHTTPS)),
		rateBucketKey(domain, inferredPort(0, SchemeHTTP)),
	}
}
