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
		var in bool
		if tw.startHour <= tw.endHour {
			in = h >= tw.startHour && h < tw.endHour
		} else {
			in = h >= tw.startHour || h < tw.endHour
		}
		if in {
			mask |= 1 << uint(h)
		}
	}
	return mask, nil
}
