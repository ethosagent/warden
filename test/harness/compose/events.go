package compose

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
)

// PollEvents reads the control plane's fleet view until it SETTLES. The stack
// writes analytics asynchronously (the workers forward events to the control
// plane on their own tick), so one immediate read races the writer: this polls
// fetch until a NON-EMPTY count of events at or after since has held stable for
// stable consecutive polls (tick apart). A zero count never settles early — an
// absent event may just be unflushed — it polls out the deadline and then
// returns whatever it saw with no error: zero is a legitimate answer the
// CALLER asserts on (never off one read), while a non-empty count that never
// stabilizes, or reads that keep failing, is an oracle fault and errors.
//
// The returned events are exactly those at or after since — the marker that
// isolates one harness's traffic from everything the stack served before it.
// sleep is injected so the unit tests are instant; the target passes
// time.Sleep.
func PollEvents(fetch func() ([]analytics.Event, error), since time.Time, deadline, tick time.Duration, stable int, sleep func(time.Duration)) ([]analytics.Event, error) {
	var out []analytics.Event
	lastCount, stableRun, lastErr := -1, 0, error(nil)
	for elapsed := time.Duration(0); ; {
		evs, err := fetch()
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			out = eventsSince(evs, since)
			switch {
			case len(out) != lastCount:
				stableRun, lastCount = 0, len(out)
			case len(out) > 0:
				stableRun++
			}
			if len(out) > 0 && stableRun >= stable {
				return out, nil
			}
		}
		if elapsed >= deadline {
			if lastErr != nil {
				return out, fmt.Errorf("compose: read fleet events: %w", lastErr)
			}
			if len(out) > 0 {
				return out, fmt.Errorf("compose: fleet events never settled within %s (%d events at or after %s): %s",
					deadline, len(out), since.Format(time.RFC3339Nano), SummarizeEvents(out))
			}
			return out, nil
		}
		sleep(tick)
		elapsed += tick
	}
}

// eventsSince keeps the events at or after since, in arrival order.
func eventsSince(evs []analytics.Event, since time.Time) []analytics.Event {
	out := make([]analytics.Event, 0, len(evs))
	for _, e := range evs {
		if !e.Timestamp.Before(since) {
			out = append(out, e)
		}
	}
	return out
}

// DecodeEvents parses the fleet/traffic API's JSON array of events.
func DecodeEvents(body []byte) ([]analytics.Event, error) {
	var evs []analytics.Event
	if err := json.Unmarshal(body, &evs); err != nil {
		return nil, fmt.Errorf("compose: decode the traffic response: %v", err)
	}
	return evs, nil
}

// SummarizeEvents renders events into one compact line for failure messages.
func SummarizeEvents(evs []analytics.Event) string {
	var b strings.Builder
	for _, e := range evs {
		fmt.Fprintf(&b, "[%s:%d %s %s] ", e.Domain, e.Port, e.Decision, e.Reason)
	}
	return b.String()
}
