//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness/compose"
)

// The suite's oracles: tb-fatalf wrappers over the compose package's shared
// primitives (the compose Target reads the very same ones), plus this suite's
// own want-driven events() on top of the shared settle poll.

// httpGet fetches url (plain or TLS verified against the proxy CA) with a
// short timeout and returns the status and body.
func httpGet(tb testing.TB, url string) (int, []byte) {
	tb.Helper()
	code, body, err := compose.TryGet(url)
	if err != nil {
		tb.Fatalf("e2e: GET %s: %v", url, err)
	}
	return code, body
}

func tryGet(url string) (int, []byte, error) { return compose.TryGet(url) }

// recordedRaw is the recorder's /_recorded body, verbatim (for leak scans).
func recordedRaw(tb testing.TB) []byte {
	tb.Helper()
	raw, err := compose.RecorderRaw()
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	return raw
}

// recorded returns what the fake upstream saw, oldest first. The recorder is
// synchronous with the request (it records before answering), so a read
// after the agent's call returned needs no wait.
func recorded(tb testing.TB) []Request {
	tb.Helper()
	recs, err := compose.RecorderRequests()
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	return recs
}

// resetRecorded clears the recorder (and any armed DNS rebinds).
func resetRecorded(tb testing.TB) {
	tb.Helper()
	if err := compose.ResetRecorder(); err != nil {
		tb.Fatalf("e2e: reset recorder: %v", err)
	}
}

// logs returns `docker compose logs --no-color <service>`.
func logs(tb testing.TB, service string) string {
	tb.Helper()
	out, err := compose.LogsOf(service)
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	return out
}

// fleetGet reads a control-plane fleet-API path and returns the body.
func fleetGet(tb testing.TB, path string) []byte {
	tb.Helper()
	body, err := compose.FleetBody(path)
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	return body
}

// workerTraffic is a worker's own /dashboard/api/traffic body. In the e2e
// stack workers run in central mode and forward events, so this is normally
// an empty list; it is read for the leak scan, not for decisions.
func workerTraffic(tb testing.TB, worker string) []byte {
	tb.Helper()
	body, err := compose.WorkerTrafficBody(worker)
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	return body
}

// eventsDeadline bounds how long events() waits for the async writer; once
// want events match, the matched count must hold steady for eventsStablePolls
// further polls before events() returns (PollUntil's fixed 500ms cadence).
const (
	eventsDeadline    = compose.EventsDeadline
	eventsStablePolls = compose.EventsStablePolls
)

// events returns the decision events a worker produced at or after since.
//
// Workers write analytics asynchronously and forward them to the control
// plane, whose fleet view is the read side (the worker's own traffic API is
// empty in central mode). So this polls until at least want events satisfy
// match (nil matches all) or the deadline passes, then fails with what it saw.
// Never assert "zero events" off one read: an absent event may just be
// unflushed.
//
// Once want events match, the matched count must also stay unchanged for
// eventsStablePolls further polls, so a duplicate flushed one tick later still
// shows up in the result instead of being missed by an early return.
func events(tb testing.TB, worker string, since time.Time, want int, match func(analytics.Event) bool) []analytics.Event {
	tb.Helper()
	var got []analytics.Event
	lastMatched, stable := -1, 0
	err := compose.PollUntil(eventsDeadline, func() (bool, string) {
		code, body, err := tryGet(cpBase + trafficPath + "?limit=1000")
		if err != nil || code != http.StatusOK {
			return false, fmt.Sprintf("fleet traffic: status %d err %v", code, err)
		}
		all, err := compose.DecodeEvents(body)
		if err != nil {
			return false, "decode: " + err.Error()
		}
		got = got[:0]
		matched := 0
		for _, e := range all {
			if e.ProxyID != worker || e.Timestamp.Before(since) {
				continue
			}
			got = append(got, e)
			if match == nil || match(e) {
				matched++
			}
		}
		if matched >= want && matched == lastMatched {
			stable++
		} else {
			stable = 0
		}
		lastMatched = matched
		return matched >= want && stable >= eventsStablePolls,
			fmt.Sprintf("%d events from %s since %s, %d matching (stable %d/%d); %s",
				len(got), worker, since.Format(time.RFC3339Nano), matched, stable, eventsStablePolls, summarize(got))
	})
	if err != nil {
		tb.Fatalf("e2e: timed out after %s waiting for %d matching %s events: %v", eventsDeadline, want, worker, err)
	}
	return got
}

func summarize(evs []analytics.Event) string { return compose.SummarizeEvents(evs) }
