//go:build e2e

package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
)

// Request is one request the fake upstream recorded (its /_recorded shape).
type Request struct {
	ID     int         `json:"id"`
	Method string      `json:"method"`
	Host   string      `json:"host"`
	Path   string      `json:"path"`
	Query  string      `json:"query"`
	Proto  string      `json:"proto"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

// httpGet fetches url (plain or TLS verified against the proxy CA) with a
// short timeout and returns the status and body.
func httpGet(tb testing.TB, url string) (int, []byte) {
	tb.Helper()
	code, body, err := tryGet(url)
	if err != nil {
		tb.Fatalf("e2e: GET %s: %v", url, err)
	}
	return code, body
}

func tryGet(url string) (int, []byte, error) {
	client, err := httpClient()
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return resp.StatusCode, body, err
}

func httpClient() (*http.Client, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(filepath.Join(root, caPath))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", caPath)
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}, nil
}

// recordedRaw is the recorder's /_recorded body, verbatim (for leak scans).
func recordedRaw(tb testing.TB) []byte {
	tb.Helper()
	code, body := httpGet(tb, recorderBase+recordedPath)
	if code != http.StatusOK {
		tb.Fatalf("e2e: recorder %s returned %d", recordedPath, code)
	}
	return body
}

// recorded returns what the fake upstream saw, oldest first. The recorder is
// synchronous with the request (it records before answering), so a read
// after the agent's call returned needs no wait.
func recorded(tb testing.TB) []Request {
	tb.Helper()
	var env struct {
		Records []Request `json:"records"`
		Dropped int       `json:"dropped"`
	}
	if err := json.Unmarshal(recordedRaw(tb), &env); err != nil {
		tb.Fatalf("e2e: decode recorder: %v", err)
	}
	if env.Dropped > 0 {
		tb.Fatalf("e2e: recorder dropped %d records; reset between scenarios", env.Dropped)
	}
	return env.Records
}

// resetRecorded clears the recorder (and any armed DNS rebinds).
func resetRecorded(tb testing.TB) {
	tb.Helper()
	req, err := http.NewRequest(http.MethodPost, recorderBase+resetPath, nil)
	if err != nil {
		tb.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("e2e: reset recorder: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("e2e: reset recorder: status %d", resp.StatusCode)
	}
}

// logs returns `docker compose logs --no-color <service>`.
func logs(tb testing.TB, service string) string {
	tb.Helper()
	res := compose(tb, 60*time.Second, "logs", "--no-color", service)
	if res.exit != 0 {
		tb.Fatalf("e2e: logs %s: exit %d: %s", service, res.exit, res.stderr)
	}
	return res.stdout
}

// fleetGet reads a control-plane fleet-API path and returns the body.
func fleetGet(tb testing.TB, path string) []byte {
	tb.Helper()
	code, body := httpGet(tb, cpBase+path)
	if code != http.StatusOK {
		tb.Fatalf("e2e: fleet API %s returned %d: %.200s", path, code, body)
	}
	return body
}

// workerTraffic is a worker's own /dashboard/api/traffic body. In the e2e
// stack workers run in central mode and forward events, so this is normally
// an empty list; it is read for the leak scan, not for decisions.
func workerTraffic(tb testing.TB, worker string) []byte {
	tb.Helper()
	base, ok := workerAdmin[worker]
	if !ok {
		tb.Fatalf("e2e: unknown worker %q", worker)
	}
	code, body := httpGet(tb, base+trafficPath)
	if code != http.StatusOK {
		tb.Fatalf("e2e: %s traffic API returned %d", worker, code)
	}
	return body
}

// eventsDeadline bounds how long events() waits for the async writer.
const eventsDeadline = 20 * time.Second

// eventsStablePolls is how many extra polls (500ms apart) the matched count
// must hold steady before events() returns.
const eventsStablePolls = 2

// events returns the decision events a worker produced at or after since.
//
// Workers write analytics asynchronously and forward them to the control
// plane, whose fleet view is the read side (the worker's own traffic API is
// empty in central mode). So this polls until at least want events satisfy
// match (nil matches all) or the deadline passes, then fails with what it saw.
// Never assert "zero events" off one read: an absent event may just be unflushed.
//
// Once want events match, the matched count must also stay unchanged for
// eventsStablePolls further polls, so a duplicate flushed one tick later still
// shows up in the result instead of being missed by an early return.
func events(tb testing.TB, worker string, since time.Time, want int, match func(analytics.Event) bool) []analytics.Event {
	tb.Helper()
	var got []analytics.Event
	lastMatched, stable := -1, 0
	waitFor(tb, eventsDeadline, fmt.Sprintf("%d matching %s events", want, worker), func() (bool, string) {
		code, body, err := tryGet(cpBase + trafficPath + "?limit=1000")
		if err != nil || code != http.StatusOK {
			return false, fmt.Sprintf("fleet traffic: status %d err %v", code, err)
		}
		var all []analytics.Event
		if err := json.Unmarshal(body, &all); err != nil {
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
		return matched >= want && stable >= eventsStablePolls, fmt.Sprintf("%d events from %s since %s, %d matching (stable %d/%d); %s",
			len(got), worker, since.Format(time.RFC3339Nano), matched, stable, eventsStablePolls, summarize(got))
	})
	return got
}

func summarize(evs []analytics.Event) string {
	var b strings.Builder
	for _, e := range evs {
		fmt.Fprintf(&b, "[%s:%d %s %s] ", e.Domain, e.Port, e.Decision, e.Reason)
	}
	return b.String()
}
