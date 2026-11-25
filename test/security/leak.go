package security

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

// The leak invariant. Every credential the stack creates or plants is
// registered here the moment it exists: user and Warden tokens, client
// assertions, enrollment tokens, console sessions, private key PEMs, and the
// swapped secret. AssertNoLeak then proves none of them appears where it must
// never be. Failure messages name the kind and the surface, never the value.

type tracked struct{ kind, value string }

type tracker struct {
	mu    sync.Mutex
	items []tracked
}

func newTracker() *tracker { return &tracker{} }

// minTracked is the shortest value worth searching for: a shorter one would
// match ordinary log text and make the invariant noisy, not stronger.
const minTracked = 12

func (t *tracker) add(kind, value string) {
	value = strings.TrimSpace(value)
	if len(value) < minTracked {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.addLocked(kind, value)
	if !strings.Contains(value, "\n") {
		return
	}
	// A multi-line secret (a PEM key) reaches JSON logs, audit rows and events
	// with its newlines escaped, so the whole string is never found. Track each
	// long body line and the body with headers and newlines stripped too.
	var body strings.Builder
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		body.WriteString(line)
		t.addLocked(kind, line)
	}
	t.addLocked(kind, body.String())
}

func (t *tracker) addLocked(kind, value string) {
	if len(value) < minTracked {
		return
	}
	for _, it := range t.items {
		if it.value == value {
			return
		}
	}
	t.items = append(t.items, tracked{kind, value})
}

func (t *tracker) all() []tracked {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]tracked(nil), t.items...)
}

// Track registers a value the leak invariant must never find (a canary a case
// plants, for example). kind names it in a failure message.
func (s *Stack) Track(kind, value string) { s.tracker.add(kind, value) }

// LeakCheck says what a case saw and how much upstream traffic may carry the
// swapped secret.
type LeakCheck struct {
	// Responses are what the agent saw: bodies and headers are scanned.
	Responses []Response
	// Replies are other replies the attacker read (a token endpoint refusal).
	Replies []Reply
	// AllowSwapUpTo is how many upstream requests, counted from the start of
	// the stack, are allowed to carry the swapped secret: the requests of
	// allowed cases. Later ones must not.
	AllowSwapUpTo int
}

// proxyOnlyHeaders must never reach an upstream.
var proxyOnlyHeaders = []string{"Proxy-Authorization", "X-Warden-Identity"}

// AssertNoLeak fails tb for every credential found where it must not be:
// the agent-visible responses, the upstream's recorded requests, the logs, the
// admin audit rows, the deny events, the token_events rows and the /metrics
// scrapes. The swapped secret may appear only in the first lc.AllowSwapUpTo
// upstream requests, and Proxy-Authorization and X-Warden-Identity may appear
// in none of them.
func (s *Stack) AssertNoLeak(tb testing.TB, lc LeakCheck) {
	tb.Helper()
	s.WaitIdle(tb)
	items := s.tracker.all()
	check := func(surface, text string, allowSwapped bool) {
		for _, it := range items {
			if it.kind == "swapped secret" && allowSwapped {
				continue
			}
			if strings.Contains(text, it.value) {
				tb.Errorf("security: leak: a %s appears in %s", it.kind, surface)
			}
		}
	}
	for i, r := range lc.Responses {
		check("agent response "+itoa(i)+" (status, headers, body)", responseText(r), false)
	}
	for i, r := range lc.Replies {
		check("attacker reply "+itoa(i)+" (headers, body)", headerText(r.Header)+r.Body, false)
	}
	for i, req := range s.Upstream.Requests() {
		text := req.Method + " " + req.Path + "\n" + headerText(req.Header) + string(req.Body)
		check("upstream request "+itoa(i), text, i < lc.AllowSwapUpTo)
		for _, h := range proxyOnlyHeaders {
			if req.Header.Get(h) != "" {
				tb.Errorf("security: leak: %s reached the upstream (request %d)", h, i)
			}
		}
	}
	for surface, text := range s.surfaces(tb) {
		check(surface, text, false)
	}
}

func responseText(r Response) string {
	return headerText(r.Header) + headerText(r.ConnectHeader) + r.Body + r.ConnectBody
}

func headerText(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		b.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	return b.String()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for ; i > 0; i /= 10 {
		d = append([]byte{byte('0' + i%10)}, d...)
	}
	return string(d)
}
