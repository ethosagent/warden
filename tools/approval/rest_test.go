package approval

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ghServer stands in for api.github.com. Every request must be a GET carrying
// the token: the verification is read-only.
func ghServer(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("non-GET request %s %s: the verification must be read-only", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing token on %s", r.URL)
		}
		body, ok := routes[r.URL.RequestURI()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		// a "next:<path>|" prefix adds a Link header, to exercise pagination
		if strings.HasPrefix(body, "next:") {
			next, rest, _ := strings.Cut(strings.TrimPrefix(body, "next:"), "|")
			w.Header().Set("Link", fmt.Sprintf(`<%s%s>; rel="next"`, "http://"+r.Host, next))
			body = rest
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, Repo: "o/r", Token: "tok", Doer: srv.Client()}
}

func TestRESTPullRequest(t *testing.T) {
	c := ghServer(t, map[string]string{
		"/repos/o/r/pulls/7": `{"user":{"login":"claude[bot]","type":"Bot"},"head":{"sha":"abc"},"labels":[{"name":"risk:gates"},{"name":"gates-change-approved"}]}`,
	})
	pr, err := c.PullRequest(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Author != (Account{"claude[bot]", "Bot"}) || pr.HeadSHA != "abc" || !hasLabel(pr.Labels, Label) {
		t.Fatalf("pr = %+v", pr)
	}
}

func TestRESTLabelEventsPaginateAndFilter(t *testing.T) {
	c := ghServer(t, map[string]string{
		"/repos/o/r/issues/7/events?per_page=100": `next:/repos/o/r/issues/7/events?per_page=100&page=2|[
			{"event":"labeled","label":{"name":"gates-change-approved"},"actor":{"login":"claude[bot]","type":"Bot"},"created_at":"2026-10-01T10:00:00Z"},
			{"event":"labeled","label":{"name":"risk:gates"},"actor":{"login":"ci[bot]","type":"Bot"},"created_at":"2026-10-01T10:01:00Z"}]`,
		"/repos/o/r/issues/7/events?per_page=100&page=2": `[
			{"event":"unlabeled","label":{"name":"gates-change-approved"},"actor":{"login":"mitesh","type":"User"},"created_at":"2026-10-01T11:00:00Z"},
			{"event":"head_ref_force_pushed","actor":{"login":"x","type":"User"},"created_at":"2026-10-01T12:00:00Z"}]`,
	})
	evs, err := c.LabelEvents(context.Background(), 7, Label)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || !evs[0].Added || evs[0].Actor.Login != "claude[bot]" || evs[1].Added || evs[1].Actor.Login != "mitesh" {
		t.Fatalf("events = %+v", evs)
	}
}

func TestRESTHeadPushedAt(t *testing.T) {
	c := ghServer(t, map[string]string{
		"/repos/o/r/commits/abc1234/check-suites?per_page=100": `{"check_suites":[{"created_at":"2026-10-01T09:30:00Z"},{"created_at":"2026-10-01T09:00:00Z"}]}`,
		"/repos/o/r/issues/7/events?per_page=100": `[
			{"event":"head_ref_force_pushed","actor":{"login":"x","type":"User"},"created_at":"2026-10-01T09:45:00Z"},
			{"event":"head_ref_force_pushed","actor":{"login":"x","type":"User"},"created_at":"2026-10-01T08:00:00Z"}]`,
	})
	got, err := c.HeadPushedAt(context.Background(), 7, "abc1234")
	if err != nil {
		t.Fatal(err)
	}
	// the later of: first check suite for the head sha (09:00), latest force push (09:45)
	if want := time.Date(2026, 10, 1, 9, 45, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("pushed = %s, want %s", got, want)
	}
}

func TestRESTHeadPushedAtWithoutAnySignalFailsClosed(t *testing.T) {
	c := ghServer(t, map[string]string{
		"/repos/o/r/commits/abc1234/check-suites?per_page=100": `{"check_suites":[]}`,
		"/repos/o/r/issues/7/events?per_page=100":              `[]`,
	})
	if _, err := c.HeadPushedAt(context.Background(), 7, "abc1234"); err == nil {
		t.Fatal("no check suite and no force push means the push time is unknown: that must be an error")
	}
}

func TestRESTPermissionUsesRoleName(t *testing.T) {
	// The legacy "permission" field folds maintain into write; role_name keeps it.
	c := ghServer(t, map[string]string{
		"/repos/o/r/collaborators/mitesh/permission": `{"permission":"write","role_name":"maintain"}`,
		"/repos/o/r/collaborators/old/permission":    `{"permission":"admin"}`,
	})
	if got, err := c.Permission(context.Background(), "mitesh"); err != nil || got != "maintain" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := c.Permission(context.Background(), "old"); err != nil || got != "admin" {
		t.Fatalf("fallback to permission: got %q, %v", got, err)
	}
}

func TestRESTErrorsAreErrors(t *testing.T) {
	c := ghServer(t, map[string]string{"/repos/o/r/pulls/7": `not json`})
	if _, err := c.PullRequest(context.Background(), 7); err == nil {
		t.Error("bad JSON must be an error")
	}
	if _, err := c.PullRequest(context.Background(), 8); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("404 must be an error naming the status, got %v", err)
	}
	if _, err := c.Permission(context.Background(), "x/../y"); err == nil {
		t.Error("a login that is not a plain name must be refused before any request")
	}
}
