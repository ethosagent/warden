package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Doer sends one HTTP request. The tools reach only api.github.com, so they use
// the transport directly (see TransportDoer) rather than a bare http.Client (X4).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// TransportDoer is a Doer over an http.RoundTripper. It does not follow
// redirects, so a token is never replayed to another host: a redirect is an error.
type TransportDoer struct{ RT http.RoundTripper }

// Do implements Doer.
func (d TransportDoer) Do(req *http.Request) (*http.Response, error) { return d.RT.RoundTrip(req) }

// Client is the GitHub implementation of GitHub. Every call is a GET.
type Client struct {
	BaseURL string // https://api.github.com
	Repo    string // owner/name
	Token   string
	Doer    Doer
}

var _ GitHub = (*Client)(nil)

const maxPages = 20

type apiAccount struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

func (a apiAccount) account() Account { return Account(a) }

// get fetches one URL and returns the body and the rel="next" link, if any.
func (c *Client) get(ctx context.Context, rawURL string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.Doer.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		// The body can echo request details; keep the status only.
		return nil, "", fmt.Errorf("GET %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return body, nextLink(resp.Header.Get("Link")), nil
}

var nextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(h string) string {
	if m := nextRe.FindStringSubmatch(h); m != nil {
		return m[1]
	}
	return ""
}

// pages follows rel="next" links, up to maxPages, calling each with a page body.
func (c *Client) pages(ctx context.Context, first string, each func([]byte) error) error {
	next := first
	for i := 0; next != ""; i++ {
		if i == maxPages {
			return fmt.Errorf("more than %d pages at %s", maxPages, first)
		}
		body, link, err := c.get(ctx, next)
		if err != nil {
			return err
		}
		if err := each(body); err != nil {
			return err
		}
		// Only follow links that stay on the API host: the token goes with them.
		if link != "" && !strings.HasPrefix(link, c.BaseURL+"/") {
			return fmt.Errorf("refusing to follow a page link off %s", c.BaseURL)
		}
		next = link
	}
	return nil
}

func (c *Client) repoURL(format string, a ...any) string {
	return c.BaseURL + "/repos/" + c.Repo + fmt.Sprintf(format, a...)
}

// PullRequest implements GitHub.
func (c *Client) PullRequest(ctx context.Context, number int) (PullRequest, error) {
	body, _, err := c.get(ctx, c.repoURL("/pulls/%d", number))
	if err != nil {
		return PullRequest{}, err
	}
	var v struct {
		User   apiAccount `json:"user"`
		Head   struct{ SHA string }
		Labels []struct{ Name string }
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return PullRequest{}, fmt.Errorf("decode PR: %w", err)
	}
	pr := PullRequest{Author: v.User.account(), HeadSHA: v.Head.SHA}
	for _, l := range v.Labels {
		pr.Labels = append(pr.Labels, l.Name)
	}
	return pr, nil
}

type issueEvent struct {
	Event     string `json:"event"`
	Label     struct{ Name string }
	Actor     apiAccount `json:"actor"`
	CreatedAt time.Time  `json:"created_at"`
}

func (c *Client) issueEvents(ctx context.Context, number int, each func(issueEvent)) error {
	return c.pages(ctx, c.repoURL("/issues/%d/events?per_page=100", number), func(body []byte) error {
		var evs []issueEvent
		if err := json.Unmarshal(body, &evs); err != nil {
			return fmt.Errorf("decode events: %w", err)
		}
		for _, e := range evs {
			each(e)
		}
		return nil
	})
}

// LabelEvents implements GitHub.
func (c *Client) LabelEvents(ctx context.Context, number int, label string) ([]LabelEvent, error) {
	var out []LabelEvent
	err := c.issueEvents(ctx, number, func(e issueEvent) {
		if (e.Event == "labeled" || e.Event == "unlabeled") && e.Label.Name == label {
			out = append(out, LabelEvent{Added: e.Event == "labeled", Actor: e.Actor.account(), At: e.CreatedAt})
		}
	})
	return out, err
}

// HeadPushedAt implements GitHub. GitHub has no "pushed at" for a commit, and a
// commit's own dates are set by its author, so they prove nothing. It uses two
// timestamps GitHub sets itself: the first check suite for the head commit (made
// when the commit reaches the repository) and the latest head_ref_force_pushed
// event of the PR, and takes the later. With neither it errors: an unknown push
// time must not approve anything.
func (c *Client) HeadPushedAt(ctx context.Context, number int, headSHA string) (time.Time, error) {
	if !shaRe.MatchString(headSHA) {
		return time.Time{}, fmt.Errorf("head sha %q is not a commit id", headSHA)
	}
	var pushed time.Time
	body, _, err := c.get(ctx, c.repoURL("/commits/%s/check-suites?per_page=100", headSHA))
	if err != nil {
		return time.Time{}, err
	}
	var suites struct {
		CheckSuites []struct {
			CreatedAt time.Time `json:"created_at"`
		} `json:"check_suites"`
	}
	if err := json.Unmarshal(body, &suites); err != nil {
		return time.Time{}, fmt.Errorf("decode check suites: %w", err)
	}
	var first time.Time
	for _, s := range suites.CheckSuites {
		if first.IsZero() || s.CreatedAt.Before(first) {
			first = s.CreatedAt
		}
	}
	pushed = first
	err = c.issueEvents(ctx, number, func(e issueEvent) {
		if e.Event == "head_ref_force_pushed" && e.CreatedAt.After(pushed) {
			pushed = e.CreatedAt
		}
	})
	if err != nil {
		return time.Time{}, err
	}
	if pushed.IsZero() {
		return time.Time{}, fmt.Errorf("no check suite or force-push event shows when %s was pushed", headSHA)
	}
	return pushed, nil
}

var (
	shaRe   = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	loginRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*(\[bot\])?$`)
)

// Permission implements GitHub. It reads role_name (which keeps "maintain"; the
// legacy permission field folds it into "write") and falls back to permission.
func (c *Client) Permission(ctx context.Context, login string) (string, error) {
	if !loginRe.MatchString(login) {
		return "", fmt.Errorf("%q is not a GitHub login", login)
	}
	body, _, err := c.get(ctx, c.repoURL("/collaborators/%s/permission", url.PathEscape(login)))
	if err != nil {
		return "", err
	}
	var v struct {
		Permission string `json:"permission"`
		RoleName   string `json:"role_name"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", fmt.Errorf("decode permission: %w", err)
	}
	if v.RoleName != "" {
		return v.RoleName, nil
	}
	return v.Permission, nil
}
