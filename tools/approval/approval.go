// Package approval decides whether a pull request carries a valid
// gates-change-approved label (#354). A label is valid only when
//
//   - it is on the PR now, and its latest event is an add (not a removal),
//   - the account that added it is not a bot or agent,
//   - that account has maintain or admin permission on the repository,
//   - it was added strictly after the latest push to the PR's head.
//
// So a label added by the bot itself, by someone without maintain rights, or
// before a later push (a new push after approval removes the approval) never
// counts. Every GitHub call goes through the GitHub interface, so each rule is
// tested offline with a fake. Any API error fails closed.
//
// It is developer tooling: no Warden package may import it.
package approval

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Label is the label a maintainer adds to approve a gate change.
const Label = "gates-change-approved"

// Account is a GitHub account as the API reports it (type is "User" or "Bot").
type Account struct {
	Login string
	Type  string
}

// PullRequest is the part of a PR the rules need.
type PullRequest struct {
	Author  Account
	HeadSHA string
	Labels  []string
}

// LabelEvent is one add or removal of a label.
type LabelEvent struct {
	Added bool
	Actor Account
	At    time.Time
}

// GitHub is the read-only GitHub surface the verification uses.
type GitHub interface {
	PullRequest(ctx context.Context, number int) (PullRequest, error)
	// LabelEvents returns the add and remove events of one label, in any order.
	LabelEvents(ctx context.Context, number int, label string) ([]LabelEvent, error)
	// HeadPushedAt is when the PR's current head commit was pushed to the PR.
	HeadPushedAt(ctx context.Context, number int, headSHA string) (time.Time, error)
	// Permission is the repository role of a user: admin, maintain, write, triage, read or none.
	Permission(ctx context.Context, login string) (string, error)
}

// Verdict is the outcome. Reason always says why, approved or not.
type Verdict struct {
	Approved bool
	Reason   string
	By       string
}

func reject(format string, a ...any) Verdict { return Verdict{Reason: fmt.Sprintf(format, a...)} }

// Verify applies the rules. isAgent says whether an account is a bot or agent
// (see risk.Map.IsAgent); such an account can never approve, whatever its
// permission. A non-nil error always comes with an unapproved verdict.
func Verify(ctx context.Context, gh GitHub, number int, isAgent func(login, accountType string) bool) (Verdict, error) {
	pr, err := gh.PullRequest(ctx, number)
	if err != nil {
		return Verdict{}, fmt.Errorf("read PR #%d: %w", number, err)
	}
	if !hasLabel(pr.Labels, Label) {
		return reject("label %s is not on the PR", Label), nil
	}
	events, err := gh.LabelEvents(ctx, number, Label)
	if err != nil {
		return Verdict{}, fmt.Errorf("read label events of PR #%d: %w", number, err)
	}
	if len(events) == 0 {
		return reject("no event shows who added %s", Label), nil
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })
	last := events[len(events)-1]
	if !last.Added {
		return reject("label %s was removed by %s; a maintainer must add it again", Label, last.Actor.Login), nil
	}
	if isAgent(last.Actor.Login, last.Actor.Type) || strings.HasSuffix(strings.ToLower(last.Actor.Login), "[bot]") {
		return reject("label %s was added by %s, a bot or agent account; only a human maintainer can approve", Label, last.Actor.Login), nil
	}
	role, err := gh.Permission(ctx, last.Actor.Login)
	if err != nil {
		return Verdict{}, fmt.Errorf("read permission of %s: %w", last.Actor.Login, err)
	}
	if !isMaintainerRole(role) {
		return reject("label %s was added by %s, who has %q permission; needs maintain or admin", Label, last.Actor.Login, role), nil
	}
	pushed, err := gh.HeadPushedAt(ctx, number, pr.HeadSHA)
	if err != nil {
		return Verdict{}, fmt.Errorf("find the latest push of PR #%d: %w", number, err)
	}
	if !last.At.After(pushed) {
		return reject("label %s was added at %s, before the latest push at %s; a new push removes the approval, so a maintainer must add it again",
			Label, last.At.UTC().Format(time.RFC3339), pushed.UTC().Format(time.RFC3339)), nil
	}
	return Verdict{Approved: true, By: last.Actor.Login, Reason: fmt.Sprintf("%s added %s after the latest push", last.Actor.Login, Label)}, nil
}

func isMaintainerRole(role string) bool {
	switch strings.ToLower(role) {
	case "admin", "maintain":
		return true
	}
	return false
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}
