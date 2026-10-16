//go:build ignore

// Tests for gen.go. gen.go is a build-ignored command, so run both files:
//
//	go test docs/roadmap/gen.go docs/roadmap/gen_test.go
package main

import (
	"strconv"
	"strings"
	"testing"
)

// TestTicketBodyCarriesHarnessRules pins what every ticket body must say: the
// two harness lines of the definition of done, and the item-level dependency on
// the harness feature (a P1 ticket reaches it only through its item).
func TestTicketBodyCarriesHarnessRules(t *testing.T) {
	t.Chdir("../..") // gen.go paths are relative to the repo root
	rm, err := load()
	if err != nil {
		t.Fatal(err)
	}
	open := map[int]bool{1: true, 2: true, 3: true, 4: true}
	num := map[string]int{"epic:p1-harness": 365}
	ref := func(n int) string { return "#" + strconv.Itoa(n) }

	it := rm.byID["p1-block-list"]
	if it == nil || len(it.Tickets) == 0 {
		t.Fatal("p1-block-list missing from tickets.json")
	}
	body := rm.ticketBody(it, 1, it.Tickets[0], open, num, ref)

	for _, want := range []string{
		"- [ ] Acceptance criteria are covered by `test/harness` scenarios",
		"- [ ] A new external dependency ships a fake in `test/harness`",
		"### Feature needs first",
		"- #365 L1 test harness",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ticket body lacks %q", want)
		}
	}
}
