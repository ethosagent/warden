package oauthbroker_test

import (
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/oauthbroker/oauthbrokertest"
)

func TestNotifier(t *testing.T) {
	var n oauthbroker.Notifier
	a, cancelA := n.Subscribe("p1")
	b, cancelB := n.Subscribe("p1")
	other, cancelOther := n.Subscribe("p2")
	defer cancelOther()
	if got := n.Waiters("p1"); got != 2 {
		t.Fatalf("Waiters = %d, want 2", got)
	}
	cancelB()
	cancelB()
	if got := n.Waiters("p1"); got != 1 {
		t.Fatalf("Waiters after cancel = %d, want 1", got)
	}
	n.Complete("p1", oauthbroker.StatusDenied)
	if got := oauthbrokertest.Received(t, a); got != oauthbroker.StatusDenied {
		t.Fatalf("waiter got %q", got)
	}
	cancelA() // after Complete: a no-op
	select {
	case <-b:
		t.Fatal("a cancelled waiter was notified")
	case <-other:
		t.Fatal("a waiter for another id was notified")
	default:
	}
	if got := n.Waiters("p1"); got != 0 {
		t.Fatalf("Waiters after Complete = %d", got)
	}
	n.Complete("nobody", oauthbroker.StatusGranted) // no waiters: no panic
}

func TestNotifierLastCancelFreesEntry(t *testing.T) {
	var n oauthbroker.Notifier
	_, cancel := n.Subscribe("p1")
	cancel()
	if got := n.Waiters("p1"); got != 0 {
		t.Fatalf("Waiters = %d", got)
	}
}

func TestNotifierConcurrent(t *testing.T) {
	var n oauthbroker.Notifier
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, cancel := n.Subscribe("p")
			defer cancel()
			select {
			case <-ch:
			default:
			}
		}()
	}
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); n.Complete("p", oauthbroker.StatusGranted) }()
	}
	wg.Wait()
}

func TestClosed(t *testing.T) {
	if got := oauthbrokertest.Received(t, oauthbroker.Closed(oauthbroker.StatusGranted)); got != oauthbroker.StatusGranted {
		t.Fatalf("Closed(granted) delivered %q", got)
	}
	if got := oauthbrokertest.Received(t, oauthbroker.Closed("")); got != "" {
		t.Fatalf("Closed(\"\") delivered %q", got)
	}
}
