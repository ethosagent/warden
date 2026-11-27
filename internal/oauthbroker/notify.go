package oauthbroker

import "sync"

// Notifier is the in-memory Subscribe map a GrantStore embeds: waiters for a
// pending id register a channel, and Complete delivers the final status to each
// and closes it. It is per process; with several CP replicas a waiter must
// also re-read the row (W-P3-JIT-04 does, every few seconds). The zero value
// is ready to use.
type Notifier struct {
	mu      sync.Mutex
	waiters map[string]map[uint64]chan PendingStatus
	next    uint64
}

// Subscribe registers a waiter for id. The channel has room for the one status
// Complete sends, so Complete never blocks. cancel unregisters the waiter and
// is safe to call more than once and after Complete.
func (n *Notifier) Subscribe(id string) (<-chan PendingStatus, func()) {
	ch := make(chan PendingStatus, 1)
	n.mu.Lock()
	if n.waiters == nil {
		n.waiters = make(map[string]map[uint64]chan PendingStatus)
	}
	n.next++
	key := n.next
	set := n.waiters[id]
	if set == nil {
		set = make(map[uint64]chan PendingStatus)
		n.waiters[id] = set
	}
	set[key] = ch
	n.mu.Unlock()
	return ch, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if set, ok := n.waiters[id]; ok {
			delete(set, key)
			if len(set) == 0 {
				delete(n.waiters, id)
			}
		}
	}
}

// Complete sends status to every waiter of id, closes their channels and
// forgets them. A later Subscribe for id starts a new set, so a store must
// check the row after subscribing (see Closed).
func (n *Notifier) Complete(id string, status PendingStatus) {
	n.mu.Lock()
	set := n.waiters[id]
	delete(n.waiters, id)
	n.mu.Unlock()
	for _, ch := range set {
		ch <- status
		close(ch)
	}
}

// Waiters returns how many waiters are registered for id.
func (n *Notifier) Waiters(id string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.waiters[id])
}

// Closed returns an already-closed channel that holds status, or nothing when
// status is "". A store returns it from Subscribe for a pending that is
// already terminal or unknown.
func Closed(status PendingStatus) <-chan PendingStatus {
	ch := make(chan PendingStatus, 1)
	if status != "" {
		ch <- status
	}
	close(ch)
	return ch
}
