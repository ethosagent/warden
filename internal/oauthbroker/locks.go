package oauthbroker

import "sync"

// GrantLocks serialises every writer of one (userKey, provider) grant: the
// connect callback (a TokenRecord write plus its metadata steps), the refresh
// engine (W-P3-PUS-03), RevokeUserGrant (W-P3-PORT-02), offboarding
// (W-P3-OFFB-01) and the stuck-connecting reconciler. Each of them holds the
// entry for the whole read-modify-write of users/<userKey>/<provider>, and
// every consent.store Delete of that key runs under it too, so no writer can
// resurrect a token another one just deleted.
//
// One *GrantLocks is shared by all of them (the control plane builds it once);
// the zero value is not usable, use NewGrantLocks. Entries are reference
// counted and removed when idle, so the map never outgrows the set of grants in
// flight. It is per process: with several CP replicas the compare-and-set
// transitions in GrantStore are what keep the metadata consistent.
type GrantLocks struct {
	mu      sync.Mutex
	entries map[string]*grantLock
}

type grantLock struct {
	mu   sync.Mutex
	refs int
}

// NewGrantLocks returns an empty lock set.
func NewGrantLocks() *GrantLocks {
	return &GrantLocks{entries: make(map[string]*grantLock)}
}

// Lock blocks until the caller holds the (userKey, provider) entry and returns
// the function that releases it. Calling the function more than once is safe.
func (l *GrantLocks) Lock(userKey, provider string) (unlock func()) {
	key := userKey + "\x00" + provider
	l.mu.Lock()
	e := l.entries[key]
	if e == nil {
		e = &grantLock{}
		l.entries[key] = e
	}
	e.refs++
	l.mu.Unlock()

	e.mu.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			e.mu.Unlock()
			l.mu.Lock()
			e.refs--
			if e.refs == 0 {
				delete(l.entries, key)
			}
			l.mu.Unlock()
		})
	}
}

// Held returns how many entries are currently held or awaited (tests use it to
// show the set drains).
func (l *GrantLocks) Held() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
