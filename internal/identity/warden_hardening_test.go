package identity_test

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
)

// TestWardenIatAndTTLBounds: exp and iat are compared in seconds with no
// overflow, iat must be positive and not in the future.
func TestWardenIatAndTTLBounds(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	v := newWarden(t, nil)
	install(t, v, 1, testIssuer, nil, k1)
	now := wardenNow.Unix()
	cases := []struct {
		name     string
		iat, exp int64
		status   identity.Status
		reason   identity.Reason
	}{
		{"huge exp", now, math.MaxInt64, identity.StatusInvalid, identity.ReasonTTLTooLong},
		{"huge exp, tiny iat", 1, math.MaxInt64, identity.StatusInvalid, identity.ReasonTTLTooLong},
		{"negative iat", -1, now + 60, identity.StatusInvalid, identity.ReasonMalformed},
		{"very negative iat", math.MinInt64, now + 60, identity.StatusInvalid, identity.ReasonMalformed},
		{"zero iat", 0, now + 60, identity.StatusInvalid, identity.ReasonMalformed},
		{"iat in the future", now + 600, now + 900, identity.StatusInvalid, identity.ReasonMalformed},
		{"iat within skew", now + 30, now + 300, identity.StatusValid, ""},
		{"exp before iat", now, now - 10, identity.StatusInvalid, identity.ReasonMalformed},
		{"exp equals iat", now, now, identity.StatusInvalid, identity.ReasonMalformed},
		{"exactly 15m", now, now + 900, identity.StatusValid, ""},
		{"15m and a second", now, now + 901, identity.StatusInvalid, identity.ReasonTTLTooLong},
	}
	for _, tc := range cases {
		c := goodClaims()
		c["iat"], c["nbf"], c["exp"] = tc.iat, now, tc.exp
		if _, st, r := v.Verify(context.Background(), mint(t, k1, wardenHdr(), c)); st != tc.status || r != tc.reason {
			t.Errorf("%s: %s/%s, want %s/%s", tc.name, st, r, tc.status, tc.reason)
		}
	}
}

// TestWardenSwapNeverServesStaleResults: a Verify that was in flight while the
// snapshot was replaced at the same generation (or the skew changed) can store
// its result late; a later Verify must never find it.
func TestWardenSwapNeverServesStaleResults(t *testing.T) {
	k1, k2 := newSigner(t, keys.AlgEdDSA), newSigner(t, keys.AlgEdDSA)
	tok1 := mint(t, k1, wardenHdr(), goodClaims())
	ctx := context.Background()
	for i := 0; i < 300; i++ {
		v := newWarden(t, nil)
		install(t, v, 1, testIssuer, nil, k1)
		var wg sync.WaitGroup
		stop := make(chan struct{})
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						v.Verify(ctx, tok1)
					}
				}
			}()
		}
		install(t, v, 1, testIssuer, nil, k2) // same generation, K1 gone
		close(stop)
		wg.Wait()
		if _, st, r := v.Verify(ctx, tok1); st != identity.StatusInvalid || r != identity.ReasonUnknownKID {
			t.Fatalf("round %d: K1 token after the swap: %s/%s, want invalid/unknown_kid", i, st, r)
		}
	}
}

// TestWardenSkewChangeDropsResults: results cached under the old skew are not
// served after SetClockSkew.
func TestWardenSkewChangeDropsResults(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	var mu sync.Mutex
	now := wardenNow
	v, err := identity.NewWardenVerifier(identity.WardenConfig{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }, ClockSkew: 300 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	install(t, v, 1, testIssuer, nil, k1)
	tok := mint(t, k1, wardenHdr(), goodClaims()) // exp = now+300
	if _, st, _ := v.Verify(context.Background(), tok); st != identity.StatusValid {
		t.Fatal(st)
	}
	mu.Lock()
	now = wardenNow.Add(400 * time.Second) // inside exp+300s, past exp+30s
	mu.Unlock()
	if err := v.SetClockSkew(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	if _, st, _ := v.Verify(context.Background(), tok); st != identity.StatusExpired {
		t.Fatalf("after the skew shrank: %s, want expired", st)
	}
}
