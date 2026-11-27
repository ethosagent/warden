package ratelimit_test

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/ratelimit"
)

func TestLimiterBucketRefills(t *testing.T) {
	l := ratelimit.NewLimiter(2, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow("k", now); !ok {
			t.Fatalf("call %d refused inside the burst", i+1)
		}
	}
	ok, wait := l.Allow("k", now)
	if ok || wait < time.Second {
		t.Fatalf("third call = %v, %v; want refused with a wait of at least 1s", ok, wait)
	}
	if ok, _ := l.Allow("other", now); !ok {
		t.Fatal("a second key shares the first key's bucket")
	}
	if ok, _ := l.Allow("k", now.Add(31*time.Second)); !ok {
		t.Fatal("the bucket did not refill after half the window")
	}
}

func TestLimiterBoundsKeys(t *testing.T) {
	l := ratelimit.NewLimiterSize(1, time.Minute, 3)
	now := time.Unix(1_700_000_000, 0)
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		l.Allow(k, now)
	}
	if n := l.Len(); n > 3 {
		t.Fatalf("Len = %d, want at most 3", n)
	}
}

func TestLimiterNeedsPositiveRate(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewLimiter(0, ...) did not panic")
		}
	}()
	ratelimit.NewLimiter(0, time.Minute)
}
