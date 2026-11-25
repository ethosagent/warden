package oidc

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

func TestJWKSRotation(t *testing.T) {
	old := newRSASigner(t, "old")
	srv := newJWKSServer(t, "", old)
	clk := &clock{t: testNow}
	v := newTestVerifier(t, srv, clk, nil)
	if _, st, _ := v.Verify(ctx2s(t), old.sign(baseClaims(srv.URL, testNow))); st != identity.StatusValid {
		t.Fatalf("first: %s", st)
	}
	if srv.hits.Load() != 1 {
		t.Fatalf("hits = %d", srv.hits.Load())
	}

	fresh := newECSigner(t, "new")
	srv.setKeys(old, fresh)
	clk.advance(31 * time.Second)
	if _, st, r := v.Verify(ctx2s(t), fresh.sign(baseClaims(srv.URL, clk.now()))); st != identity.StatusValid {
		t.Fatalf("new kid: %s/%s", st, r)
	}
	if srv.hits.Load() != 2 {
		t.Fatalf("hits after rotation = %d, want 2", srv.hits.Load())
	}

	ghost := newRSASigner(t, "ghost")
	before := srv.hits.Load()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, st, r := v.Verify(ctx2s(t), ghost.sign(baseClaims(srv.URL, clk.now())))
			if st != identity.StatusInvalid || r != identity.ReasonUnknownKID {
				t.Errorf("ghost: %s/%s", st, r)
			}
		}()
	}
	wg.Wait()
	if d := srv.hits.Load() - before; d > 1 {
		t.Errorf("unknown-kid storm caused %d fetches, want <= 1", d)
	}
}

func TestKeysetKeepsLastGood(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	clk := &clock{t: testNow}
	v := newTestVerifier(t, srv, clk, nil)
	if _, st, _ := v.Verify(ctx2s(t), sg.sign(baseClaims(srv.URL, testNow))); st != identity.StatusValid {
		t.Fatal(st)
	}
	srv.status.Store(500)
	clk.advance(31 * time.Second)
	// A fresh token (cache miss) with an unknown kid forces a failing refetch.
	// The issuer is unreachable, so the kid may be a rotated key: unverified.
	ghost := newRSASigner(t, "ghost")
	if _, st, r := v.Verify(ctx2s(t), ghost.sign(baseClaims(srv.URL, clk.now()))); st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
		t.Errorf("ghost after failed refetch: %s/%s", st, r)
	}
	c := baseClaims(srv.URL, clk.now())
	c["sub"] = "suite-user"
	c["email"] = "different@example.com"
	if _, st, _ := v.Verify(ctx2s(t), sg.sign(c)); st != identity.StatusValid {
		t.Errorf("known kid after outage: %s", st)
	}
}

// TestKeysetOutageDuringRotation: an IdP outage that overlaps a key rotation
// must not turn the new kid into a permanent unknown_kid (subject_invalid at
// the token endpoint, which forces a re-login). While the latest fetch has
// failed, an unknown kid is jwks_unavailable; known kids keep verifying; the
// refetch floor still bounds fetches; once a fetch succeeds an absent kid is
// unknown_kid again.
func TestKeysetOutageDuringRotation(t *testing.T) {
	k1 := newRSASigner(t, "k1")
	rotated := newECSigner(t, "rotated")
	srv := newJWKSServer(t, "", k1)
	clk := &clock{t: testNow}
	v := newTestVerifier(t, srv, clk, nil)
	fresh := func(sub string) map[string]any {
		c := baseClaims(srv.URL, clk.now())
		c["sub"] = sub // a distinct token each time, so the result cache never answers
		return c
	}
	if _, st, r := v.Verify(ctx2s(t), k1.sign(fresh("load"))); st != identity.StatusValid {
		t.Fatalf("initial load: %s/%s", st, r)
	}

	// The IdP goes down; the rotated kid triggers one failing refetch.
	srv.status.Store(503)
	clk.advance(31 * time.Second)
	before := srv.hits.Load()
	if _, st, r := v.Verify(ctx2s(t), rotated.sign(fresh("outage-1"))); st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
		t.Fatalf("unknown kid during outage: %s/%s, want unverified/jwks_unavailable", st, r)
	}
	if d := srv.hits.Load() - before; d != 1 {
		t.Fatalf("refetch during outage: %d fetches, want 1", d)
	}

	// Inside the floor after the failure: known kid verifies from the cache,
	// unknown kids stay unavailable, and random kids cause no fetch storm.
	clk.advance(5 * time.Second)
	before = srv.hits.Load()
	if _, st, r := v.Verify(ctx2s(t), k1.sign(fresh("known"))); st != identity.StatusValid {
		t.Errorf("known kid during outage: %s/%s", st, r)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := rotated
			if i%2 == 0 {
				s = newECSigner(t, "random-"+strconv.Itoa(i))
			}
			_, st, r := v.Verify(ctx2s(t), s.sign(fresh("storm")))
			if st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
				t.Errorf("unknown kid inside floor: %s/%s", st, r)
			}
		}(i)
	}
	wg.Wait()
	if d := srv.hits.Load() - before; d != 0 {
		t.Errorf("inside the floor: %d fetches, want 0", d)
	}

	// The IdP is back but still does not publish the kid: genuinely unknown.
	srv.status.Store(0)
	clk.advance(31 * time.Second)
	before = srv.hits.Load()
	if _, st, r := v.Verify(ctx2s(t), rotated.sign(fresh("back-absent"))); st != identity.StatusInvalid || r != identity.ReasonUnknownKID {
		t.Errorf("IdP back, kid absent: %s/%s, want invalid/unknown_kid", st, r)
	}
	if d := srv.hits.Load() - before; d != 1 {
		t.Errorf("refetch after recovery: %d fetches, want 1", d)
	}
	// Inside the floor after a success, an absent kid stays unknown_kid.
	if _, st, r := v.Verify(ctx2s(t), rotated.sign(fresh("back-absent-2"))); st != identity.StatusInvalid || r != identity.ReasonUnknownKID {
		t.Errorf("kid absent inside floor after success: %s/%s", st, r)
	}

	// The IdP publishes the rotated key: it verifies after the floor.
	srv.setKeys(k1, rotated)
	clk.advance(31 * time.Second)
	if _, st, r := v.Verify(ctx2s(t), rotated.sign(fresh("back-present"))); st != identity.StatusValid {
		t.Errorf("IdP back with kid: %s/%s", st, r)
	}
}

func TestIssuerDown(t *testing.T) {
	t.Run("closed", func(t *testing.T) {
		sg := newRSASigner(t, "k1")
		srv := newJWKSServer(t, "", sg)
		tok := sg.sign(baseClaims(srv.URL, testNow))
		srv.Close()
		start := time.Now()
		v := newTestVerifier(t, srv, &clock{t: testNow}, nil)
		if time.Since(start) > 50*time.Millisecond {
			t.Error("constructor blocked")
		}
		_, st, r := v.Verify(ctx2s(t), tok)
		if st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
			t.Errorf("got %s/%s", st, r)
		}
	})
	t.Run("hung", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
			}
		}()
		sg := newRSASigner(t, "k1")
		base := "http://" + ln.Addr().String()
		v, err := NewOIDCVerifier(Config{Issuer: base, Audience: "warden", InternalIssuerURL: base, Now: (&clock{t: testNow}).now})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := ctxTimeout(200 * time.Millisecond)
		defer cancel()
		start := time.Now()
		_, st, r := v.Verify(ctx, sg.sign(baseClaims(base, testNow)))
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("took %v", d)
		}
		if st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
			t.Errorf("got %s/%s", st, r)
		}
	})
}
