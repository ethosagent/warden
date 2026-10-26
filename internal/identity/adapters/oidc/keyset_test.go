package oidc

import (
	"net"
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
	ghost := newRSASigner(t, "ghost")
	if _, st, r := v.Verify(ctx2s(t), ghost.sign(baseClaims(srv.URL, clk.now()))); st != identity.StatusInvalid || r != identity.ReasonUnknownKID {
		t.Errorf("ghost after failed refetch: %s/%s", st, r)
	}
	c := baseClaims(srv.URL, clk.now())
	c["sub"] = "suite-user"
	c["email"] = "different@example.com"
	if _, st, _ := v.Verify(ctx2s(t), sg.sign(c)); st != identity.StatusValid {
		t.Errorf("known kid after outage: %s", st)
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
