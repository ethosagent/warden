package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// signInIssuer is an httptest issuer with a discovery document and a device
// endpoint, with levers for the failure modes.
type signInIssuer struct {
	srv      *httptest.Server
	disc     atomic.Int64
	starts   atomic.Int64
	mu       sync.Mutex
	status   int
	gate     chan struct{} // when set, the device endpoint waits on it
	override func(map[string]any)
	expires  int
}

func newSignInIssuer(t *testing.T) *signInIssuer {
	t.Helper()
	si := &signInIssuer{expires: 300}
	si.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dex/.well-known/openid-configuration":
			si.disc.Add(1)
			doc := map[string]any{
				"issuer":                        si.issuer(),
				"token_endpoint":                si.issuer() + "/token",
				"device_authorization_endpoint": si.issuer() + "/device/code",
			}
			si.mu.Lock()
			if si.override != nil {
				si.override(doc)
			}
			si.mu.Unlock()
			_ = json.NewEncoder(w).Encode(doc)
		case "/dex/device/code":
			n := si.starts.Add(1)
			si.mu.Lock()
			status, gate, expires := si.status, si.gate, si.expires
			si.mu.Unlock()
			if gate != nil {
				<-gate
			}
			if status != 0 {
				http.Error(w, "no", status)
				return
			}
			_ = r.ParseForm()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": fmt.Sprintf("dc-%d", n), "user_code": fmt.Sprintf("UC-%d", n),
				"verification_uri":          si.issuer() + "/device",
				"verification_uri_complete": si.issuer() + "/device?user_code=" + fmt.Sprintf("UC-%d", n),
				"expires_in":                expires, "interval": 5,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(si.srv.Close)
	return si
}

func (si *signInIssuer) issuer() string { return si.srv.URL + "/dex" }

func (si *signInIssuer) set(f func(*signInIssuer)) {
	si.mu.Lock()
	defer si.mu.Unlock()
	f(si)
}

type tclock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *tclock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *tclock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestStarter(t *testing.T, si *signInIssuer, clk *tclock, maxPending, perMinute int) *DeviceStarter {
	t.Helper()
	d, err := NewDeviceStarter(DeviceStarterConfig{
		Issuer: si.issuer(), ClientID: "warden-cli", Scopes: []string{"openid", "email"},
		MaxPending: maxPending, StartsPerMinute: perMinute,
		HTTP: &http.Client{Timeout: 5 * time.Second}, Now: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDeviceStarterStartReuseExpire(t *testing.T) {
	si := newSignInIssuer(t)
	clk := &tclock{t: time.Now()}
	d := newTestStarter(t, si, clk, 8, 100)
	ctx := context.Background()

	o1, out := d.Start(ctx, "a")
	if out != SignInStarted || o1.DeviceCode != "dc-1" || o1.ClientID != "warden-cli" || o1.Issuer != si.issuer() ||
		o1.TokenEndpoint != si.issuer()+"/token" || o1.Interval != 5 || o1.ExpiresIn != 300 {
		t.Fatalf("first: %v %+v", out, o1)
	}
	clk.advance(100 * time.Second)
	o2, out := d.Start(ctx, "a")
	if out != SignInReused || o2.DeviceCode != "dc-1" || o2.ExpiresIn != 200 {
		t.Fatalf("reuse: %v %+v (expires_in must count down)", out, o2)
	}
	if si.starts.Load() != 1 || si.disc.Load() != 1 {
		t.Fatalf("issuer saw %d starts, %d discoveries, want 1 and 1", si.starts.Load(), si.disc.Load())
	}
	// Reuse ends 30s before the offer expires.
	clk.advance(169 * time.Second)
	if _, out := d.Start(ctx, "a"); out != SignInReused {
		t.Fatalf("at expires-31s: %v, want reused", out)
	}
	clk.advance(2 * time.Second)
	o3, out := d.Start(ctx, "a")
	if out != SignInStarted || o3.DeviceCode != "dc-2" {
		t.Fatalf("after the reuse window: %v %+v, want a new start", out, o3)
	}
	// Another agent is independent.
	if o, out := d.Start(ctx, "b"); out != SignInStarted || o.DeviceCode != "dc-3" {
		t.Fatalf("agent b: %v %+v", out, o)
	}
	if si.disc.Load() != 1 {
		t.Errorf("discovery ran %d times, want once", si.disc.Load())
	}
}

func TestDeviceStarterForget(t *testing.T) {
	si := newSignInIssuer(t)
	d := newTestStarter(t, si, &tclock{t: time.Now()}, 8, 100)
	d.Forget("a") // nothing pending: a no-op
	o1, _ := d.Start(context.Background(), "a")
	d.Forget("a")
	o2, out := d.Start(context.Background(), "a")
	if out != SignInStarted || o2.DeviceCode == o1.DeviceCode {
		t.Fatalf("after Forget: %v %+v, want a new start", out, o2)
	}
}

func TestDeviceStarterSingleFlight(t *testing.T) {
	si := newSignInIssuer(t)
	gate := make(chan struct{})
	si.set(func(s *signInIssuer) { s.gate = gate })
	d := newTestStarter(t, si, &tclock{t: time.Now()}, 8, 100)

	const n = 50
	outs := make([]SignInOutcome, n)
	codes := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, out := d.Start(context.Background(), "a")
			outs[i], codes[i] = out, o.DeviceCode
		}()
	}
	// Let the leader reach the issuer, and the rest queue behind it.
	deadline := time.Now().Add(5 * time.Second)
	for si.starts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	if got := si.starts.Load(); got != 1 {
		t.Fatalf("%d device authorizations for %d concurrent starts, want 1", got, n)
	}
	started := 0
	for i := range n {
		if codes[i] != "dc-1" {
			t.Fatalf("start %d got code %q", i, codes[i])
		}
		if outs[i] == SignInStarted {
			started++
		}
	}
	if started != 1 {
		t.Errorf("%d starters, want exactly one leader", started)
	}
}

func TestDeviceStarterFailuresAreNotCached(t *testing.T) {
	si := newSignInIssuer(t)
	d := newTestStarter(t, si, &tclock{t: time.Now()}, 8, 100)
	si.set(func(s *signInIssuer) { s.status = 500 })
	if o, out := d.Start(context.Background(), "a"); out != SignInIssuerUnreachable || o.DeviceCode != "" {
		t.Fatalf("failing issuer: %v %+v", out, o)
	}
	si.set(func(s *signInIssuer) { s.status = 0 })
	if _, out := d.Start(context.Background(), "a"); out != SignInStarted {
		t.Fatalf("after recovery: %v, want started", out)
	}
}

func TestDeviceStarterBounds(t *testing.T) {
	t.Run("maxPending", func(t *testing.T) {
		si := newSignInIssuer(t)
		d := newTestStarter(t, si, &tclock{t: time.Now()}, 2, 100)
		for _, a := range []string{"a", "b"} {
			if _, out := d.Start(context.Background(), a); out != SignInStarted {
				t.Fatalf("%s: %v", a, out)
			}
		}
		if _, out := d.Start(context.Background(), "c"); out != SignInRateLimited {
			t.Fatalf("third agent over maxPending: %v, want rate_limited", out)
		}
		if _, out := d.Start(context.Background(), "a"); out != SignInReused {
			t.Fatalf("an existing offer is still served at the bound: %v", out)
		}
		if si.starts.Load() != 2 {
			t.Errorf("%d starts, want 2", si.starts.Load())
		}
	})
	t.Run("startsPerMinute", func(t *testing.T) {
		si := newSignInIssuer(t)
		clk := &tclock{t: time.Now()}
		d := newTestStarter(t, si, clk, 100, 3)
		for _, a := range []string{"a", "b", "c"} {
			if _, out := d.Start(context.Background(), a); out != SignInStarted {
				t.Fatalf("%s: %v", a, out)
			}
		}
		if _, out := d.Start(context.Background(), "d"); out != SignInRateLimited {
			t.Fatalf("fourth start in a minute: %v, want rate_limited", out)
		}
		clk.advance(20 * time.Second) // one token back (3 per minute)
		if _, out := d.Start(context.Background(), "d"); out != SignInStarted {
			t.Fatalf("after a refill: %v, want started", out)
		}
		if _, out := d.Start(context.Background(), "e"); out != SignInRateLimited {
			t.Fatalf("bucket empty again: %v", out)
		}
	})
}

func TestDeviceStarterRejectsMisbehavingIssuer(t *testing.T) {
	cases := map[string]func(*signInIssuer){
		"discovery names another issuer": func(s *signInIssuer) {
			s.override = func(d map[string]any) { d["issuer"] = "http://other.example/dex" }
		},
		"device endpoint on another origin": func(s *signInIssuer) {
			s.override = func(d map[string]any) { d["device_authorization_endpoint"] = "http://evil.example/device" }
		},
		"token endpoint on another origin": func(s *signInIssuer) {
			s.override = func(d map[string]any) { d["token_endpoint"] = "http://evil.example/token" }
		},
		"no device endpoint": func(s *signInIssuer) {
			s.override = func(d map[string]any) { delete(d, "device_authorization_endpoint") }
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			si := newSignInIssuer(t)
			si.set(mut)
			d := newTestStarter(t, si, &tclock{t: time.Now()}, 8, 100)
			if o, out := d.Start(context.Background(), "a"); out != SignInIssuerUnreachable || o.DeviceCode != "" {
				t.Fatalf("%v %+v, want issuer_unreachable", out, o)
			}
			if si.starts.Load() != 0 {
				t.Error("a device authorization was started against a rejected discovery document")
			}
		})
	}
}

func TestDeviceStarterOriginCheck(t *testing.T) {
	d, err := NewDeviceStarter(DeviceStarterConfig{
		Issuer: "https://idp.example.com/dex", ClientID: "c", MaxPending: 1, StartsPerMinute: 1, HTTP: &http.Client{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]bool{
		"https://idp.example.com/dex/device":                          true,
		"https://IDP.example.com:443/dex/device?x=1":                  true,
		"https://idp.example.com/other":                               true, // same origin; the path is the issuer's business
		"http://idp.example.com/dex/device":                           false,
		"https://idp.example.com:8443/dex/device":                     false,
		"https://evil.example.com/dex/device":                         false,
		"https://idp.example.com.evil.test/dex":                       false,
		"https://user@idp.example.com/dex/device":                     false,
		"https://idp.example.com@evil.test/dex":                       false,
		"javascript:alert(1)":                                         false,
		"//idp.example.com/dex":                                       false,
		"":                                                            false,
		"https://idp.example.com/" + strings.Repeat("a", maxURLBytes): false,
	} {
		if got := d.onIssuerOrigin(raw); got != want {
			t.Errorf("onIssuerOrigin(%.60q) = %v, want %v", raw, got, want)
		}
	}
}

func TestDeviceStarterRejectsBadOffers(t *testing.T) {
	for name, mut := range map[string]func(map[string]any){
		"no device_code":         func(m map[string]any) { delete(m, "device_code") },
		"no user_code":           func(m map[string]any) { delete(m, "user_code") },
		"huge device_code":       func(m map[string]any) { m["device_code"] = strings.Repeat("x", maxCodeBytes+1) },
		"foreign verification":   func(m map[string]any) { m["verification_uri"] = "https://evil.example/device" },
		"foreign complete":       func(m map[string]any) { m["verification_uri_complete"] = "https://evil.example/device?c=1" },
		"verification_uri empty": func(m map[string]any) { m["verification_uri"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				base := "http://" + r.Host + "/dex"
				if strings.HasSuffix(r.URL.Path, "openid-configuration") {
					_ = json.NewEncoder(w).Encode(map[string]any{"issuer": base, "token_endpoint": base + "/token", "device_authorization_endpoint": base + "/device/code"})
					return
				}
				m := map[string]any{"device_code": "d", "user_code": "u", "verification_uri": base + "/device", "verification_uri_complete": base + "/device?u=1", "expires_in": 60, "interval": 5}
				mut(m)
				_ = json.NewEncoder(w).Encode(m)
			}))
			defer srv.Close()
			d, _ := NewDeviceStarter(DeviceStarterConfig{Issuer: srv.URL + "/dex", ClientID: "c", MaxPending: 4, StartsPerMinute: 4, HTTP: srv.Client()})
			if _, out := d.Start(context.Background(), "a"); out != SignInIssuerUnreachable {
				t.Fatalf("%v, want issuer_unreachable", out)
			}
		})
	}
}

func TestDeviceStarterClampsTimings(t *testing.T) {
	si := newSignInIssuer(t)
	si.set(func(s *signInIssuer) { s.expires = 100000 })
	clk := &tclock{t: time.Now()}
	d := newTestStarter(t, si, clk, 8, 100)
	o, _ := d.Start(context.Background(), "a")
	if o.ExpiresIn != signInMaxExpires {
		t.Errorf("expires_in %d, want the %d cap", o.ExpiresIn, signInMaxExpires)
	}
	// A short offer is reused for half its life, not for a negative window.
	si2 := newSignInIssuer(t)
	si2.set(func(s *signInIssuer) { s.expires = 20 })
	clk2 := &tclock{t: time.Now()}
	d2 := newTestStarter(t, si2, clk2, 8, 100)
	_, _ = d2.Start(context.Background(), "a")
	clk2.advance(5 * time.Second)
	if _, out := d2.Start(context.Background(), "a"); out != SignInReused {
		t.Errorf("inside half of a 20s offer: %v, want reused", out)
	}
	clk2.advance(6 * time.Second)
	if _, out := d2.Start(context.Background(), "a"); out != SignInStarted {
		t.Errorf("past half of a 20s offer: %v, want a new start", out)
	}
}

func TestNewDeviceStarterValidates(t *testing.T) {
	for name, cfg := range map[string]DeviceStarterConfig{
		"no issuer":    {ClientID: "c", MaxPending: 1, StartsPerMinute: 1, HTTP: &http.Client{}},
		"bad scheme":   {Issuer: "ftp://x", ClientID: "c", MaxPending: 1, StartsPerMinute: 1, HTTP: &http.Client{}},
		"no client":    {Issuer: "https://x", MaxPending: 1, StartsPerMinute: 1, HTTP: &http.Client{}},
		"no http":      {Issuer: "https://x", ClientID: "c", MaxPending: 1, StartsPerMinute: 1},
		"zero pending": {Issuer: "https://x", ClientID: "c", StartsPerMinute: 1, HTTP: &http.Client{}},
		"zero rate":    {Issuer: "https://x", ClientID: "c", MaxPending: 1, HTTP: &http.Client{}},
	} {
		if _, err := NewDeviceStarter(cfg); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// BenchmarkDeviceStarterForget is the cost a valid request pays in challenge
// mode when no sign-in is pending: one atomic load, no lock.
func BenchmarkDeviceStarterForget(b *testing.B) {
	d, _ := NewDeviceStarter(DeviceStarterConfig{Issuer: "https://x", ClientID: "c", MaxPending: 1, StartsPerMinute: 1, HTTP: &http.Client{}})
	b.ReportAllocs()
	for b.Loop() {
		d.Forget("agent")
	}
}
