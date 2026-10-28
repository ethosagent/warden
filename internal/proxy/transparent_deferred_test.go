package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
)

// W-P1-GPOL-03 on the transparent listeners: no Proxy-Authorization exists
// there, so a Conditional destination always continues with deferIdentity, and
// every request on it is denied identity_required until GPOL-10 passes the
// request subject.
func TestTransparent_DeferredIdentity(t *testing.T) {
	scoped := []config.AllowlistEntry{{Domain: invHost, Groups: []string{"eng"}}}
	e := newTransparentEnv(t, transparentOpts{allow: scoped, plainHTTP: true})
	// wantNewDeny waits for a deny beyond the n already counted, so a later
	// subtest cannot pass on an earlier one's event.
	denies := func() int {
		n := 0
		for _, ev := range e.store.snapshot() {
			if ev.Decision == "deny" && ev.Reason == string(denyreason.IdentityRequired) {
				n++
			}
		}
		return n
	}
	wantNewDeny := func(t *testing.T, before int) {
		t.Helper()
		for i := 0; i < 1000 && denies() <= before; i++ {
			time.Sleep(5 * time.Millisecond)
		}
		if denies() <= before {
			t.Fatalf("no new identity_required deny; events: %+v", e.store.snapshot())
		}
	}

	t.Run("https continues and denies each request", func(t *testing.T) {
		before := denies()
		req, _ := http.NewRequest(http.MethodGet, "https://"+invHost+"/x", nil)
		_, status, err := e.doH1(invHost, req)
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", status)
		}
		wantNewDeny(t, before)
	})

	t.Run("https unknown protocol inside TLS is denied", func(t *testing.T) {
		before := denies()
		tc, err := e.tlsDialSNI(invHost)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tc.Close() }()
		_, _ = tc.Write([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"))
		_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.Copy(io.Discard, tc)
		wantNewDeny(t, before)
	})

	t.Run("plain http continues and denies the request", func(t *testing.T) {
		before := denies()
		conn, err := net.DialTimeout("tcp", e.httpAddr(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		req, _ := http.NewRequest(http.MethodGet, "http://"+invHost+"/x", nil)
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		wantNewDeny(t, before)
	})

	if n := e.tlsUpstreamDials(); n != 0 {
		t.Errorf("upstream TLS dials = %d, want 0", n)
	}
}
