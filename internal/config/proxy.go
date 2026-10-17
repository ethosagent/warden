package config

import (
	"fmt"
	"net"
	"strings"
)

// ProxyMode selects what a worker's proxy listens for (#376).
//
//   - forward (the default): the explicit CONNECT proxy on `listen`, exactly as
//     before this block existed.
//   - transparent: the interception listeners only (`proxy.transparent.*`) —
//     raw TLS on httpsListen (SNI-gated) and, when httpListen is set, plain
//     HTTP. The CONNECT listener does not exist.
//   - both: the CONNECT listener AND the transparent listeners.
type ProxyMode string

const (
	ProxyModeForward     ProxyMode = "forward"
	ProxyModeTransparent ProxyMode = "transparent"
	ProxyModeBoth        ProxyMode = "both"
)

// DefaultProxyMode is the mode when the proxy block is absent: the explicit
// forward proxy, byte-identical to before #376.
const DefaultProxyMode = ProxyModeForward

// ProxyConfig is the LOCAL-ONLY interception-mode block (`proxy:`). Like every
// listen/CA setting it is consumed once at worker assembly, so it never travels
// to a worker over the control-plane wire: json:"-" keeps a CP-served policy
// from choosing how a worker is reachable.
type ProxyConfig struct {
	Mode        ProxyMode         `json:"-"`
	Transparent TransparentConfig `json:"-"`
}

// TransparentConfig holds the transparent interception listeners. Plain HTTP is
// OFF unless HTTPListen is set; HTTPSListen is required whenever the mode is
// transparent or both.
type TransparentConfig struct {
	HTTPSListen string `json:"-"`
	HTTPListen  string `json:"-"`
}

// rawProxy mirrors the `proxy:` YAML block.
type rawProxy struct {
	Mode        string          `yaml:"mode"`
	Transparent *rawTransparent `yaml:"transparent"`
}

type rawTransparent struct {
	HTTPSListen string `yaml:"httpsListen"`
	HTTPListen  string `yaml:"httpListen"`
}

// parseProxy normalizes the proxy block. The mode DEFAULT is deliberately NOT
// applied here: an absent block parses to the zero value so `Policy.Proxy.Mode`
// stays "" and ResolveListen reports the forward default with SourceDefault,
// exactly like every other defaulted setting.
func parseProxy(raw *rawProxy) ProxyConfig {
	if raw == nil {
		return ProxyConfig{}
	}
	pc := ProxyConfig{
		Mode: ProxyMode(strings.ToLower(strings.TrimSpace(raw.Mode))),
	}
	if raw.Transparent != nil {
		pc.Transparent = TransparentConfig{
			HTTPSListen: strings.TrimSpace(raw.Transparent.HTTPSListen),
			HTTPListen:  strings.TrimSpace(raw.Transparent.HTTPListen),
		}
	}
	return pc
}

// transparentMode reports whether the mode serves the transparent listeners at
// all. An empty mode is forward (handled by the caller's default), so only the
// two explicit transparent modes count here.
func (pc ProxyConfig) transparentMode() bool {
	return pc.Mode == ProxyModeTransparent || pc.Mode == ProxyModeBoth
}

// validateProxyMode enforces the strict boot-time rules on the proxy block:
// the mode is one of the declared three, a transparent mode has its TLS
// listener, and a forward mode carries no dead transparent keys (a typo'd or
// leftover key under forward would otherwise be silently ignored).
func validateProxyMode(p ProxyConfig) error {
	switch p.Mode {
	case "", ProxyModeForward, ProxyModeTransparent, ProxyModeBoth:
	default:
		return fmt.Errorf("config: proxy.mode %q is invalid; must be one of: forward, transparent, both", p.Mode)
	}
	if !p.transparentMode() {
		if p.Transparent.HTTPSListen != "" || p.Transparent.HTTPListen != "" {
			return fmt.Errorf("config: proxy.transparent set but proxy.mode is forward; set proxy.mode to transparent or both, or remove the block")
		}
		return nil
	}
	if p.Transparent.HTTPSListen == "" {
		return fmt.Errorf("config: proxy.transparent.httpsListen is required when proxy.mode is %q (plain HTTP via httpListen is optional)", p.Mode)
	}
	return nil
}

// wildcardHosts are the host spellings that mean "every interface" in a listen
// address; any of them overlaps any other host on the same port.
var wildcardHosts = map[string]bool{"": true, "0.0.0.0": true, "::": true}

// listenAddrsClash reports whether two listen addresses would bind the same
// socket: the same port and overlapping hosts (equal hosts, or either side a
// wildcard). Port 0 never clashes — the kernel hands out distinct ephemeral
// ports, so two :0 binds cannot collide by construction.
func listenAddrsClash(a, b string) bool {
	ha, pa, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	hb, pb, err := net.SplitHostPort(b)
	if err != nil {
		return false
	}
	if pa != pb {
		return false
	}
	if pa == "0" {
		return false
	}
	if wildcardHosts[ha] || wildcardHosts[hb] {
		return true
	}
	return policyhostsEqual(ha, hb)
}

// policyhostsEqual compares two host literals case-insensitively (listen
// addresses are literals, never patterns).
func policyhostsEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// resolveTransparent applies config-only precedence to the transparent
// listeners and validates them, plus the cross-listener clash and CA rules that
// need the RESOLVED forward/admin addresses (which may carry flag values and
// defaults the raw config never saw).
func resolveTransparent(r *Resolved, pol Policy) error {
	if pol.Proxy.Transparent.HTTPSListen != "" {
		r.TransparentHTTPS = Setting{pol.Proxy.Transparent.HTTPSListen, "config proxy.transparent.httpsListen:"}
	}
	if pol.Proxy.Transparent.HTTPListen != "" {
		r.TransparentHTTP = Setting{pol.Proxy.Transparent.HTTPListen, "config proxy.transparent.httpListen:"}
	}
	for _, s := range []Setting{r.TransparentHTTPS, r.TransparentHTTP} {
		if s.Value == "" {
			continue
		}
		if err := validateAddr(s); err != nil {
			return fmt.Errorf("config: %v", err)
		}
	}
	if !pol.Proxy.transparentMode() {
		return nil
	}
	// A transparent mode intercepts by re-terminating TLS: without the CA it
	// could only fail every handshake, so refuse at boot with the reason named.
	if r.CACert.Value == "" {
		return fmt.Errorf("config: proxy.mode %q intercepts TLS and requires a CA: set tls.caCert/tls.caKey (or --ca-cert/--ca-key)", pol.Proxy.Mode)
	}
	// The admin listener binds in every mode.
	for name, s := range map[string]Setting{"httpsListen": r.TransparentHTTPS, "httpListen": r.TransparentHTTP} {
		if s.Value == "" {
			continue
		}
		if listenAddrsClash(s.Value, r.AdminListen.Value) {
			return fmt.Errorf("config: proxy.transparent.%s %s clashes with the admin listener on %s; choose a different port", name, s.Value, r.AdminListen.Value)
		}
	}
	// The two transparent listeners must not collide with each other.
	if r.TransparentHTTPS.Value != "" && r.TransparentHTTP.Value != "" &&
		listenAddrsClash(r.TransparentHTTPS.Value, r.TransparentHTTP.Value) {
		return fmt.Errorf("config: proxy.transparent.httpsListen %s clashes with proxy.transparent.httpListen %s; choose a different port",
			r.TransparentHTTPS.Value, r.TransparentHTTP.Value)
	}
	// In `both` mode the forward CONNECT listener also binds, so the transparent
	// listeners must avoid it too. Plain `transparent` does not bind it.
	if pol.Proxy.Mode == ProxyModeBoth {
		for name, s := range map[string]Setting{"httpsListen": r.TransparentHTTPS, "httpListen": r.TransparentHTTP} {
			if s.Value == "" {
				continue
			}
			if listenAddrsClash(s.Value, r.Listen.Value) {
				return fmt.Errorf("config: proxy.transparent.%s %s clashes with the forward listener on %s; choose a different port",
					name, s.Value, r.Listen.Value)
			}
		}
	}
	return nil
}
