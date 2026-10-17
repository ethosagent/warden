package config

import (
	"strings"
	"testing"
)

// The `proxy:` block (#376) selects the interception mode and the transparent
// listeners. These tests pin the YAML surface, the strict validation (unknown
// mode, a transparent mode with no listener, forward-mode leftovers) and the
// boot-time resolution (mode default, clash detection against the forward and
// admin listeners, CA requirement).

func TestParseProxyBlock(t *testing.T) {
	p, err := parse([]byte(`
proxy:
  mode: both
  transparent:
    httpsListen: ":443"
    httpListen: ":80"
policy:
  allowlist:
    - domain: example.com
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.Proxy.Mode != ProxyModeBoth {
		t.Errorf("mode = %q, want %q", pol.Proxy.Mode, ProxyModeBoth)
	}
	if pol.Proxy.Transparent.HTTPSListen != ":443" || pol.Proxy.Transparent.HTTPListen != ":80" {
		t.Errorf("transparent listeners = %+v", pol.Proxy.Transparent)
	}
}

func TestProxyMode_DefaultsToForward(t *testing.T) {
	// An absent proxy block is byte-identical to before: mode resolves to
	// forward and no transparent listener serves.
	p, err := parse([]byte("policy:\n  allowlist:\n    - domain: example.com\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.Proxy.Mode != "" {
		t.Errorf("absent block: mode = %q, want empty", pol.Proxy.Mode)
	}
	r, err := ResolveListen(pol, ListenFlags{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Mode.Value != string(ProxyModeForward) || r.Mode.Source != SourceDefault {
		t.Errorf("resolved mode = %+v, want default forward", r.Mode)
	}
	if r.TransparentHTTPS.Value != "" || r.TransparentHTTP.Value != "" {
		t.Errorf("resolved transparent listeners = %+v / %+v, want empty", r.TransparentHTTPS, r.TransparentHTTP)
	}
}

func TestParseProxy_UnknownModeFails(t *testing.T) {
	_, err := parse([]byte(`
proxy:
  mode: sneaky
policy:
  allowlist:
    - domain: example.com
`))
	if err == nil || !strings.Contains(err.Error(), "proxy.mode") {
		t.Fatalf("error = %v, want one naming proxy.mode", err)
	}
}

func TestParseProxy_UnknownKeyFails(t *testing.T) {
	// KnownFields(true) means a typo'd transparent key fails at load, not silently.
	_, err := parse([]byte(`
proxy:
  mode: transparent
  transparent:
    httpsListen: ":443"
    htpsListen: ":80"
policy:
  allowlist:
    - domain: example.com
`))
	if err == nil {
		t.Fatal("expected an unknown-key error")
	}
}

func TestValidateProxyMode(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string // substring of the expected error; "" = must parse
	}{
		{
			name: "transparent needs httpsListen",
			yaml: "proxy:\n  mode: transparent\n",
			want: "proxy.transparent.httpsListen",
		},
		{
			name: "both needs httpsListen",
			yaml: "proxy:\n  mode: both\n",
			want: "proxy.transparent.httpsListen",
		},
		{
			name: "transparent with only httpListen",
			yaml: "proxy:\n  mode: transparent\n  transparent:\n    httpListen: \":80\"\n",
			want: "proxy.transparent.httpsListen",
		},
		{
			name: "forward with transparent keys set",
			yaml: "proxy:\n  mode: forward\n  transparent:\n    httpsListen: \":443\"\n",
			want: "proxy.mode is forward",
		},
		{
			name: "default forward with transparent keys set",
			yaml: "proxy:\n  transparent:\n    httpsListen: \":443\"\n",
			want: "proxy.mode is forward",
		},
		{
			name: "transparent with httpsListen only",
			yaml: "proxy:\n  mode: transparent\n  transparent:\n    httpsListen: \":443\"\n",
			want: "",
		},
		{
			name: "both with both listeners",
			yaml: "proxy:\n  mode: both\n  transparent:\n    httpsListen: \":443\"\n    httpListen: \":80\"\n",
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := tc.yaml + "policy:\n  allowlist:\n    - domain: example.com\n"
			_, err := parse([]byte(doc))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestResolveListen_Transparent(t *testing.T) {
	pol := Policy{
		TLS: TLSConfig{CACert: "ca.crt", CAKey: "ca.key"},
		Proxy: ProxyConfig{
			Mode:        ProxyModeBoth,
			Transparent: TransparentConfig{HTTPSListen: ":443", HTTPListen: ":80"},
		},
	}
	r, err := ResolveListen(pol, ListenFlags{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Mode.Value != "both" || r.Mode.Source != "config proxy.mode:" {
		t.Errorf("mode = %+v", r.Mode)
	}
	if r.TransparentHTTPS.Value != ":443" || r.TransparentHTTPS.Source != "config proxy.transparent.httpsListen:" {
		t.Errorf("https listener = %+v", r.TransparentHTTPS)
	}
	if r.TransparentHTTP.Value != ":80" || r.TransparentHTTP.Source != "config proxy.transparent.httpListen:" {
		t.Errorf("http listener = %+v", r.TransparentHTTP)
	}
}

func TestResolveListen_TransparentErrors(t *testing.T) {
	tests := []struct {
		name  string
		pol   Policy
		flags ListenFlags
		want  []string
	}{
		{
			name: "transparent without CA",
			pol: Policy{
				Proxy: ProxyConfig{Mode: ProxyModeTransparent,
					Transparent: TransparentConfig{HTTPSListen: ":443"}},
			},
			want: []string{"CA", "proxy.mode"},
		},
		{
			name: "both without CA",
			pol: Policy{
				Proxy: ProxyConfig{Mode: ProxyModeBoth,
					Transparent: TransparentConfig{HTTPSListen: ":443"}},
			},
			want: []string{"CA"},
		},
		{
			name: "httpsListen clashes with the forward listen",
			pol: Policy{
				Listen: ":8443",
				TLS:    TLSConfig{CACert: "ca.crt", CAKey: "ca.key"},
				Proxy: ProxyConfig{Mode: ProxyModeBoth,
					Transparent: TransparentConfig{HTTPSListen: "0.0.0.0:8443"}},
			},
			want: []string{"clash", ":8443"},
		},
		{
			name: "httpListen clashes with the admin listen default",
			pol: Policy{
				TLS: TLSConfig{CACert: "ca.crt", CAKey: "ca.key"},
				Proxy: ProxyConfig{Mode: ProxyModeBoth,
					Transparent: TransparentConfig{HTTPSListen: ":443", HTTPListen: ":9090"}},
			},
			want: []string{"clash", DefaultAdminListen},
		},
		{
			name: "transparent listeners clash with each other",
			pol: Policy{
				TLS: TLSConfig{CACert: "ca.crt", CAKey: "ca.key"},
				Proxy: ProxyConfig{Mode: ProxyModeBoth,
					Transparent: TransparentConfig{HTTPSListen: ":443", HTTPListen: ":443"}},
			},
			want: []string{"clash"},
		},
		{
			name: "bad transparent address",
			pol: Policy{
				TLS: TLSConfig{CACert: "ca.crt", CAKey: "ca.key"},
				Proxy: ProxyConfig{Mode: ProxyModeTransparent,
					Transparent: TransparentConfig{HTTPSListen: "nonsense"}},
			},
			want: []string{"proxy.transparent.httpsListen"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveListen(tc.pol, tc.flags)
			if err == nil {
				t.Fatal("expected error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q missing %q", err, w)
				}
			}
		})
	}
}

func TestResolveListen_TransparentModeNoForwardClash(t *testing.T) {
	// In transparent mode the forward CONNECT listener is NOT bound, so a
	// transparent listener on the same port as `listen` is not a clash — the
	// agent-facing proxy port simply does not exist.
	pol := Policy{
		Listen: ":443",
		TLS:    TLSConfig{CACert: "ca.crt", CAKey: "ca.key"},
		Proxy: ProxyConfig{Mode: ProxyModeTransparent,
			Transparent: TransparentConfig{HTTPSListen: ":443"}},
	}
	r, err := ResolveListen(pol, ListenFlags{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.TransparentHTTPS.Value != ":443" {
		t.Errorf("https listener = %+v", r.TransparentHTTPS)
	}
}

func TestResolveListen_PortZeroNeverClashes(t *testing.T) {
	// Port 0 asks the kernel for an ephemeral port: two such binds can never
	// land on the same socket, so the clash check must stay quiet — the harness
	// boots every listener on 127.0.0.1:0.
	pol := Policy{
		Listen: "127.0.0.1:0",
		TLS:    TLSConfig{CACert: "ca.crt", CAKey: "ca.key"},
		Proxy: ProxyConfig{Mode: ProxyModeBoth,
			Transparent: TransparentConfig{HTTPSListen: "127.0.0.1:0", HTTPListen: "127.0.0.1:0"}},
	}
	if _, err := ResolveListen(pol, ListenFlags{AdminListen: "127.0.0.1:0"}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
}
