package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseListenKeys(t *testing.T) {
	p, err := parse([]byte(`
listen: ":8443"
adminListen: "0.0.0.0:9191"
tls:
  caCert: /etc/warden/ca.crt
  caKey: /etc/warden/ca.key
policy:
  allowlist:
    - domain: example.com
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.Listen != ":8443" || pol.AdminListen != "0.0.0.0:9191" ||
		pol.TLS.CACert != "/etc/warden/ca.crt" || pol.TLS.CAKey != "/etc/warden/ca.key" {
		t.Fatalf("unexpected policy: %+v", pol)
	}
}

func TestResolveListen_Precedence(t *testing.T) {
	pol := Policy{Listen: ":8443", AdminListen: ":9191", TLS: TLSConfig{CACert: "c.crt", CAKey: "c.key"}}

	// Defaults when nothing is set.
	r, err := ResolveListen(Policy{}, ListenFlags{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Listen.Value != DefaultListen || r.Listen.Source != SourceDefault ||
		r.AdminListen.Value != DefaultAdminListen || r.AdminListen.Source != SourceDefault ||
		r.CACert.Value != "" || r.CAKey.Value != "" {
		t.Fatalf("defaults: %+v", r)
	}

	// Config beats default.
	r, err = ResolveListen(pol, ListenFlags{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Listen.Value != ":8443" || r.Listen.Source != "config listen:" ||
		r.AdminListen.Source != "config adminListen:" ||
		r.CACert.Value != "c.crt" || r.CACert.Source != "config tls.caCert:" ||
		r.CAKey.Source != "config tls.caKey:" {
		t.Fatalf("config: %+v", r)
	}

	// Flag beats config, per value.
	r, err = ResolveListen(pol, ListenFlags{Listen: "127.0.0.1:1", AdminListen: "127.0.0.1:2", CACert: "f.crt", CAKey: "f.key"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Listen.Value != "127.0.0.1:1" || r.Listen.Source != "flag --listen" ||
		r.AdminListen.Value != "127.0.0.1:2" || r.AdminListen.Source != "flag --admin-listen" ||
		r.CACert.Value != "f.crt" || r.CACert.Source != "flag --ca-cert" ||
		r.CAKey.Value != "f.key" || r.CAKey.Source != "flag --ca-key" {
		t.Fatalf("flags: %+v", r)
	}

	// A flag duplicating the config value is idempotent.
	r, err = ResolveListen(pol, ListenFlags{Listen: ":8443"})
	if err != nil || r.Listen.Value != ":8443" {
		t.Fatalf("idempotent: %+v %v", r, err)
	}
}

func TestResolveListen_Errors(t *testing.T) {
	tests := []struct {
		name  string
		pol   Policy
		flags ListenFlags
		want  []string
	}{
		{"bad listen flag", Policy{}, ListenFlags{Listen: "nonsense"}, []string{"from flag --listen", "nonsense"}},
		{"bad listen config", Policy{Listen: "host:notaport"}, ListenFlags{}, []string{"from config listen:", "host:notaport"}},
		{"port out of range", Policy{AdminListen: ":70000"}, ListenFlags{}, []string{"from config adminListen:", "70000"}},
		{"bad admin flag", Policy{}, ListenFlags{AdminListen: "x"}, []string{"from flag --admin-listen"}},
		{"cert only flag", Policy{}, ListenFlags{CACert: "a.crt"}, []string{"CA cert and key must be set together", "from flag --ca-cert", "key is unset"}},
		{"key only config", Policy{TLS: TLSConfig{CAKey: "a.key"}}, ListenFlags{}, []string{"from config tls.caKey:", "cert is unset"}},
		{"mixed sources", Policy{TLS: TLSConfig{CACert: "a.crt"}}, ListenFlags{}, []string{"from config tls.caCert:"}},
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

func TestResolved_LogFields(t *testing.T) {
	r, _ := ResolveListen(Policy{Listen: ":8443"}, ListenFlags{AdminListen: "127.0.0.1:1"})
	got := fmt.Sprint(r.LogArgs()...)
	for _, w := range []string{"listen", ":8443", "config listen:", "flag --admin-listen"} {
		if !strings.Contains(got, w) {
			t.Errorf("log args %q missing %q", got, w)
		}
	}
}
