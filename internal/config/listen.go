package config

import (
	"fmt"
	"net"
	"strconv"
)

// Built-in defaults for the listeners (the lowest-precedence source).
const (
	DefaultListen      = "127.0.0.1:8080"
	DefaultAdminListen = "127.0.0.1:9090"
)

// Source labels name where an effective value came from, for startup logs and
// validation errors.
const SourceDefault = "default"

// TLSConfig holds the proxy CA key material paths (the `tls:` block).
type TLSConfig struct {
	CACert string
	CAKey  string
}

// rawTLS mirrors the `tls:` YAML block.
type rawTLS struct {
	CACert string `yaml:"caCert"`
	CAKey  string `yaml:"caKey"`
}

// ListenFlags carries the CLI flag values for the listener/CA settings. An empty
// string means the flag was not set explicitly, so cmd/ must only populate a
// field when cobra's Flags().Changed reports it.
type ListenFlags struct {
	Listen      string
	AdminListen string
	CACert      string
	CAKey       string
}

// Setting is one effective value plus a human-readable source.
type Setting struct {
	Value  string
	Source string
}

// Resolved is the effective listener/CA configuration after applying
// precedence: CLI flag > config key > built-in default. Mode and the
// transparent listeners (#376) are config-only (no flags): Mode defaults to
// forward, and an empty transparent listener means that port is not served.
type Resolved struct {
	Listen      Setting
	AdminListen Setting
	CACert      Setting
	CAKey       Setting
	Mode        Setting
	// TransparentHTTPS / TransparentHTTP are the transparent interception
	// listeners; Value "" = not serving that port.
	TransparentHTTPS Setting
	TransparentHTTP  Setting
}

// ResolveListen applies precedence and validates the result, regardless of where
// each value came from. Errors name the source of the offending value.
func ResolveListen(pol Policy, f ListenFlags) (Resolved, error) {
	pick := func(flagVal, flagName, cfgVal, cfgName, def string) Setting {
		switch {
		case flagVal != "":
			return Setting{flagVal, "flag --" + flagName}
		case cfgVal != "":
			return Setting{cfgVal, "config " + cfgName + ":"}
		default:
			return Setting{def, SourceDefault}
		}
	}
	mode := pol.Proxy.Mode
	modeSource := "config proxy.mode:"
	if mode == "" {
		mode, modeSource = DefaultProxyMode, SourceDefault
	}
	r := Resolved{
		Listen:      pick(f.Listen, "listen", pol.Listen, "listen", DefaultListen),
		AdminListen: pick(f.AdminListen, "admin-listen", pol.AdminListen, "adminListen", DefaultAdminListen),
		CACert:      pick(f.CACert, "ca-cert", pol.TLS.CACert, "tls.caCert", ""),
		CAKey:       pick(f.CAKey, "ca-key", pol.TLS.CAKey, "tls.caKey", ""),
		Mode:        Setting{string(mode), modeSource},
	}
	if err := validateAddr(r.Listen); err != nil {
		return Resolved{}, err
	}
	if err := validateAddr(r.AdminListen); err != nil {
		return Resolved{}, err
	}
	switch {
	case r.CACert.Value != "" && r.CAKey.Value == "":
		return Resolved{}, fmt.Errorf("config: CA cert and key must be set together: cert %q from %s, but key is unset", r.CACert.Value, r.CACert.Source)
	case r.CACert.Value == "" && r.CAKey.Value != "":
		return Resolved{}, fmt.Errorf("config: CA cert and key must be set together: key %q from %s, but cert is unset", r.CAKey.Value, r.CAKey.Source)
	}
	// Transparent listeners + their clash/CA rules (#376): config-only, so the
	// strict checks run here where the resolved (flag/default-aware) forward and
	// admin addresses are known.
	if err := resolveTransparent(&r, pol); err != nil {
		return Resolved{}, err
	}
	return r, nil
}

func validateAddr(s Setting) error {
	_, port, err := net.SplitHostPort(s.Value)
	if err != nil {
		return fmt.Errorf("config: invalid listen address %q from %s: %v", s.Value, s.Source, err)
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 0 || n > 65535 {
		return fmt.Errorf("config: invalid listen address %q from %s: port %q must be 0-65535", s.Value, s.Source, port)
	}
	return nil
}

// LogArgs returns slog key/value pairs describing each effective value and its
// source. CA paths are file paths, not secrets.
func (r Resolved) LogArgs() []any {
	args := []any{
		"listen", r.Listen.Value, "listenSource", r.Listen.Source,
		"adminListen", r.AdminListen.Value, "adminListenSource", r.AdminListen.Source,
		"mode", r.Mode.Value, "modeSource", r.Mode.Source,
	}
	if r.TransparentHTTPS.Value != "" {
		args = append(args, "transparentHTTPS", r.TransparentHTTPS.Value, "transparentHTTPSSource", r.TransparentHTTPS.Source)
	}
	if r.TransparentHTTP.Value != "" {
		args = append(args, "transparentHTTP", r.TransparentHTTP.Value, "transparentHTTPSource", r.TransparentHTTP.Source)
	}
	if r.CACert.Value != "" {
		args = append(args,
			"caCert", r.CACert.Value, "caCertSource", r.CACert.Source,
			"caKey", r.CAKey.Value, "caKeySource", r.CAKey.Source)
	}
	return args
}
