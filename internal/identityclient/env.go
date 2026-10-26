package identityclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Output shells and formats of ProxyEnv.
const (
	ShellSh         = "sh"
	ShellFish       = "fish"
	ShellPowerShell = "powershell"

	FormatShell  = "" // a shell script, see EnvOptions.Shell
	FormatDotenv = "dotenv"
	FormatJSON   = "json"
)

// ProxyUser is the fixed user name of the proxy credentials; the worker reads
// the ID token from the password.
const ProxyUser = "session"

// EnvOptions selects what ProxyEnv renders. The zero value is a POSIX sh
// script with the proxy variables only.
type EnvOptions struct {
	// CA is a CA bundle path; when set it fills SSL_CERT_FILE, CURL_CA_BUNDLE,
	// REQUESTS_CA_BUNDLE and NODE_EXTRA_CA_CERTS.
	CA string
	// Shell is sh (default), fish or powershell. It is ignored for the dotenv
	// and json formats.
	Shell string
	// Format is FormatShell (default), FormatDotenv or FormatJSON.
	Format string
	// IncludeHTTP also sets HTTP_PROXY and http_proxy. The worker denies plain
	// http, so these are off by default.
	IncludeHTTP bool
}

// EnvVar is one variable of the rendered environment.
type EnvVar struct{ Name, Value string }

// ProxyVars returns the variables in a stable order: the proxy URL variables,
// NO_PROXY, then the CA bundle variables. worker is host:port of the worker's
// explicit-proxy listener. The proxy URL carries url.UserPassword("session",
// token), so the token is percent-encoded as needed.
func ProxyVars(worker, token string, opts EnvOptions) ([]EnvVar, error) {
	host, port, err := net.SplitHostPort(worker)
	if err != nil || host == "" {
		return nil, errors.New("identityclient: worker must be host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, errors.New("identityclient: worker port must be a number from 1 to 65535")
	}
	if strings.ContainsAny(host, "/@?#\\ ") {
		return nil, errors.New("identityclient: worker must be host:port without a scheme, user or path")
	}
	if token == "" {
		return nil, errors.New("identityclient: empty token")
	}
	if hasControl(token) || hasControl(opts.CA) {
		return nil, errors.New("identityclient: the token and the CA path must not contain control characters")
	}
	u := url.URL{Scheme: "http", User: url.UserPassword(ProxyUser, token), Host: net.JoinHostPort(host, port)}
	proxy := u.String()

	vars := []EnvVar{{"HTTPS_PROXY", proxy}, {"https_proxy", proxy}}
	if opts.IncludeHTTP {
		vars = append(vars, EnvVar{"HTTP_PROXY", proxy}, EnvVar{"http_proxy", proxy})
	}
	vars = append(vars, EnvVar{"NO_PROXY", "localhost,127.0.0.1"})
	if opts.CA != "" {
		for _, n := range []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"} {
			vars = append(vars, EnvVar{n, opts.CA})
		}
	}
	return vars, nil
}

// ProxyEnv renders the proxy environment for worker and token as text ending
// in a newline. The output holds the token: write it to stdout only.
func ProxyEnv(worker, token string, opts EnvOptions) (string, error) {
	vars, err := ProxyVars(worker, token, opts)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	switch opts.Format {
	case FormatJSON:
		m := make(map[string]string, len(vars))
		for _, v := range vars {
			m[v.Name] = v.Value
		}
		out, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return "", err
		}
		b.Write(out)
		b.WriteByte('\n')
	case FormatDotenv:
		for _, v := range vars {
			fmt.Fprintf(&b, "%s=%s\n", v.Name, dotenvQuote(v.Value))
		}
	case FormatShell:
		for _, v := range vars {
			switch opts.Shell {
			case ShellSh, "":
				fmt.Fprintf(&b, "export %s=%s\n", v.Name, shQuote(v.Value))
			case ShellFish:
				fmt.Fprintf(&b, "set -gx %s %s\n", v.Name, fishQuote(v.Value))
			case ShellPowerShell:
				fmt.Fprintf(&b, "$env:%s = %s\n", v.Name, psQuote(v.Value))
			default:
				return "", fmt.Errorf("identityclient: unknown shell %q (sh, fish or powershell)", opts.Shell)
			}
		}
	default:
		return "", fmt.Errorf("identityclient: unknown format %q (dotenv or json)", opts.Format)
	}
	return b.String(), nil
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

// shQuote single-quotes s for POSIX sh: nothing is expanded inside, and an
// embedded quote is written as '\” .
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// fishQuote single-quotes s for fish, where only \ and ' are special inside.
func fishQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// psQuote single-quotes s for PowerShell, where an embedded quote is doubled.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// dotenvQuote double-quotes s; \, " and $ are escaped so no loader expands them.
func dotenvQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`).Replace(s) + `"`
}

// TokenExpiry reads the exp claim of a JWT without verifying it, for the
// expiry note of `identity env` when the token did not come from the cache.
func TokenExpiry(jwt string) (time.Time, error) {
	cl, err := parseClaims(jwt)
	if err != nil {
		return time.Time{}, err
	}
	return cl.Expiry, nil
}
