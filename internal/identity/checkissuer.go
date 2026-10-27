package identity

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// CheckIssuer is the http-issuer rule, and the only place it lives. The issuer
// must be an absolute http or https URL with a host and no userinfo, query or
// fragment. A plain-http issuer is accepted only when internalIssuerURL is set
// (the operator opted into a split-horizon setup). internalIssuerURL, when set,
// must be an absolute http or https origin (empty path or "/") and needs a
// non-empty issuer. Any parse problem is an error. Errors never carry the raw
// URLs, because they can hold userinfo.
func CheckIssuer(issuer, internalIssuerURL string) error {
	if internalIssuerURL != "" && issuer == "" {
		return errors.New("identity: internalIssuerURL requires an issuer")
	}
	if issuer == "" {
		return errors.New("identity: issuer is required")
	}
	iu, err := parseAbs(issuer)
	if err != nil {
		return errors.New("identity: issuer: " + err.Error())
	}
	if internalIssuerURL != "" {
		xu, err := parseAbs(internalIssuerURL)
		if err != nil {
			return errors.New("identity: internalIssuerURL: " + err.Error())
		}
		if xu.Path != "" && xu.Path != "/" {
			return errors.New("identity: internalIssuerURL must be an origin without a path")
		}
	}
	if strings.EqualFold(iu.Scheme, "http") && internalIssuerURL == "" {
		return errors.New("identity: issuer must use https; a plain-http issuer is accepted only with internalIssuerURL set")
	}
	return nil
}

// parseAbs parses raw as an absolute http(s) URL with a host and no userinfo,
// query or fragment. The returned error never includes raw.
func parseAbs(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, errors.New("must be an absolute http or https URL")
	}
	switch {
	case u.Host == "" || u.Hostname() == "":
		return nil, errors.New("must have a host")
	case u.User != nil:
		return nil, errors.New("must not contain userinfo")
	case u.RawQuery != "" || u.ForceQuery:
		return nil, errors.New("must not contain a query")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, errors.New("must not contain a fragment")
	}
	return u, nil
}

// CheckClientIssuer is the issuer rule for a client that runs on the user's own
// host (the `warden identity` CLI). It takes the same shape rules as
// CheckIssuer (absolute URL with a host, no userinfo, query or fragment), and
// accepts https always and plain http only for a loopback host (see
// IsLoopbackHost). There is no override: such a client never needs the
// split-horizon internal issuer URL. Errors never carry the raw URL.
func CheckClientIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("identity: issuer is required")
	}
	u, err := parseAbs(issuer)
	if err != nil {
		return errors.New("identity: issuer: " + err.Error())
	}
	if strings.EqualFold(u.Scheme, "http") && !IsLoopbackHost(u.Hostname()) {
		return errors.New("identity: issuer must use https; plain http is accepted only for a loopback host (localhost, 127.0.0.0/8, ::1)")
	}
	return nil
}

// IsLoopbackHost reports whether host (a bare name or IP literal, no port) is
// "localhost", an address in 127.0.0.0/8 or ::1.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}
