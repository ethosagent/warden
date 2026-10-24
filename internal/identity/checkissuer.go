package identity

import (
	"errors"
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
