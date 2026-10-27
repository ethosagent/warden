package identityclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ethosagent/warden/internal/identity"
)

// Endpoints are the discovered OIDC endpoints the client uses.
type Endpoints struct {
	Token               string
	DeviceAuthorization string
}

type discoveryDoc struct {
	Issuer              string `json:"issuer"`
	TokenEndpoint       string `json:"token_endpoint"`
	DeviceAuthorization string `json:"device_authorization_endpoint"`
}

// Discover reads the plain JSON discovery document of issuer (no go-oidc). The
// document's issuer must equal the configured one byte for byte, and the issuer
// and the endpoints must be https or loopback http URLs. Errors never include
// the response body.
func Discover(ctx context.Context, hc *http.Client, issuer string) (Endpoints, error) {
	if err := identity.CheckClientIssuer(issuer); err != nil {
		return Endpoints{}, err
	}
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Endpoints{}, errors.New("identityclient: discovery: bad request")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return Endpoints{}, ErrIssuerUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			return Endpoints{}, ErrIssuerUnreachable
		}
		return Endpoints{}, errors.New("identityclient: discovery: issuer answered " + resp.Status)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&doc); err != nil {
		return Endpoints{}, errors.New("identityclient: discovery: not a valid JSON document")
	}
	if doc.Issuer != issuer {
		return Endpoints{}, errors.New("identityclient: discovery: document issuer does not match the configured issuer")
	}
	if err := checkEndpoint(doc.TokenEndpoint); err != nil {
		return Endpoints{}, errors.New("identityclient: discovery: token_endpoint: " + err.Error())
	}
	if doc.DeviceAuthorization != "" {
		if err := checkEndpoint(doc.DeviceAuthorization); err != nil {
			return Endpoints{}, errors.New("identityclient: discovery: device_authorization_endpoint: " + err.Error())
		}
	}
	return Endpoints{Token: doc.TokenEndpoint, DeviceAuthorization: doc.DeviceAuthorization}, nil
}

// checkEndpoint applies the https-or-loopback-http rule to an endpoint URL.
func checkEndpoint(raw string) error {
	if raw == "" {
		return errors.New("missing")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return errors.New("not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if identity.IsLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return errors.New("must be https (plain http only for a loopback host)")
}
