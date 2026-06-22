package auth

import (
	"fmt"
	"net/http"
)

// APIKeyInjector injects an API key into a request header or basic-auth
// credentials. Query-param injection is intentionally unsupported because it
// leaks secrets into logs, URLs, browser history, and Referer headers.
type APIKeyInjector struct {
	location string // "header" or "basic_auth"
	name     string // header name (or username for basic_auth)
	value    string // the key value (or password for basic_auth)
}

// NewAPIKeyInjector creates an APIKeyInjector. location must be one of
// "header" or "basic_auth". The "query" location is rejected because it leaks
// secrets into URLs and logs.
func NewAPIKeyInjector(location, name, value string) (*APIKeyInjector, error) {
	if location != "header" && location != "basic_auth" {
		return nil, fmt.Errorf("auth: unsupported api key location %q; only \"header\" and \"basic_auth\" are safe", location)
	}
	return &APIKeyInjector{location: location, name: name, value: value}, nil
}

// Transform applies the API key to the request.
func (a *APIKeyInjector) Transform(req *http.Request) error {
	switch a.location {
	case "header":
		req.Header.Set(a.name, a.value)
	case "basic_auth":
		req.SetBasicAuth(a.name, a.value)
	default:
		return fmt.Errorf("auth: unknown api key location %q", a.location)
	}
	return nil
}
