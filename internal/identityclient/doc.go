// Package identityclient is the client side of the Warden identity contract:
// it logs a user in against any standards OIDC issuer with the RFC 8628 device
// code grant, keeps the refresh token and the current ID token in a 0600 file
// cache under an exclusive lock, and hands out a valid ID token on demand.
//
// It is a library for the `warden identity` commands and the loopback
// forwarder; it holds no cobra code and never reads the worker --config. It
// never prompts from Token: an unusable login is reported as ErrLoginRequired
// and the caller decides what to do.
//
// ID token claims are parsed here without verifying the signature, only to
// schedule refreshes and to show the user who they are. The worker verifies
// every token it receives (internal/identity).
//
// Secrets hygiene: tokens, device codes and IdP error bodies are never put in
// an error string or a log line. The logger gets the issuer, client id, scopes,
// expiry and an 8-hex fingerprint (Fingerprint) of a token, nothing else.
package identityclient
