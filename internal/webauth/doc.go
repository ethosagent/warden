// Package webauth is the browser sign-in machinery the control plane's web
// front doors share: the admin console today, the consent portal next. It holds
// the OIDC authorization-code flow with S256 PKCE, state and nonce (Flow), the
// lazily discovered provider (Provider), the pending-login store over the
// oidc_pending table (PendingStore), server-side sessions parameterized by
// table (SessionStore), the session cookie spec (Cookie) and the per-session
// CSRF token (CSRFToken, CSRF).
//
// Every consumer brings its own names: a login Purpose (so one front door's
// state never completes on the other), a session table, a cookie name and a
// CSRF label. Nothing here knows about roles, principals or routes; those stay
// with the consumer.
//
// The package never imports the OIDC adapter. The consumer builds the shared
// OIDC HTTP client and the ID-token verifier (identity.Verifier) and injects
// them through ProviderConfig and Flow, so this package depends only on the
// identity domain and the cpstate database.
//
// No code, verifier, nonce, state, token, cookie or CSRF value is ever logged.
package webauth
