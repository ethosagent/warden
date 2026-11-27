// Package oauthbroker is the control plane's OAuth broker domain: the
// metadata the CP keeps while a signed-in employee connects a third-party
// provider (Google, GitHub, ...) through an authorization code + PKCE flow.
//
// The CP database keeps only metadata. Tokens live in the CP-only consent
// store (secrets.UserGrantKey(userKey, provider)); no type, field or column in
// this package or its adapters can hold an access token, a refresh token or a
// client secret (TestGrantStoreConformance pins it). The one sensitive value
// stored is the PKCE code verifier of an in-flight browser attempt: it lives
// only in connect_attempts in the 0600 cpstate file for at most AttemptTTL,
// is deleted when the attempt is consumed, and never appears in a log line
// (Attempt's String, GoString and LogValue omit it).
//
// Three records, one GrantStore port:
//   - Pending: the long-lived intent "user U should connect provider P with
//     scopes S", shared with JIT (W-P3-JIT-01), which fills the request
//     columns the portal landing page shows. It ends granted, denied or
//     expired; Subscribe lets a waiter learn when.
//   - Attempt: one browser round trip to the provider, keyed by the SHA-256 of
//     the OAuth state and consumed once, like the SSO oidc_pending row, so a
//     retry or a second tab never overwrites another attempt.
//   - Grant: the per-(userKey, provider) row that says a token exists in the
//     consent store, in state connecting, active, reconsent_required or
//     revoked.
//
// Layout:
//   - store.go: the types, the GrantStore port, limits and errors.
//   - notify.go: Notifier, the in-memory Subscribe map stores embed.
//   - sweeper.go: RunSweeper, the 1-minute loop over GrantStore.Sweep.
//   - adapters/sqlite: the cpstate migrations oauthbroker/0001..0003 and the
//     SQLite GrantStore.
//   - oauthbrokertest: the conformance suite every GrantStore must pass (a
//     Postgres store for p5-postgres-ha runs the same suite).
//
// This package is the domain: it does no I/O and reads no clock. Time, ids and
// the database come from the adapter.
package oauthbroker
