// Package apikeys implements Warden's scoped control-plane API keys: the
// "wak_" key format, the scope registry, a SQLite store on the cpstate
// database and an in-memory index that authenticates a presented key without
// any DB I/O.
//
// These are credentials a human owner hands to a script or CI job so it can
// call the control plane's admin API on the owner's behalf, limited to the
// scopes the key was given and to the owner's current console role. They are
// unrelated to internal/auth.APIKeyInjector, which swaps placeholder tokens for
// the real upstream credentials an agent's outbound requests need.
//
// Layout:
//   - format.go: Generate, Parse, LooksLikeKey and the Pattern egress
//     detection builds on.
//   - scopes.go: the scope registry (Register, Lookup, ParseScopes).
//   - store.go: the Store interface, SQLiteStore and the api_keys/0001
//     migration.
//   - index.go: Index, the request-path authenticator that is rebuilt after
//     in-process writes and reloaded when another process changes the file.
//
// A key is stored only as the sha256 of its 32 secret bytes (a 256-bit random
// secret needs no slow hash). No exported method or String/LogValue in this
// package returns or prints the plaintext, the secret or the stored hash; the
// one place the plaintext leaves is the return value of Store.Create, once.
package apikeys
