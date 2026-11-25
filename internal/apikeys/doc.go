// Package apikeys implements Warden's scoped control-plane API keys: the
// "wak_" key format, the scope registry, the Store port and an in-memory index
// that authenticates a presented key without any DB I/O. The SQLite store on
// the cpstate database is in adapters/sqlitestore.
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
//   - scopes.go: the scope Registry (Register, Lookup, ParseScopes).
//   - store.go: Key, CreateParams, Snapshot, Change and the Store port.
//   - index.go: Index, the request-path authenticator that applies local
//     revocations at once and reloads when another process changes the file.
//   - adapters/sqlitestore: SQLiteStore and the api_keys/0001 migration.
//
// A key is stored only as the sha256 of its 32 secret bytes (a 256-bit random
// secret needs no slow hash). No String, GoString or LogValue in this package
// prints the plaintext, the secret or the stored hash, and Authenticate and
// Parse never return them. The plaintext leaves once, as the return value of
// Store.Create; the hash is reachable only through Generated.StorageHash, which
// Store implementations use to persist it and nothing else may.
//
// Layering (as internal/keys): this package is the domain, with the format,
// the scope Registry, the Store port and the Index, and does no I/O. The SQLite
// implementation lives in adapters/sqlitestore.
package apikeys
