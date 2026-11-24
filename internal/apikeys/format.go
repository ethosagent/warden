package apikeys

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Key format: "wak_" + 16 lowercase hex characters (the public id) + "_" + 52
// lowercase unpadded base32 characters (32 crypto/rand bytes), 73 characters in
// all. Base32 rather than base64url keeps "_" and "-" out of the secret, so
// splitting on the separator is unambiguous.
const (
	// Prefix starts every API key.
	Prefix = "wak_"

	idLen     = 16
	secretLen = 52
	secretRaw = 32 // random bytes behind the base32 secret
	sepOffset = len(Prefix) + idLen

	// Length is the exact length of every key.
	Length = len(Prefix) + idLen + 1 + secretLen

	// Pattern is a regular expression (RE2) matching exactly the shape of a
	// key, for scanners that look for keys inside larger text (egress
	// detection). It is an over-approximation of what Parse accepts: Parse also
	// requires the secret to be canonical base32. Data-plane scanners
	// (internal/scan) may not import this package (zone Z2), so they copy this
	// literal; a test on their side keeps the copy in step.
	Pattern = `wak_[0-9a-f]{16}_[a-z2-7]{52}`

	// maxIDAttempts bounds Generate's retries on an id collision. A 64-bit id
	// colliding even once is astronomically unlikely, so reaching the bound
	// means the callback is broken.
	maxIDAttempts = 8
)

// ErrMalformed is returned by Parse (and so by Index.Authenticate's Reason
// "malformed") for any value that is not shaped like a key. No hashing or
// lookup happened.
var ErrMalformed = errors.New("apikeys: malformed key")

// b32 is RFC 4648 base32 with a lowercase alphabet and no padding: the same
// bytes as StdEncoding lowercased, without a case conversion on the hot path.
var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// LooksLikeKey reports whether s starts with the "wak_" prefix. It is the
// routing test for code that must decide whether a bearer value is an API key
// (a worker authenticator rejecting one, a token endpoint refusing one): it is
// deliberately prefix-only, so a truncated or corrupted key is still treated as
// a key and fails closed instead of falling through to another credential
// check. Use Parse for the full shape check.
func LooksLikeKey(s string) bool { return strings.HasPrefix(s, Prefix) }

// Generated is a freshly minted key. Plaintext is the only copy of the
// credential; the caller shows it once and never stores or logs it.
type Generated struct {
	// ID is the public identifier (16 lowercase hex characters).
	ID string
	// Plaintext is the full 73-character key.
	Plaintext string

	hash [sha256.Size]byte
}

// StorageHash returns the sha256 of the key's secret bytes, the only form a
// Store may persist. It exists for Store implementations alone: never log it,
// return it from an API or put it in an audit row.
func (g Generated) StorageHash() [sha256.Size]byte { return g.hash }

// String and GoString never print the plaintext.
func (g Generated) String() string   { return "apikeys.Generated{id=" + g.ID + "}" }
func (g Generated) GoString() string { return g.String() }

// Generate mints a key from random bytes read from r (crypto/rand.Reader in
// production; a domain package does no I/O of its own, so the adapter or
// assembly injects it). It skips any id taken reports as already used (a nil
// taken accepts every id), retrying with a fresh id, and fails after a few
// attempts rather than loop forever.
func Generate(r io.Reader, taken func(id string) bool) (Generated, error) {
	for range maxIDAttempts {
		var idb [idLen / 2]byte
		if _, err := io.ReadFull(r, idb[:]); err != nil {
			return Generated{}, fmt.Errorf("apikeys: random id: %w", err)
		}
		id := hex.EncodeToString(idb[:])
		if taken != nil && taken(id) {
			continue
		}
		var secret [secretRaw]byte
		if _, err := io.ReadFull(r, secret[:]); err != nil {
			return Generated{}, fmt.Errorf("apikeys: random secret: %w", err)
		}
		return Generated{
			ID:        id,
			Plaintext: Prefix + id + "_" + b32.EncodeToString(secret[:]),
			hash:      sha256.Sum256(secret[:]),
		}, nil
	}
	return Generated{}, errors.New("apikeys: could not find an unused key id")
}

// Parse validates the shape of a key and returns its public id. It checks the
// prefix, the exact length, the separator offset and the alphabet before doing
// any work on the secret, and returns ErrMalformed for every failure.
func Parse(token string) (id string, err error) {
	id, _, err = parse(token)
	return id, err
}

// parse is Parse plus the sha256 of the secret bytes, which only this package
// may see.
func parse(token string) (id string, hash [sha256.Size]byte, err error) {
	if len(token) != Length || token[:len(Prefix)] != Prefix || token[sepOffset] != '_' {
		return "", hash, ErrMalformed
	}
	id = token[len(Prefix):sepOffset]
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", hash, ErrMalformed
		}
	}
	enc := token[sepOffset+1:]
	for i := 0; i < len(enc); i++ {
		if c := enc[i]; (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return "", hash, ErrMalformed
		}
	}
	// 52 base32 characters carry 260 bits for 256 bits of data; the last
	// character's low 4 bits must be zero, or two different strings would decode
	// to the same secret.
	if last := enc[secretLen-1]; last != 'a' && last != 'q' {
		return "", hash, ErrMalformed
	}
	var raw [secretRaw + 1]byte
	n, derr := b32.Decode(raw[:], []byte(enc))
	if derr != nil || n != secretRaw {
		return "", hash, ErrMalformed
	}
	return id, sha256.Sum256(raw[:secretRaw]), nil
}
