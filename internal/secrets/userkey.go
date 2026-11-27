package secrets

// Per-user credential key layout (W-P3-CSIG-06).
//
// Every per-user credential in P3 lives in the CP-only user credential store
// (consent.store, built by controlplane.NewUserStore), never in the
// distributed secretStore whose credential workers hold. Logical keys in that
// store are built ONLY by the helpers in this file; no P3 code formats them
// from a raw subject:
//
//	idp/<userKey>                   IdP refresh token (W-P3-CSIG-03)
//	users/<userKey>/<provider>      provider grant, an oauthbroker.TokenRecord (W-P3-BRKR-04, W-P3-PUS-03)
//	revoking/<userKey>/<provider>   a grant parked for provider revoke (W-P3-PORT-02, W-P3-OFFB-01)
//	oauth-clients/<provider>        an OAuth client secret (W-P3-BRKR-01, W-P3-BRKR-06)
//
// userKey = UserKey(iss, sub): a fixed-length, path-safe pseudonym for the
// (issuer, subject) identity key, so a subject containing "/" or "..", or one
// longer than a backend name allows, can never change the shape of a key. With
// the default namePrefix the backend name of idp/<userKey> is
// warden-cp/idp/<userKey>.
//
// The four namespaces (and cp/) are reserved everywhere else (IsReservedKey):
// config validation rejects a placeholder under one, storeFetcher.Fetch and the
// worker Cache refuse one before any backend call, and /central/secrets and the
// dashboard secret store answer 403 reserved_key and leave them out of List.
//
// internal/secrets is repository class: only assembly (controlplane, cmd) and
// this package call these helpers; domain and adapter packages receive the
// user key or the built key as a value or through a port.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ethosagent/warden/internal/config"
)

// Key prefixes of the per-user namespaces, each ending in "/".
const (
	UserGrantPrefix    = config.ReservedUserGrantNamespace + "/"
	IdPLinkPrefix      = config.ReservedIdPLinkNamespace + "/"
	RevokingPrefix     = config.ReservedRevokingNamespace + "/"
	ClientSecretPrefix = config.ReservedClientSecretNamespace + "/"
)

// userKeyDomain separates this derivation from any other SHA-256 use and
// versions it: a future scheme would use a new label, never reuse this one.
const userKeyDomain = "warden-user-v1\x00"

// UserKeyLen is the length of a user key: 16 bytes in lowercase hex.
const UserKeyLen = 32

// ErrInvalidUserKey is returned for an identity UserKey cannot derive a key
// from, or a user key that is not 32 lowercase hex characters.
var ErrInvalidUserKey = errors.New("secrets: invalid user key")

// ErrInvalidProviderID is returned for a provider id that fails ValidProviderID.
var ErrInvalidProviderID = errors.New("secrets: invalid provider id")

var (
	userKeyRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	providerIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// UserKey derives the per-user key of the identity (iss, sub): the lowercase
// hex of the first 16 bytes of SHA-256("warden-user-v1\x00" + iss + "\x00" +
// sub), 32 characters. The NUL separators make the split between iss and sub
// unambiguous, which is why either one containing NUL is refused, as is an
// empty one. Both are used verbatim (no trimming or case folding): the identity
// key is exactly the verified token's iss and sub.
func UserKey(iss, sub string) (string, error) {
	if iss == "" || sub == "" {
		return "", fmt.Errorf("%w: issuer and subject must be non-empty", ErrInvalidUserKey)
	}
	if strings.ContainsRune(iss, 0) || strings.ContainsRune(sub, 0) {
		return "", fmt.Errorf("%w: issuer and subject must not contain NUL", ErrInvalidUserKey)
	}
	h := sha256.New()
	h.Write([]byte(userKeyDomain))
	h.Write([]byte(iss))
	h.Write([]byte{0})
	h.Write([]byte(sub))
	return hex.EncodeToString(h.Sum(nil)[:UserKeyLen/2]), nil
}

// ValidUserKey reports whether userKey has the shape UserKey returns.
func ValidUserKey(userKey string) bool { return userKeyRE.MatchString(userKey) }

// ValidProviderID reports whether id is a valid provider id:
// ^[a-z][a-z0-9-]{0,31}$. consent.providers[].id and perUserSecrets mappings
// validate against it, so every id that reaches a key builder is path-safe.
func ValidProviderID(id string) bool { return providerIDRE.MatchString(id) }

func checkUserKey(userKey string) error {
	if !ValidUserKey(userKey) {
		return fmt.Errorf("%w: want %d lowercase hex characters", ErrInvalidUserKey, UserKeyLen)
	}
	return nil
}

func checkProvider(provider string) error {
	if !ValidProviderID(provider) {
		// The id is operator config, not a secret, but it may be arbitrary
		// input on a bad path; keep it quoted so it cannot forge a log line.
		return fmt.Errorf("%w: %q must match ^[a-z][a-z0-9-]{0,31}$", ErrInvalidProviderID, provider)
	}
	return nil
}

// UserGrantKey returns users/<userKey>/<provider>, the key of a user's grant
// for provider.
func UserGrantKey(userKey, provider string) (string, error) {
	if err := checkUserKey(userKey); err != nil {
		return "", err
	}
	if err := checkProvider(provider); err != nil {
		return "", err
	}
	return UserGrantPrefix + userKey + "/" + provider, nil
}

// UserPrefix returns users/<userKey>/, the prefix of every grant of a user
// (offboarding and the portal list a user's grants under it).
func UserPrefix(userKey string) (string, error) {
	if err := checkUserKey(userKey); err != nil {
		return "", err
	}
	return UserGrantPrefix + userKey + "/", nil
}

// IdPLinkKey returns idp/<userKey>, the key of a user's IdP refresh token.
func IdPLinkKey(userKey string) (string, error) {
	if err := checkUserKey(userKey); err != nil {
		return "", err
	}
	return IdPLinkPrefix + userKey, nil
}

// RevokingKey returns revoking/<userKey>/<provider>, the key of a grant parked
// until its provider revoke succeeds.
func RevokingKey(userKey, provider string) (string, error) {
	if err := checkUserKey(userKey); err != nil {
		return "", err
	}
	if err := checkProvider(provider); err != nil {
		return "", err
	}
	return RevokingPrefix + userKey + "/" + provider, nil
}

// ClientSecretKey returns oauth-clients/<provider>, the key of provider's OAuth
// client secret.
func ClientSecretKey(provider string) (string, error) {
	if err := checkProvider(provider); err != nil {
		return "", err
	}
	return ClientSecretPrefix + provider, nil
}
