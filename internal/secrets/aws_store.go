package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// awsSecretStore implements the write-capable SecretStore over an
// AWSSecretsClient (real HTTP+SigV4 client in aws_httpclient.go, or the test
// fake). It is a pure pass-through to AWS Secrets Manager: no value ever
// persists inside Warden, and every op logs by-reference only (never the raw
// value). The control plane uses Put/Delete/List; a worker uses Get behind the
// Cache via NewStoreFetcher.
//
// KEY → SECRET-NAME CONVENTION. A logical key K maps to the AWS secret name
// namePrefix + encodeKey(K) (default prefix "warden/"), so IAM can scope to
// "warden/*" (see D6). AWS secret names allow only [A-Za-z0-9] and /_+=.@- — a
// key such as "{{OPENAI_API_KEY}}" contains disallowed characters, so encodeKey
// applies a REVERSIBLE encoding (see encodeKey/decodeKey) that List undoes to
// recover the original key. The round-trip is exact: decodeKey(encodeKey(K))==K.
type awsSecretStore struct {
	client     AWSSecretsClient
	region     string
	namePrefix string
}

// Compile-time assertion: awsSecretStore satisfies the write-capable SecretStore.
var _ SecretStore = (*awsSecretStore)(nil)

// NewAWSSecretStore builds a SecretStore backed by client. namePrefix defaults
// to "warden/" when empty. region is retained for logging/diagnostics; the
// client is already region-bound. It returns the SecretStore interface (the
// concrete type is unexported by design — callers depend only on the seam).
func NewAWSSecretStore(client AWSSecretsClient, region, namePrefix string) SecretStore {
	if namePrefix == "" {
		namePrefix = defaultAWSNamePrefix
	}
	return &awsSecretStore{client: client, region: region, namePrefix: namePrefix}
}

// defaultAWSNamePrefix mirrors config.defaultAWSNamePrefix. It is duplicated here
// (rather than imported) so the secrets package stays free of a config
// dependency; the value is the single documented convention "warden/".
const defaultAWSNamePrefix = "warden/"

// name returns the backend secret name for a logical key.
func (s *awsSecretStore) name(key string) string {
	return s.namePrefix + encodeKey(key)
}

// keyFromName recovers the logical key from a backend secret name, stripping the
// prefix and reversing encodeKey. A name without the expected prefix is returned
// decoded as-is (defensive: List should only ever see prefixed names).
func (s *awsSecretStore) keyFromName(name string) string {
	return decodeKey(strings.TrimPrefix(name, s.namePrefix))
}

// Get resolves key to its raw value via GetSecretValue. It logs nothing here
// (the value is in hand); callers reference it by Ref, never raw.
func (s *awsSecretStore) Get(_ context.Context, key string) (string, error) {
	if key == "" {
		return "", ErrEmptyKey
	}
	val, err := s.client.GetSecretValue(s.name(key))
	if err != nil {
		return "", fmt.Errorf("secrets: aws get %q: %w", key, err)
	}
	return val, nil
}

// Put upserts key→value: it tries PutSecretValue (new version of an existing
// secret) and, on ErrSecretNotFound, falls back to CreateSecret. Idempotent from
// the operator's view. The caller (the CP handler) logs key + version + Ref;
// this method never logs the raw value.
func (s *awsSecretStore) Put(_ context.Context, key, value string) error {
	if key == "" {
		return ErrEmptyKey
	}
	if value == "" {
		return ErrEmptyValue
	}
	name := s.name(key)
	_, err := s.client.PutSecretValue(name, value)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrSecretNotFound) {
		return fmt.Errorf("secrets: aws put %q: %w", key, err)
	}
	// Not-found → the secret does not exist yet: create it.
	if _, cerr := s.client.CreateSecret(name, value); cerr != nil {
		return fmt.Errorf("secrets: aws create %q: %w", key, cerr)
	}
	return nil
}

// Delete removes key. It is idempotent: a not-found from the backend is treated
// as success (nothing to delete). Logs the key only (no value in hand).
func (s *awsSecretStore) Delete(_ context.Context, key string) error {
	if key == "" {
		return ErrEmptyKey
	}
	if err := s.client.DeleteSecret(s.name(key)); err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return nil
		}
		return fmt.Errorf("secrets: aws delete %q: %w", key, err)
	}
	return nil
}

// List returns value-free metadata for every secret under namePrefix, mapping
// each backend name back to its logical key. It NEVER calls GetSecretValue.
func (s *awsSecretStore) List(_ context.Context) ([]SecretMeta, error) {
	entries, err := s.client.ListSecrets(s.namePrefix)
	if err != nil {
		return nil, fmt.Errorf("secrets: aws list: %w", err)
	}
	out := make([]SecretMeta, 0, len(entries))
	for _, e := range entries {
		out = append(out, SecretMeta{
			Key:       s.keyFromName(e.Name),
			Version:   e.Version,
			UpdatedAt: e.UpdatedAt,
		})
	}
	return out, nil
}

// encodeKey maps a logical key to an AWS-Secrets-Manager-safe name component
// using a REVERSIBLE encoding. AWS secret names permit only alphanumerics and
// the punctuation /_+.@- (the value-name charset) plus =, which this encoding
// RESERVES as its escape byte. Every byte that is not a passthrough character —
// including a literal '=' — is emitted as "=HH" (uppercase hex). decodeKey
// reverses it exactly, so List can recover the original key.
//
// Passthrough set: A-Z a-z 0-9 and / _ + . @ - (all AWS-legal, unambiguous).
// Everything else (e.g. the braces in "{{OPENAI_API_KEY}}", spaces, '=') is
// hex-escaped. Example: "{{K}}" → "=7B=7BK=7D=7D".
func encodeKey(key string) string {
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		if isNamePassthrough(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "=%02X", c)
	}
	return b.String()
}

// decodeKey reverses encodeKey. An unterminated or non-hex escape is left
// verbatim (defensive; encodeKey never produces one).
func decodeKey(encoded string) string {
	var b strings.Builder
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		if c == '=' && i+2 < len(encoded) {
			hi, ok1 := fromHex(encoded[i+1])
			lo, ok2 := fromHex(encoded[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// isNamePassthrough reports whether c is emitted verbatim by encodeKey: the AWS
// secret-name charset MINUS '=' (which is reserved as the escape byte).
func isNamePassthrough(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '/' || c == '_' || c == '+' || c == '.' || c == '@' || c == '-':
		return true
	default:
		return false
	}
}

// fromHex decodes a single uppercase/lowercase hex digit.
func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}
