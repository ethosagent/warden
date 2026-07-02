package secrets

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeEntry is an in-memory secret held by fakeAWSClient: its value plus
// value-free metadata (version + last-change time).
type fakeEntry struct {
	value     string
	version   int
	updatedAt time.Time
}

// fakeAWSClient is a test double for the full AWSSecretsClient seam (read +
// write + list). It is an in-memory map keyed by backend secret NAME; it
// exercises the store's upsert branch by returning ErrSecretNotFound from
// PutSecretValue when the name is absent, and models version bumps + timestamps.
type fakeAWSClient struct {
	store map[string]*fakeEntry
	err   error // when set, GetSecretValue returns it (legacy read tests)
	now   func() time.Time
}

// GetSecretValue returns the stored value or ErrSecretNotFound. The legacy err
// field short-circuits (kept for the existing AWSFetcher error test).
func (c *fakeAWSClient) GetSecretValue(name string) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	e, ok := c.store[name]
	if !ok {
		return "", ErrSecretNotFound
	}
	return e.value, nil
}

// PutSecretValue updates an EXISTING secret in place (bumping its version). It
// returns ErrSecretNotFound when the name is absent, so the store routes a
// first-write through CreateSecret.
func (c *fakeAWSClient) PutSecretValue(name, value string) (string, error) {
	e, ok := c.store[name]
	if !ok {
		return "", ErrSecretNotFound
	}
	e.value = value
	e.version++
	e.updatedAt = c.clock()
	return strconv.Itoa(e.version), nil
}

// CreateSecret adds a NEW secret (version 1). It errors if the name already
// exists (mirrors AWS's ResourceExistsException).
func (c *fakeAWSClient) CreateSecret(name, value string) (string, error) {
	if _, ok := c.store[name]; ok {
		return "", errors.New("ResourceExistsException: secret already exists")
	}
	if c.store == nil {
		c.store = map[string]*fakeEntry{}
	}
	c.store[name] = &fakeEntry{value: value, version: 1, updatedAt: c.clock()}
	return "1", nil
}

// DeleteSecret removes name; deleting an absent name is idempotent (no error).
func (c *fakeAWSClient) DeleteSecret(name string) error {
	delete(c.store, name)
	return nil
}

// ListSecrets returns value-free metadata for names with the given prefix.
func (c *fakeAWSClient) ListSecrets(namePrefix string) ([]AWSSecretEntry, error) {
	var out []AWSSecretEntry
	for name, e := range c.store {
		if !strings.HasPrefix(name, namePrefix) {
			continue
		}
		out = append(out, AWSSecretEntry{
			Name:      name,
			Version:   strconv.Itoa(e.version),
			UpdatedAt: e.updatedAt,
		})
	}
	return out, nil
}

func (c *fakeAWSClient) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// newFakeAWSClient builds an empty in-memory fake.
func newFakeAWSClient() *fakeAWSClient {
	return &fakeAWSClient{store: map[string]*fakeEntry{}}
}

func TestAWSFetcher_Success(t *testing.T) {
	client := newFakeAWSClient()
	client.store["prod/openai-key"] = &fakeEntry{value: "sk-aws-secret", version: 1}
	f := NewAWSFetcher(client, map[string]string{
		"openai_key": "prod/openai-key",
	})

	got, err := f.Fetch("openai_key")
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if got != "sk-aws-secret" {
		t.Errorf("Fetch = %q, want %q", got, "sk-aws-secret")
	}
}

func TestAWSFetcher_UnknownPlaceholder(t *testing.T) {
	client := newFakeAWSClient()
	f := NewAWSFetcher(client, map[string]string{})

	_, err := f.Fetch("unknown")
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Errorf("err = %v, want ErrUnknownPlaceholder", err)
	}
}

func TestAWSFetcher_ClientError(t *testing.T) {
	client := &fakeAWSClient{err: errors.New("access denied")}
	f := NewAWSFetcher(client, map[string]string{
		"key": "prod/key",
	})

	_, err := f.Fetch("key")
	if err == nil {
		t.Fatal("expected error from client")
	}
	if errors.Is(err, ErrUnknownPlaceholder) {
		t.Error("should not be ErrUnknownPlaceholder")
	}
}
