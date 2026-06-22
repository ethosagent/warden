package secrets

import (
	"errors"
	"testing"
)

// fakeGCPClient is a test double for GCPSecretClient.
type fakeGCPClient struct {
	secrets map[string]string
	err     error
}

func (c *fakeGCPClient) AccessSecret(name string) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	v, ok := c.secrets[name]
	if !ok {
		return "", errors.New("secret not found")
	}
	return v, nil
}

func TestGCPFetcher_Success(t *testing.T) {
	client := &fakeGCPClient{secrets: map[string]string{
		"projects/my-proj/secrets/openai-key/versions/latest": "sk-gcp-secret",
	}}
	f := NewGCPFetcher(client, map[string]string{
		"openai_key": "projects/my-proj/secrets/openai-key/versions/latest",
	})

	got, err := f.Fetch("openai_key")
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if got != "sk-gcp-secret" {
		t.Errorf("Fetch = %q, want %q", got, "sk-gcp-secret")
	}
}

func TestGCPFetcher_UnknownPlaceholder(t *testing.T) {
	client := &fakeGCPClient{secrets: map[string]string{}}
	f := NewGCPFetcher(client, map[string]string{})

	_, err := f.Fetch("unknown")
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Errorf("err = %v, want ErrUnknownPlaceholder", err)
	}
}

func TestGCPFetcher_ClientError(t *testing.T) {
	client := &fakeGCPClient{err: errors.New("permission denied")}
	f := NewGCPFetcher(client, map[string]string{
		"key": "projects/p/secrets/s/versions/latest",
	})

	_, err := f.Fetch("key")
	if err == nil {
		t.Fatal("expected error from client")
	}
	if errors.Is(err, ErrUnknownPlaceholder) {
		t.Error("should not be ErrUnknownPlaceholder")
	}
}
