package secrets

import (
	"errors"
	"testing"
)

// fakeAWSClient is a test double for AWSSecretsClient.
type fakeAWSClient struct {
	secrets map[string]string
	err     error
}

func (c *fakeAWSClient) GetSecretValue(name string) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	v, ok := c.secrets[name]
	if !ok {
		return "", errors.New("secret not found")
	}
	return v, nil
}

func TestAWSFetcher_Success(t *testing.T) {
	client := &fakeAWSClient{secrets: map[string]string{
		"prod/openai-key": "sk-aws-secret",
	}}
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
	client := &fakeAWSClient{secrets: map[string]string{}}
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
