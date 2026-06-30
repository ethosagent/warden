package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/proxy"
)

// expandEnv resolves ${VAR} / $VAR references in a config credential field from
// the environment. Secrets therefore live in the environment, never in the
// config file. An unset variable expands to the empty string.
func expandEnv(s string) string {
	return os.Expand(s, os.Getenv)
}

// newSafeHTTPClient builds an *http.Client whose dials go through the proxy's
// SafeDialer, so outbound auth-token fetches and central forwarding obey the
// same SSRF protection as proxied traffic (no dialing link-local/private ranges).
func newSafeHTTPClient(timeout time.Duration) (*http.Client, error) {
	sd, err := proxy.NewSafeDialer(timeout, nil)
	if err != nil {
		return nil, fmt.Errorf("safe http client: %w", err)
	}
	tr := &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return sd.Dial(network, addr)
		},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// buildTransformers constructs the per-destination auth transformers from config.
// Credential fields are ${ENV}-expanded here so the agent never holds them and
// they never appear in the parsed config struct that backs the dashboard.
func buildTransformers(entries []config.AuthEntry, client *http.Client) ([]*auth.MatchedTransformer, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]*auth.MatchedTransformer, 0, len(entries))
	for i, e := range entries {
		var (
			t   auth.RequestTransformer
			err error
		)
		switch e.Type {
		case config.AuthOAuth2ClientCredentials:
			t = auth.NewOAuth2ClientCredentials(client, e.TokenURL,
				expandEnv(e.ClientID), expandEnv(e.ClientSecret), e.Scopes)
		case config.AuthAWSSigV4:
			t = auth.NewAWSSigV4(expandEnv(e.AccessKeyID), expandEnv(e.SecretAccessKey),
				expandEnv(e.SessionToken), e.Region, e.Service)
		case config.AuthHMAC:
			t, err = auth.NewHMACSigner([]byte(expandEnv(e.Secret)), e.Header, e.Algorithm)
		case config.AuthAPIKey:
			t, err = auth.NewAPIKeyInjector(e.Location, e.Name, expandEnv(e.Value))
		default:
			err = fmt.Errorf("unsupported type %q", e.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("auth[%d] (%s): %w", i, e.Match, err)
		}
		mt, err := auth.NewMatchedTransformer(e.Match, t)
		if err != nil {
			return nil, fmt.Errorf("auth[%d] (%s): %w", i, e.Match, err)
		}
		out = append(out, mt)
	}
	return out, nil
}

// pollControlPlane periodically re-pulls policy from the control plane and
// hot-swaps the live evaluator on success. A failed pull is logged and the
// last-known-good policy is kept, so a worker keeps running through a
// control-plane outage. It returns when ctx is cancelled.
func pollControlPlane(ctx context.Context, rp *config.RemoteProvider, ev *policy.Evaluator, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := rp.Pull(); err != nil {
				logger.Warn("control plane pull failed; keeping last-known policy", "error", err)
				continue
			}
			remote, err := rp.GetPolicy()
			if err != nil {
				continue
			}
			ev.Replace(remote)
			logger.Debug("control plane policy reloaded")
		}
	}
}

// loadOrCreateSigner returns an Ed25519 receipt signer. With no keyFile it
// generates an ephemeral key (the public key is logged at startup each run).
// With a keyFile it loads an existing PKCS#8 PEM key, or generates and persists
// one (0600) on first run so receipts verify across restarts under a stable key.
func loadOrCreateSigner(keyFile string) (*audit.Signer, error) {
	if keyFile == "" {
		return audit.NewSigner()
	}
	data, err := os.ReadFile(keyFile)
	switch {
	case err == nil:
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("audit: no PEM block in key file %q", keyFile)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("audit: parse key file %q: %w", keyFile, err)
		}
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("audit: key file %q is not an Ed25519 key", keyFile)
		}
		return audit.NewSignerFromKey(ed), nil
	case errors.Is(err, os.ErrNotExist):
		_, priv, gErr := ed25519.GenerateKey(nil)
		if gErr != nil {
			return nil, fmt.Errorf("audit: generate key: %w", gErr)
		}
		der, mErr := x509.MarshalPKCS8PrivateKey(priv)
		if mErr != nil {
			return nil, fmt.Errorf("audit: marshal key: %w", mErr)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if wErr := os.WriteFile(keyFile, pemBytes, 0o600); wErr != nil {
			return nil, fmt.Errorf("audit: persist key file %q: %w", keyFile, wErr)
		}
		return audit.NewSignerFromKey(priv), nil
	default:
		return nil, fmt.Errorf("audit: read key file %q: %w", keyFile, err)
	}
}
