package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
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
//
// When caCertPath is non-empty, that PEM CA is added to this client's trust
// pool (system roots PLUS the CA), so a privately-signed central aggregator is
// trusted without changing the process-wide trust store. Public-CA endpoints
// (e.g. OAuth token URLs) keep working because the system roots are retained.
func newSafeHTTPClient(timeout time.Duration, caCertPath string) (*http.Client, error) {
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
	if caCertPath != "" {
		pool, pErr := x509.SystemCertPool()
		if pErr != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, rErr := os.ReadFile(caCertPath)
		if rErr != nil {
			return nil, fmt.Errorf("safe http client: read ca cert %q: %w", caCertPath, rErr)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("safe http client: no certificates found in %q", caCertPath)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// newControlPlaneHTTPClient builds an *http.Client for the worker's own trusted,
// operator-configured control-plane connection (policy is pulled by a separate
// client; this is for central analytics forwarding). It deliberately does NOT use
// the SafeDialer: SSRF protection guards AGENT-driven egress, but the control
// plane is the worker's own infrastructure and is commonly on a PRIVATE network
// (e.g. a Docker/Kubernetes service), which the SafeDialer would block. caCertPath
// (optional) adds a private CA to this client's pool only.
func newControlPlaneHTTPClient(timeout time.Duration, caCertPath string) (*http.Client, error) {
	tr := &http.Transport{ForceAttemptHTTP2: true}
	if caCertPath != "" {
		pool, pErr := x509.SystemCertPool()
		if pErr != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, rErr := os.ReadFile(caCertPath)
		if rErr != nil {
			return nil, fmt.Errorf("control-plane client: read ca cert %q: %w", caCertPath, rErr)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("control-plane client: no certificates found in %q", caCertPath)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
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

// longPollControlPlane holds a long-poll against the control plane: the CP
// returns immediately when policy changes (hot-swapping the evaluator) or after
// `wait` with no change, and the worker re-polls at once. A failed poll is logged
// and the last-known-good policy is kept (capped backoff), so a worker rides out
// a control-plane outage. It returns when ctx is cancelled.
//
// onApply, when non-nil, runs after each applied policy change (same long-poll
// round-trip) so the worker can apply the distributed behavioral settings —
// notably rebuilding + atomically swapping the MCP gateway — in lock-step with
// the allow/deny reload. It is passed as a closure (built in run.go) so wiring
// stays free of the proxy/scanner/store internals the rebuild needs.
func longPollControlPlane(ctx context.Context, rp *config.RemoteProvider, ev *policy.Evaluator, wait time.Duration, logger *slog.Logger, onApply func()) {
	const maxBackoff = 15 * time.Second
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		changed, err := rp.PollLong(ctx, wait)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn("control plane long-poll failed; keeping last-known policy", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second
		if changed {
			if remote, gErr := rp.GetPolicy(); gErr == nil {
				ev.Replace(remote)
				logger.Info("control plane policy reloaded")
				// Apply behavioral settings (e.g. MCP gateway rebuild) in the same
				// round-trip, so a single long-poll lands both policy and settings.
				if onApply != nil {
					onApply()
				}
			}
		}
		// 304 (no change): re-poll immediately.
	}
}

// pushMCPSnapshots forwards this worker's MCP inventory + observed schema to the
// control plane over the analytics ingest channel. It pushes whenever the
// snapshot changes (hash-gated) and unconditionally every few ticks as a safety
// net (so a restarted control plane re-learns the snapshot). It returns when ctx
// is cancelled. The snapshot is value-free — only paths, types, and sensitivity.
func pushMCPSnapshots(ctx context.Context, gw *gateway.Gateway, remote *analytics.HTTPRemoteStore, interval time.Duration, logger *slog.Logger) {
	const forceEveryN = 5
	var lastHash string
	ticks := 0
	push := func(force bool) {
		snap := analytics.MCPSnapshot{Inventory: gw.Inventory(), Schema: gw.SchemaSnapshot()}
		h := hashMCPSnapshot(snap)
		if h == lastHash && !force {
			return
		}
		if err := remote.SendMCP(snap); err != nil {
			if ctx.Err() == nil {
				logger.Debug("mcp snapshot push failed; will retry", "error", err)
			}
			return
		}
		lastHash = h
	}
	push(true) // initial full push
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ticks++
			push(ticks%forceEveryN == 0)
		}
	}
}

func hashMCPSnapshot(snap analytics.MCPSnapshot) string {
	b, _ := json.Marshal(snap)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// heartbeatControlPlane pings the control plane every interval so it lists this
// worker as online even when idle (no traffic, long-poll held open).
func heartbeatControlPlane(ctx context.Context, rp *config.RemoteProvider, interval time.Duration, logger *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := rp.Heartbeat(ctx); err != nil && ctx.Err() == nil {
				logger.Debug("control plane heartbeat failed", "error", err)
			}
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
