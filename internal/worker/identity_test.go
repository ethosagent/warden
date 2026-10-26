package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/test/fakes"
)

// stubVerifier is a distinct verifier instance, so a test can tell "kept" from
// "rebuilt" by identity.
type stubVerifier struct{ n int }

func (stubVerifier) Verify(context.Context, string, ...identity.VerifyOption) (identity.Claims, identity.Status, identity.Reason) {
	return identity.Claims{}, identity.StatusUnverified, ""
}

// identityApplier is newTestApplier with an identity wiring whose builder counts
// builds and can be told to fail. Warnings land in the returned buffer.
func identityApplier(t *testing.T) (*SettingsApplier, *fakeControlPlaneClient, *int, *error, *bytes.Buffer) {
	t.Helper()
	a, fake, _ := newTestApplier(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	builds := 0
	var buildErr error
	w := newIdentityWiring(a.p, "default", logger)
	w.build = func(oidc.Config) (identity.Verifier, error) {
		if buildErr != nil {
			return nil, buildErr
		}
		builds++
		return stubVerifier{n: builds}, nil
	}
	a.identity = w
	return a, fake, &builds, &buildErr, &buf
}

func identityWire(issuer string) *config.SettingsWire {
	return &config.SettingsWire{
		Identity: &config.IdentitySettings{
			DefaultMode: "off", Issuer: issuer, Audience: "warden",
			InternalIssuerURL: issuer,
		},
		Agents: []config.AgentSettings{{ID: "default", Identity: "attribute"}},
	}
}

func TestSettingsApplierIdentity(t *testing.T) {
	a, fake, builds, _, _ := identityApplier(t)

	// The agent's own entry says attribute while DefaultMode is off: Apply turns
	// verification on without a restart.
	fake.settings = identityWire("http://idp.test")
	a.Apply()
	w := a.identity
	if w.live.mode != proxy.IdentityModeAttribute || w.live.v == nil || *builds != 1 {
		t.Fatalf("live = mode %q verifier %v builds %d, want attribute with one build", w.live.mode, w.live.v, *builds)
	}
	first := w.live.v

	// An unrelated setting changes nothing about the verifier.
	fake.settings.CacheTTLSeconds = intPtr(120)
	a.Apply()
	if w.live.v != first || *builds != 1 {
		t.Errorf("unrelated change rebuilt the verifier (builds %d)", *builds)
	}

	// A mode-only change swaps the mode and keeps the instance, including on the
	// way back from off.
	fake.settings.Agents[0].Identity = "off"
	a.Apply()
	if w.live.mode != proxy.IdentityModeOff || w.live.v != first {
		t.Errorf("off: mode %q, verifier kept %v", w.live.mode, w.live.v == first)
	}
	fake.settings.Agents[0].Identity = "attribute"
	a.Apply()
	if w.live.mode != proxy.IdentityModeAttribute || w.live.v != first || *builds != 1 {
		t.Errorf("back to attribute: mode %q, verifier kept %v, builds %d", w.live.mode, w.live.v == first, *builds)
	}

	// Each verifier input replaces it.
	for name, mut := range map[string]func(*config.IdentitySettings){
		"issuer": func(s *config.IdentitySettings) {
			s.Issuer = "http://other.test"
			s.InternalIssuerURL = "http://other.test"
		},
		"internalIssuerURL": func(s *config.IdentitySettings) { s.InternalIssuerURL = "http://dex:5556" },
		"audience":          func(s *config.IdentitySettings) { s.Audience = "other" },
		"jwksURL":           func(s *config.IdentitySettings) { s.JWKSURL = "http://dex:5556/keys" },
		"allowedAZP":        func(s *config.IdentitySettings) { s.AllowedAZP = []string{"agent-harness"} },
		"skew":              func(s *config.IdentitySettings) { s.ClockSkewSeconds = 30 },
		"ttl":               func(s *config.IdentitySettings) { s.MaxTokenTTLSeconds = 600 },
	} {
		before, n := w.live.v, *builds
		mut(fake.settings.Identity)
		a.Apply()
		if w.live.v == before || *builds != n+1 {
			t.Errorf("%s change did not replace the verifier", name)
		}
	}
}

func TestSettingsApplierIdentityUnknownMode(t *testing.T) {
	a, fake, builds, _, buf := identityApplier(t)
	fake.settings = identityWire("http://idp.test")
	a.Apply()
	prev := a.identity.live
	buf.Reset()

	// A newer control plane serves a mode this build does not know, per agent
	// and as the default.
	for name, mut := range map[string]func(*config.SettingsWire){
		"agent":   func(s *config.SettingsWire) { s.Agents[0].Identity = "require" },
		"default": func(s *config.SettingsWire) { s.Agents[0].Identity = ""; s.Identity.DefaultMode = "require" },
	} {
		w := identityWire("http://idp.test")
		mut(w)
		fake.settings = w
		buf.Reset()
		a.Apply()
		if a.identity.live != prev || *builds != 1 {
			t.Errorf("%s: unknown mode changed the live config", name)
		}
		if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
			t.Errorf("%s: %d warnings, want 1:\n%s", name, n, buf.String())
		}
	}
}

func TestSettingsApplierIdentityRebuildFailureKeepsPrevious(t *testing.T) {
	a, fake, _, buildErr, buf := identityApplier(t)
	fake.settings = identityWire("http://idp.test")
	a.Apply()
	prev := a.identity.live

	*buildErr = errors.New("oidc verifier: audience is required")
	fake.settings.Identity.Audience = "changed"
	buf.Reset()
	a.Apply()
	if a.identity.live != prev {
		t.Error("failed rebuild replaced the live config")
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Errorf("%d warnings, want 1:\n%s", n, buf.String())
	}
}

func TestSettingsApplierIdentityMissingBlockTurnsOff(t *testing.T) {
	a, fake, _, _, _ := identityApplier(t)
	fake.settings = identityWire("http://idp.test")
	a.Apply()
	fake.settings = &config.SettingsWire{}
	a.Apply()
	if a.identity.live.mode != proxy.IdentityModeOff {
		t.Errorf("mode = %q, want off once the CP drops the block", a.identity.live.mode)
	}
}

func TestResolveIdentityMode(t *testing.T) {
	agents := []config.AgentPolicy{{ID: "a", Identity: "attribute"}, {ID: "b"}}
	tests := []struct {
		name, def, id, want string
	}{
		{"agent entry wins over default", "off", "a", "attribute"},
		{"entry without override falls to default", "attribute", "b", "attribute"},
		{"no entry uses default", "attribute", "agent:3128", "attribute"},
		{"nothing configured is off", "", "b", "off"},
	}
	for _, tt := range tests {
		got := resolveIdentityMode(config.IdentitySettings{DefaultMode: tt.def}, agents, tt.id)
		if got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

// startIdentityWorker boots Run on port-0 listeners from a Go-built policy and
// returns the proxy address plus a metrics reader.
func startIdentityWorker(t *testing.T, pol config.Policy) (string, *sdkmetric.ManualReader) {
	t.Helper()
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	pol.Observability = config.ObservabilityConfig{Enabled: true}
	ready := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, io.Discard, Params{
			Config:        &fakes.FakeConfigProvider{Policy: pol},
			DBPath:        t.TempDir() + "/warden.db",
			Version:       "test",
			ProxyListener: proxyLn,
			AdminListener: adminLn,
			OnReady:       func(proxyAddr, _ string) { ready <- proxyAddr },
			Overrides:     &Overrides{MetricsReader: reader},
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Run did not stop")
		}
	})
	select {
	case addr := <-ready:
		return addr, reader
	case err := <-errCh:
		t.Fatalf("worker did not start: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not become ready")
	}
	return "", nil
}

// connectWithToken sends CONNECT api.openai.com:443 with the token as the Basic
// password and returns the status line.
func connectWithToken(t *testing.T, addr, token string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	cred := base64.StdEncoding.EncodeToString([]byte(proxy.ProxyAuthUsername + ":" + token))
	_, _ = fmt.Fprintf(c, "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n", cred)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	return resp.Status
}

// verifyCount sums warden.identity.verify.total for one result label.
func verifyCount(t *testing.T, r *sdkmetric.ManualReader, result string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "warden.identity.verify.total" {
				continue
			}
			sum, _ := m.Data.(metricdata.Sum[int64])
			for _, dp := range sum.DataPoints {
				if v, ok := dp.Attributes.Value("result"); ok && v.AsString() == result {
					n += dp.Value
				}
			}
		}
	}
	return n
}

func identityPolicy(iss *fakes.OIDCIssuer, issuerURL string) config.Policy {
	pol := goPolicy()
	pol.Identity = config.IdentitySettings{
		DefaultMode: "off", Issuer: issuerURL, InternalIssuerURL: issuerURL,
		Audience: fakes.OIDCAudience, AllowedAZP: []string{fakes.OIDCAZP},
	}
	pol.Agents = []config.AgentPolicy{{ID: "default", Identity: "attribute"}}
	return pol
}

// TestWorkerLocalIdentity boots a worker from a local identity block (no
// control plane): the Agents entry turns attribute on although DefaultMode is
// off, and a token on CONNECT is verified against the issuer.
func TestWorkerLocalIdentity(t *testing.T) {
	iss := fakes.NewOIDCIssuer(t)
	addr, reader := startIdentityWorker(t, identityPolicy(iss, iss.Issuer()))

	connectWithToken(t, addr, iss.Mint(fakes.Valid("alice", "alice@example.com", "eng")))
	if got := verifyCount(t, reader, "valid"); got != 1 {
		t.Errorf("valid verifications = %d, want 1", got)
	}
}

// TestWorkerLocalIdentityOff proves the default: no identity block, no
// verification, and a token is never read.
func TestWorkerLocalIdentityOff(t *testing.T) {
	iss := fakes.NewOIDCIssuer(t)
	pol := goPolicy()
	addr, reader := startIdentityWorker(t, pol)
	connectWithToken(t, addr, iss.Mint(fakes.Valid("alice", "alice@example.com")))
	if got := verifyCount(t, reader, "valid"); got != 0 {
		t.Errorf("valid verifications = %d with identity off, want 0", got)
	}
}

// TestWorkerIdentityUnreachableIssuer proves boot never contacts the issuer: a
// worker pointed at a dead issuer starts, serves a CONNECT (allowed, attributed
// unverified) and never blocks on it.
func TestWorkerIdentityUnreachableIssuer(t *testing.T) {
	iss := fakes.NewOIDCIssuer(t)
	token := iss.Mint(fakes.Valid("alice", "alice@example.com"))
	dead := iss.Issuer()
	iss.Stop()

	addr, reader := startIdentityWorker(t, identityPolicy(iss, dead))
	status := connectWithToken(t, addr, token)
	if !strings.Contains(status, "200") {
		t.Errorf("CONNECT status = %q, want 200: attribution never blocks", status)
	}
	if got := verifyCount(t, reader, "unverified"); got != 1 {
		t.Errorf("unverified verifications = %d, want 1", got)
	}
}
