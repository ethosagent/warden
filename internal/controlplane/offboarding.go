package controlplane

import (
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/offboard"
	"github.com/ethosagent/warden/internal/offboard/adapters/oidcrefresh"
)

// The IdP refresh job (W-P3-OFFB-02). With the consent block, --state-dir, the
// IdP link and consent.offboarding.mode observe or enforce, New builds an
// offboard.Job over the portal's LinkStore and Start runs it next to the
// retention pruner. It refreshes against the IdP's token endpoint as the
// warden-portal client (consent.oidc), through the portal provider's lazily
// discovered endpoint and the shared server-side OIDC client, and verifies
// the returned ID token with the portal's verifier (aud warden-portal). It
// has no Offboarder: until W-P3-OFFB-05 enforce behaves as observe and
// nothing the job decides offboards anyone. With mode off nothing is built
// and no goroutine starts.

// initOffboarding builds s.offboarding, or leaves it nil.
func (s *Server) initOffboarding() {
	p := s.portal
	if p == nil || !p.cfg.IdPLink.Enabled || !p.cfg.Offboarding.Enabled() {
		return
	}
	oc := p.cfg.Offboarding
	if p.linkStore == nil || p.provider == nil || p.idVerifier == nil {
		s.cfg.Logger.Error("control plane: consent.offboarding is on but the portal's IdP link or OIDC client is unavailable; the refresh job does not run")
		return
	}
	shared, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: p.cfg.OIDC.Issuer, InternalIssuerURL: p.cfg.OIDC.InternalIssuerURL})
	if err != nil {
		s.cfg.Logger.Error("control plane: offboarding refresh job unavailable", "error", err)
		return
	}
	// Same transport (no proxy, no redirects, body cap, internal rewrite);
	// only the overall timeout is consent.offboarding.requestTimeout.
	httpc := *shared
	httpc.Timeout = oc.RequestTimeout
	provider := p.provider
	client, err := oidcrefresh.New(oidcrefresh.Config{
		HTTP: &httpc, ClientID: p.cfg.OIDC.ClientID, ClientSecret: s.cfg.ConsentClientSecret,
		TokenURL: func() (string, bool) {
			c, ok := provider.Config()
			return c.Endpoint.TokenURL, ok && c.Endpoint.TokenURL != ""
		},
	})
	if err != nil {
		s.cfg.Logger.Error("control plane: offboarding refresh job unavailable", "error", err)
		return
	}
	s.offboardMetrics = offboard.NewMetrics()
	job, err := offboard.NewJob(offboard.JobConfig{
		Links: p.linkStore, Client: client, Verifier: p.idVerifier,
		Now: s.cfg.Clock.Now, After: s.cfg.Clock.After,
		Leader: offboard.AlwaysLeader{}, Findings: offboardFindings{s: s}, Metrics: s.offboardMetrics,
		Logger: s.cfg.Logger, Mode: oc.Mode,
		Interval: oc.Interval, Concurrency: oc.Concurrency, RequestTimeout: oc.RequestTimeout,
		MaxFailures: oc.MaxFailures, ReauthWarning: oc.ReauthWarning,
	})
	if err != nil {
		s.cfg.Logger.Error("control plane: offboarding refresh job unavailable", "error", err)
		return
	}
	s.offboarding = job
}

// OffboardingJob returns the refresh job, or nil when it is not built.
func (s *Server) OffboardingJob() *offboard.Job { return s.offboarding }

// OffboardingMetrics returns the job's counters (nil without the job).
func (s *Server) OffboardingMetrics() *offboard.Metrics { return s.offboardMetrics }

// offboardFindings publishes the job's Findings through Server.publishFinding.
type offboardFindings struct{ s *Server }

func (f offboardFindings) PublishFinding(x offboard.Finding) {
	sev := integration.SevMedium
	switch x.Severity {
	case offboard.SeverityHigh:
		sev = integration.SevHigh
	case offboard.SeverityCritical:
		sev = integration.SevCritical
	}
	f.s.publishFinding(integration.Finding{
		RuleID: x.RuleID, Category: "security", Severity: sev,
		Subject: integration.Subject{User: x.Sub}, Summary: x.Summary,
		Evidence: integration.Evidence(x.Evidence), DedupKey: x.DedupKey, Ts: x.Ts,
	})
}
