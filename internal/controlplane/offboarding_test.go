package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/offboard"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

func offboardingMode(mode string) config.ConsentOffboarding {
	return config.ConsentOffboarding{
		Mode: mode, Interval: time.Hour, Concurrency: 4, RequestTimeout: 10 * time.Second,
		MaxFailures: 3, ReauthWarning: 72 * time.Hour,
	}
}

func servedPolicy(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/policy = %d", rec.Code)
	}
	return rec.Body.String()
}

// TestOffboardingJob_ModeOff: mode off (and an absent consent block) builds no
// job, so Start starts no refresh goroutine; observe and enforce build one;
// /policy is byte-identical in every case; and the job has no Offboarder seam
// (pinned in package offboard by TestRefreshJob_NoOffboarderSeam).
func TestOffboardingJob_ModeOff(t *testing.T) {
	none := newPortalRig(t, portalRigOpts{noConsent: true})
	base := servedPolicy(t, none.h)
	if none.srv.OffboardingJob() != nil || none.srv.OffboardingMetrics() != nil {
		t.Fatal("a job without the consent block")
	}
	for _, tc := range []struct {
		name    string
		opts    portalRigOpts
		wantJob bool
	}{
		{"zero block", portalRigOpts{}, false},
		{"mode off", portalRigOpts{offboarding: offboardingMode(config.OffboardingModeOff)}, false},
		{"observe without the IdP link", portalRigOpts{noIdPLink: true, offboarding: offboardingMode(config.OffboardingModeObserve)}, false},
		{"observe", portalRigOpts{offboarding: offboardingMode(config.OffboardingModeObserve)}, true},
		{"enforce", portalRigOpts{offboarding: offboardingMode(config.OffboardingModeEnforce)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPortalRig(t, tc.opts)
			if got := r.srv.OffboardingJob() != nil; got != tc.wantJob {
				t.Fatalf("job built = %v, want %v", got, tc.wantJob)
			}
			if got := servedPolicy(t, r.h); got != base {
				t.Fatalf("/policy differs:\n%s\nwant\n%s", got, base)
			}
		})
	}
}

// TestOffboardingJob_Wired: the job the control plane builds refreshes a
// portal login's token against the issuer as warden-portal, through the
// portal's discovered token endpoint and verifier, and writes it back.
func TestOffboardingJob_Wired(t *testing.T) {
	mem := fakes.NewMemorySecretStore()
	r := newPortalRig(t, portalRigOpts{userStore: mem, offboarding: offboardingMode(config.OffboardingModeObserve)})
	r.idp.SetLogin(fakes.Valid("dana", "dana@example.com"))
	r.ready()
	r.login("")
	job := r.srv.OffboardingJob()
	st, err := job.RunOnce(context.Background())
	if err != nil || st.OK != 1 {
		t.Fatalf("RunOnce = %+v, %v", st, err)
	}
	uk, err := secrets.UserKey(r.idp.Issuer(), "dana")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := mem.Value("idp/" + uk)
	if got == portalRefreshToken || !r.idp.LiveRefreshToken(got) {
		t.Fatal("consent.store does not hold the rotated, live token")
	}
	l, err := r.srv.IdPLinks().Get(context.Background(), r.idp.Issuer(), "dana")
	if err != nil || l.Generation != 2 || l.State != portal.LinkActive || l.RefreshRef != secrets.Ref(got).String() {
		t.Fatalf("link = %+v, %v", l, err)
	}
	if r.srv.OffboardingMetrics().Refresh(string(offboard.ClassOK)) != 1 {
		t.Fatal("refresh_total{outcome=ok} not counted")
	}
}
