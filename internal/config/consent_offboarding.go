package config

import (
	"fmt"
	"strings"
	"time"
)

// consent.offboarding (W-P3-OFFB-02): the control plane's IdP refresh job.
// Like the rest of the consent block it is CP-local (read from the
// operator-owned --config only, json:"-" through Policy.Consent) and never
// appears in GET /policy.
//
// The job refreshes each portal user's stored IdP refresh token as the
// warden-portal client and records the link's state. observe classifies and
// alerts but never offboards; enforce is accepted now and behaves as observe
// until W-P3-OFFB-05 adds enforcement. W-P3-OFFB-05 adds the remaining keys
// (confirmDelay, revokeGrace, propagationWait, blockRetention, breaker); a key
// not declared here fails the strict parse until then.

// Offboarding modes.
const (
	OffboardingModeOff     = "off"
	OffboardingModeObserve = "observe"
	OffboardingModeEnforce = "enforce"
)

// consent.offboarding defaults and bounds. The interval must stay well below
// the IdP's idle refresh lifetime (Dex validIfNotUsedFor, 168h in the
// reference recipe), so a chain that is refreshed never idles out.
const (
	DefaultOffboardingInterval       = time.Hour
	MinOffboardingInterval           = 5 * time.Minute
	MaxOffboardingInterval           = 24 * time.Hour
	DefaultOffboardingConcurrency    = 4
	MaxOffboardingConcurrency        = 32
	DefaultOffboardingRequestTimeout = 10 * time.Second
	MaxOffboardingRequestTimeout     = 2 * time.Minute
	DefaultOffboardingMaxFailures    = 3
	MaxOffboardingMaxFailures        = 100
	DefaultOffboardingReauthWarning  = 72 * time.Hour
)

// ConsentOffboarding is `consent.offboarding`.
type ConsentOffboarding struct {
	// Mode is off (default), observe or enforce.
	Mode string
	// Interval is how often each link is refreshed (5m-24h).
	Interval time.Duration
	// Concurrency bounds the refreshes in flight (1-32).
	Concurrency int
	// RequestTimeout bounds one token-endpoint call.
	RequestTimeout time.Duration
	// MaxFailures is how many consecutive transient failures of one user
	// raise idp_refresh_failing (when the issuer is otherwise healthy).
	MaxFailures int
	// ReauthWarning moves a link to expiring this long before its
	// relink_due_at (consent.idpLink.refreshLifetime after the login).
	ReauthWarning time.Duration
}

// Enabled reports whether the refresh job runs (mode observe or enforce).
func (o ConsentOffboarding) Enabled() bool { return o.Mode != "" && o.Mode != OffboardingModeOff }

type rawConsentOffboarding struct {
	Mode           string `yaml:"mode"`
	Interval       string `yaml:"interval"`
	Concurrency    *int   `yaml:"concurrency"`
	RequestTimeout string `yaml:"requestTimeout"`
	MaxFailures    *int   `yaml:"maxFailures"`
	ReauthWarning  string `yaml:"reauthWarning"`
}

func defaultConsentOffboarding() ConsentOffboarding {
	return ConsentOffboarding{
		Mode:           OffboardingModeOff,
		Interval:       DefaultOffboardingInterval,
		Concurrency:    DefaultOffboardingConcurrency,
		RequestTimeout: DefaultOffboardingRequestTimeout,
		MaxFailures:    DefaultOffboardingMaxFailures,
		ReauthWarning:  DefaultOffboardingReauthWarning,
	}
}

// parseConsentOffboarding converts the raw block and applies the defaults.
func parseConsentOffboarding(r *rawConsentOffboarding) (ConsentOffboarding, error) {
	o := defaultConsentOffboarding()
	if r == nil {
		return o, nil
	}
	if m := strings.TrimSpace(r.Mode); m != "" {
		o.Mode = m
	}
	for _, d := range []struct {
		key string
		raw string
		dst *time.Duration
	}{
		{"interval", r.Interval, &o.Interval},
		{"requestTimeout", r.RequestTimeout, &o.RequestTimeout},
		{"reauthWarning", r.ReauthWarning, &o.ReauthWarning},
	} {
		s := strings.TrimSpace(d.raw)
		if s == "" {
			continue
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return ConsentOffboarding{}, fmt.Errorf("config: consent.offboarding.%s %q is not a valid duration: %w", d.key, s, err)
		}
		*d.dst = v
	}
	if r.Concurrency != nil {
		o.Concurrency = *r.Concurrency
	}
	if r.MaxFailures != nil {
		o.MaxFailures = *r.MaxFailures
	}
	return o, nil
}

// validateConsentOffboarding checks the block of an enabled consent config.
// Every error names the key.
func validateConsentOffboarding(c ConsentConfig) error {
	o := c.Offboarding
	switch o.Mode {
	case OffboardingModeOff, OffboardingModeObserve, OffboardingModeEnforce:
	default:
		return fmt.Errorf("config: consent.offboarding.mode %q must be off, observe or enforce", o.Mode)
	}
	if o.Interval < MinOffboardingInterval || o.Interval > MaxOffboardingInterval {
		return fmt.Errorf("config: consent.offboarding.interval (%s) must be between %s and %s", o.Interval, MinOffboardingInterval, MaxOffboardingInterval)
	}
	if o.Concurrency < 1 || o.Concurrency > MaxOffboardingConcurrency {
		return fmt.Errorf("config: consent.offboarding.concurrency (%d) must be between 1 and %d", o.Concurrency, MaxOffboardingConcurrency)
	}
	if o.RequestTimeout < time.Second || o.RequestTimeout > MaxOffboardingRequestTimeout || o.RequestTimeout >= o.Interval/2 {
		return fmt.Errorf("config: consent.offboarding.requestTimeout (%s) must be between 1s and %s and below half the interval", o.RequestTimeout, MaxOffboardingRequestTimeout)
	}
	if o.MaxFailures < 1 || o.MaxFailures > MaxOffboardingMaxFailures {
		return fmt.Errorf("config: consent.offboarding.maxFailures (%d) must be between 1 and %d", o.MaxFailures, MaxOffboardingMaxFailures)
	}
	if o.ReauthWarning <= 0 {
		return fmt.Errorf("config: consent.offboarding.reauthWarning (%s) must be > 0", o.ReauthWarning)
	}
	// Checked only when the job runs, so a short refreshLifetime with the job
	// off stays valid.
	if o.Enabled() && o.ReauthWarning >= c.IdPLink.RefreshLifetime {
		return fmt.Errorf("config: consent.offboarding.reauthWarning (%s) must be > 0 and below consent.idpLink.refreshLifetime (%s)", o.ReauthWarning, c.IdPLink.RefreshLifetime)
	}
	if o.Enabled() && !c.IdPLink.Enabled {
		return fmt.Errorf("config: consent.offboarding.mode %s needs consent.idpLink.enabled (there is no refresh token to refresh)", o.Mode)
	}
	return nil
}
