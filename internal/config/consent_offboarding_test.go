package config

import (
	"strings"
	"testing"
	"time"
)

func TestConsentOffboardingDefaults(t *testing.T) {
	prov, err := parse(consoleYAML(validConsent))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	o := p.Consent.Offboarding
	want := ConsentOffboarding{Mode: OffboardingModeOff, Interval: time.Hour, Concurrency: 4,
		RequestTimeout: 10 * time.Second, MaxFailures: 3, ReauthWarning: 72 * time.Hour}
	if o != want {
		t.Fatalf("defaults = %+v, want %+v", o, want)
	}
	if o.Enabled() {
		t.Error("mode off must not be enabled")
	}
	// An absent consent block carries the same defaults (off).
	if prov, err = parse(consoleYAML("")); err != nil {
		t.Fatal(err)
	}
	if p, _ = prov.GetPolicy(); p.Consent.Offboarding.Enabled() {
		t.Error("an absent consent block must leave offboarding off")
	}
}

func TestConsentOffboardingConfig(t *testing.T) {
	base := cIssuer + cSecret + cRedir
	off := func(lines string) string { return consentBlock(base, "  offboarding:\n"+lines) }
	cases := []struct {
		name    string
		block   string
		wantErr string
	}{
		{"observe", off("    mode: observe\n"), ""},
		{"enforce accepted", off("    mode: enforce\n"), ""},
		{"explicit", off("    mode: observe\n    interval: 5m\n    concurrency: 32\n    requestTimeout: 1s\n    maxFailures: 1\n    reauthWarning: 1h\n"), ""},
		{"max interval", off("    interval: 24h\n"), ""},
		{"unknown mode", off("    mode: on\n"), "consent.offboarding.mode"},
		{"interval too short", off("    interval: 4m\n"), "consent.offboarding.interval"},
		{"interval too long", off("    interval: 25h\n"), "consent.offboarding.interval"},
		{"zero concurrency", off("    concurrency: 0\n"), "consent.offboarding.concurrency"},
		{"concurrency too high", off("    concurrency: 33\n"), "consent.offboarding.concurrency"},
		{"timeout too short", off("    requestTimeout: 500ms\n"), "consent.offboarding.requestTimeout"},
		{"timeout over half the interval", off("    interval: 5m\n    requestTimeout: 2m30s\n"), "consent.offboarding.requestTimeout"},
		{"zero maxFailures", off("    maxFailures: 0\n"), "consent.offboarding.maxFailures"},
		{"zero reauthWarning", off("    reauthWarning: 0s\n"), "consent.offboarding.reauthWarning"},
		{"reauthWarning over the lifetime", off("    mode: observe\n    reauthWarning: 720h\n"), "consent.offboarding.reauthWarning"},
		{"long reauthWarning with the job off", off("    reauthWarning: 720h\n"), ""},
		{"bad duration", off("    interval: hourly\n"), "not a valid duration"},
		{"unknown key", off("    confirmDelay: 60s\n"), "confirmDelay"},
		{"observe without idpLink", consentBlock(base, "  idpLink:\n    enabled: false\n  offboarding:\n    mode: observe\n"), "needs consent.idpLink.enabled"},
		{"off without idpLink", consentBlock(base, "  idpLink:\n    enabled: false\n  offboarding:\n    mode: off\n"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(consoleYAML(tc.block))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
	prov, err := parse(consoleYAML(off("    mode: observe\n    interval: 30m\n    concurrency: 8\n")))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	if o := p.Consent.Offboarding; o.Mode != OffboardingModeObserve || o.Interval != 30*time.Minute || o.Concurrency != 8 || !o.Enabled() {
		t.Fatalf("parsed = %+v", o)
	}
}
