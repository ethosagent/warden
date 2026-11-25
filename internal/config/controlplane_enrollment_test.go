package config

import (
	"strings"
	"testing"
)

func TestControlPlaneEnrollmentConfig(t *testing.T) {
	head := cpHead
	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{"none", "", ""},
		{"enrollment", "  stateDir: /var/lib/warden\n  enrollment:\n    tokenEnv: WARDEN_ENROLL_TOKEN\n    workerIdSuffixEnv: POD_NAME\n", ""},
		{"clientCert", "  clientCert: /etc/w/cert.pem\n  clientKey: /etc/w/key.pem\n", ""},
		{"enrollment needs stateDir", "  enrollment:\n    tokenEnv: T\n", "stateDir is required"},
		{"enrollment needs tokenEnv", "  stateDir: /s\n  enrollment: {}\n", "enrollment.tokenEnv is required"},
		{"exclusive", "  stateDir: /s\n  enrollment:\n    tokenEnv: T\n  clientCert: /c\n  clientKey: /k\n", "mutually exclusive"},
		{"cert without key", "  clientCert: /c\n", "must be set together"},
		{"key without cert", "  clientKey: /k\n", "must be set together"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prov, err := parse([]byte(head + tc.extra))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p, _ := prov.GetPolicy()
			cp := p.ControlPlane
			switch tc.name {
			case "none":
				if cp.CertAuth() || cp.Enrollment.Enabled() || cp.StateDir != "" {
					t.Errorf("zero config reports cert auth: %+v", cp)
				}
			case "enrollment":
				if !cp.CertAuth() || cp.StateDir != "/var/lib/warden" || cp.Enrollment.TokenEnv != "WARDEN_ENROLL_TOKEN" || cp.Enrollment.WorkerIDSuffixEnv != "POD_NAME" {
					t.Errorf("enrollment config = %+v", cp)
				}
			case "clientCert":
				if !cp.CertAuth() || cp.ClientCert != "/etc/w/cert.pem" || cp.ClientKey != "/etc/w/key.pem" {
					t.Errorf("clientCert config = %+v", cp)
				}
			}
		})
	}
}
