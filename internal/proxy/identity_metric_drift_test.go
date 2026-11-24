package proxy

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/observability"
)

// TestIdentityReasonsPassMetricAllowlist keeps the observability reason
// allowlist in step with identity: every identity.Reason, status and token type
// must be recorded unchanged, never folded into "other".
func TestIdentityReasonsPassMetricAllowlist(t *testing.T) {
	rd := sdkmetric.NewManualReader()
	m, _, shutdown, err := observability.New(observability.Config{Enabled: true, ServiceName: "t", MetricsEnabled: true, Reader: rd})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	want := map[string]bool{}
	for _, r := range identity.Reasons() {
		m.RecordIdentityVerify(string(identity.StatusInvalid), string(r), string(identity.TokenIdP))
		want["invalid|"+string(r)+"|idp"] = true
	}
	for _, s := range []identity.Status{identity.StatusOff, identity.StatusNone, identity.StatusValid, identity.StatusInvalid,
		identity.StatusExpired, identity.StatusUnverified, identity.StatusConflict} {
		m.RecordIdentityVerify(string(s), "none", string(identity.TokenWarden))
		want[string(s)+"|none|warden"] = true
	}
	m.RecordIdentityVerify("valid", "none", string(identity.TokenNone))
	want["valid|none|none"] = true

	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, mt := range sm.Metrics {
			if mt.Name != "warden.identity.verify.total" {
				continue
			}
			for _, dp := range mt.Data.(metricdata.Sum[int64]).DataPoints {
				res, _ := dp.Attributes.Value("result")
				rea, _ := dp.Attributes.Value("reason")
				tt, _ := dp.Attributes.Value("token_type")
				got[res.AsString()+"|"+rea.AsString()+"|"+tt.AsString()] = true
			}
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("series %q missing: the observability allowlist drifted from internal/identity (got %v)", k, got)
		}
	}
}
