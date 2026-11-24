package observability

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newWithReader builds an enabled emitter that also feeds a manual reader.
func newWithReader(t *testing.T) (*Metrics, *sdkmetric.ManualReader) {
	t.Helper()
	rd := sdkmetric.NewManualReader()
	m, _, shutdown, err := New(Config{Enabled: true, ServiceName: "warden-test", MetricsEnabled: true, Reader: rd})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })
	return m, rd
}

func collect(t *testing.T, rd *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := rd.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rm
}

// identitySeries returns every warden.identity.verify.total series as
// "result|reason|token_type" -> count.
func identitySeries(t *testing.T, rd *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, sm := range collect(t, rd).ScopeMetrics {
		for _, mt := range sm.Metrics {
			if mt.Name != "warden.identity.verify.total" {
				continue
			}
			sum, ok := mt.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("identity verify is %T, want Sum[int64]", mt.Data)
			}
			for _, dp := range sum.DataPoints {
				get := func(k string) string {
					v, _ := dp.Attributes.Value(attribute.Key(k))
					return v.AsString()
				}
				if dp.Attributes.Len() != 3 {
					t.Errorf("series has %d labels, want exactly result, reason, token_type", dp.Attributes.Len())
				}
				out[get("result")+"|"+get("reason")+"|"+get("token_type")] += dp.Value
			}
		}
	}
	return out
}

func TestRecordIdentityVerifyTokenType(t *testing.T) {
	m, rd := newWithReader(t)
	m.RecordIdentityVerify("valid", "none", "idp")
	for _, reason := range []string{"agent_mismatch", "cnf_mismatch", "agent_disabled", "agent_unregistered", "unbound_token", "missing_claim"} {
		m.RecordIdentityVerify("invalid", reason, "warden")
	}
	got := identitySeries(t, rd)
	want := map[string]int64{
		"valid|none|idp":                    1,
		"invalid|agent_mismatch|warden":     1,
		"invalid|cnf_mismatch|warden":       1,
		"invalid|agent_disabled|warden":     1,
		"invalid|agent_unregistered|warden": 1,
		"invalid|unbound_token|warden":      1,
		"invalid|missing_claim|warden":      1,
	}
	if len(got) != len(want) {
		t.Fatalf("series = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("series %q = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
}

func TestRecordIdentityVerifyBounded(t *testing.T) {
	var nilm *Metrics
	nilm.RecordIdentityVerify("valid", "none", "idp") // nil-safe
	nilm.RecordControlPlaneClockSkew(time.Second)

	m, rd := newWithReader(t)
	m.RecordIdentityVerify("valid", "none", "none")
	m.RecordIdentityVerify("sub=alice", "none", "idp")
	m.RecordIdentityVerify("invalid", "kid-123", "idp")
	m.RecordIdentityVerify("invalid", "bad_signature", "eyJhbGciOi")
	got := identitySeries(t, rd)
	want := map[string]int64{
		"valid|none|none":             1,
		"other|none|idp":              1,
		"invalid|other|idp":           1,
		"invalid|bad_signature|other": 1,
	}
	if len(got) != len(want) {
		t.Fatalf("series = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("series %q = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
}

func TestRecordControlPlaneClockSkew(t *testing.T) {
	m, rd := newWithReader(t)
	m.RecordControlPlaneClockSkew(120 * time.Second)
	m.RecordControlPlaneClockSkew(-3 * time.Second)
	found := false
	for _, sm := range collect(t, rd).ScopeMetrics {
		for _, mt := range sm.Metrics {
			if mt.Name != "warden.controlplane.clock_skew_seconds" {
				continue
			}
			g, ok := mt.Data.(metricdata.Gauge[float64])
			if !ok || len(g.DataPoints) != 1 {
				t.Fatalf("clock skew data = %#v, want one gauge point", mt.Data)
			}
			if g.DataPoints[0].Attributes.Len() != 0 {
				t.Errorf("clock skew gauge carries labels")
			}
			if v := g.DataPoints[0].Value; v != -3 {
				t.Errorf("clock skew = %v, want the last value -3", v)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("warden.controlplane.clock_skew_seconds not exported")
	}
}

func TestRecordBlockedIdentityReasons(t *testing.T) {
	m, rd := newWithReader(t)
	for _, r := range []string{"identity_required", "identity_expired", "identity_conflict"} {
		m.RecordBlocked(r)
	}
	seen := map[string]int64{}
	for _, sm := range collect(t, rd).ScopeMetrics {
		for _, mt := range sm.Metrics {
			if mt.Name != "warden.blocked.total" {
				continue
			}
			for _, dp := range mt.Data.(metricdata.Sum[int64]).DataPoints {
				v, _ := dp.Attributes.Value("reason")
				seen[v.AsString()] += dp.Value
			}
		}
	}
	for _, r := range []string{"identity_required", "identity_expired", "identity_conflict"} {
		if seen[r] != 1 {
			t.Errorf("blocked{reason=%s} = %d, want 1 (all: %v)", r, seen[r], seen)
		}
	}
}
