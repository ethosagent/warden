package scan

import "testing"

func TestPrivateIP(t *testing.T) {
	s := NewScanner()
	for _, ok := range []string{
		"10.0.0.5", "172.16.31.9", "192.168.1.1", "169.254.10.20",
	} {
		dets := s.ScanResponse([]byte("host at " + ok + " reachable"))
		assertDetection(t, dets, "infrastructure", "private_ip")
		if !hasClass(dets, "private_ip", ClassInfrastructure) {
			t.Fatalf("%s must carry infrastructure class", ok)
		}
	}
	for _, no := range []string{
		"8.8.8.8",         // public
		"172.32.0.1",      // just outside 172.16/12
		"999.999.999.999", // invalid octets
		"1.2.3",           // not a dotted quad
	} {
		dets := s.ScanResponse([]byte("host at " + no + " reachable"))
		assertNoDetection(t, dets, "infrastructure", "private_ip")
	}
}

func TestInternalHostname(t *testing.T) {
	s := NewScanner()
	for _, ok := range []string{
		"db1.internal", "payments.corp", "api.default.svc.cluster.local",
	} {
		dets := s.ScanResponse([]byte("connect to " + ok + " now"))
		assertDetection(t, dets, "infrastructure", "internal_hostname")
	}
	dets := s.ScanResponse([]byte("visit https://example.com today"))
	assertNoDetection(t, dets, "infrastructure", "internal_hostname")
}

func TestAWSResourceIdentifiers(t *testing.T) {
	s := NewScanner()
	dets := s.ScanResponse([]byte("role arn:aws:iam::123456789012:role/admin here"))
	assertDetection(t, dets, "infrastructure", "aws_arn")

	dets = s.ScanResponse([]byte("instance i-0abcdef1234567890 running"))
	assertDetection(t, dets, "infrastructure", "aws_resource_id")

	dets = s.ScanResponse([]byte("net vpc-0a1b2c3d in use"))
	assertDetection(t, dets, "infrastructure", "aws_resource_id")
}

func TestK8sManifestCooccurrence(t *testing.T) {
	s := NewScanner()
	manifest := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
	dets := s.ScanResponse([]byte(manifest))
	assertDetection(t, dets, "infrastructure", "k8s_manifest")

	// A lone `kind:` (no apiVersion) must NOT trigger.
	dets = s.ScanResponse([]byte("kind: regards\nfrom the team\n"))
	assertNoDetection(t, dets, "infrastructure", "k8s_manifest")
}
