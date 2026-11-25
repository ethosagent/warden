package worker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
)

// TestControlPlaneMTLSClient (W-P2-WBND-05): against a control plane that needs
// a client certificate and rejects any Authorization header, every call the
// worker makes succeeds: pull, long-poll, heartbeat, analytics batch and MCP
// snapshot. The bearer env is set on purpose: with a certificate it is unused.
func TestControlPlaneMTLSClient(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	cp.rejectAuth.Store(true)
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	t.Setenv("WARDEN_TEST_CP_TOKEN", "bearer-must-not-be-sent")
	logger, logs := certLogger()
	wc, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := pollPolicy(t, wc, cp.endpoint())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if _, err := rp.PollLong(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("PollLong: %v", err)
	}
	if err := rp.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	remote, err := analytics.NewHTTPRemoteStore(cp.srv.URL+"/central/ingest", "", wc.WorkerID(), wc.Client(cpClientTimeout))
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.SendBatch([]analytics.Event{{Timestamp: certT0, Domain: "api.allowed.example", Port: 443, Decision: "allow"}}); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if err := remote.SendMCP(analytics.MCPSnapshot{}); err != nil {
		t.Fatalf("SendMCP: %v", err)
	}
	if cp.sawBearer() {
		t.Error("an Authorization header reached the control plane")
	}
	if got := logs.String(); strings.Contains(got, "PRIVATE KEY") || strings.Contains(got, "bearer-must-not-be-sent") {
		t.Errorf("key material or a credential reached the logs: %s", got)
	}
}

// TestControlPlaneCertRenewMidPoll: a renewal that lands while a long-poll is
// held does not cancel it (it completes with 200), and the next request, made
// after the held one finished, handshakes with the new serial instead of
// reusing the held connection and the old certificate.
func TestControlPlaneCertRenewMidPoll(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	cp.rejectAuth.Store(true)
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	logger, _ := certLogger()
	wc, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := pollPolicy(t, wc, cp.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	oldSerial := wc.source.Current().Serial()

	entered, release := make(chan string, 1), make(chan struct{})
	cp.pollHook = func(serial string) {
		entered <- serial
		<-release
	}
	type pollResult struct {
		changed bool
		err     error
	}
	done := make(chan pollResult, 1)
	go func() {
		changed, err := rp.PollLong(context.Background(), time.Minute)
		done <- pollResult{changed, err}
	}()
	if got := <-entered; got != oldSerial {
		t.Fatalf("the held poll presented serial %s, want %s", got, oldSerial)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wc.jitter = func() float64 { return 0 }
	wc.start(ctx, nil)
	waitFor(t, "the renewer to arm", func() bool { return clk.PendingTimers() >= 2 })
	clk.Advance(12 * time.Hour)
	waitFor(t, "the renewed certificate", func() bool { return wc.source.Current().Serial() != oldSerial })
	newSerial := wc.source.Current().Serial()
	// The renewal also closed the idle connections; the poll must still be alive.
	select {
	case r := <-done:
		t.Fatalf("the renewal ended the held poll: %+v", r)
	default:
	}

	// While the old poll is still held, a new request must not ride its
	// (HTTP/2) connection and the old certificate.
	if err := rp.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	cp.mu.Lock()
	during := cp.heartbeats[len(cp.heartbeats)-1]
	cp.mu.Unlock()
	if during["_serial"] != newSerial {
		t.Errorf("a request made after the renewal, during the held poll, presented serial %v, want %s", during["_serial"], newSerial)
	}

	close(release)
	r := <-done
	if r.err != nil || !r.changed {
		t.Fatalf("held poll after the renewal = changed %v, err %v, want a 200", r.changed, r.err)
	}
	if err := rp.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	cp.mu.Lock()
	last := cp.heartbeats[len(cp.heartbeats)-1]
	cp.mu.Unlock()
	if last["_serial"] != newSerial {
		t.Errorf("the request after the renewal presented serial %v, want the new %s", last["_serial"], newSerial)
	}
	if cp.sawBearer() {
		t.Error("an Authorization header reached the control plane")
	}
}

// TestRun_EnrollsFromTokenAndUsesTheCertForEveryCall boots worker.Run with
// controlPlane.enrollment against a control plane that needs the client
// certificate and rejects any Authorization header. The worker enrolls once
// from its wet_ token, then pulls policy, long-polls, heartbeats and forwards
// analytics over the certificate, with a bearer env set that must stay unused.
func TestRun_EnrollsFromTokenAndUsesTheCertForEveryCall(t *testing.T) {
	clk := clocktest.NewFake(time.Now()) // Run uses the real clock: the certificate must be valid now
	cp := newCertCP(t, clk)
	cp.rejectAuth.Store(true)
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	t.Setenv("WARDEN_TEST_CP_TOKEN", "bearer-must-not-be-sent")
	base := "https://" + strings.TrimPrefix(cp.srv.URL, "https://")
	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: error
  format: json
controlPlane:
  endpoint: ` + base + `/policy
  tokenEnv: WARDEN_TEST_CP_TOKEN
  caCert: ` + cp.caPath + `
  stateDir: ` + t.TempDir() + `
  enrollment:
    tokenEnv: WARDEN_TEST_ENROLL_TOKEN
  pollInterval: 20ms
  longPollWait: 10ms
  heartbeatInterval: 20ms
central:
  mode: worker
  endpoint: ` + base + `/central/ingest
  interval: 50ms
`
	p := runParams(t, writeConfig(t, cfg))
	logs := &syncBuf{}
	p.ErrOut = logs
	seed, err := analytics.NewSQLiteStore("file:"+p.DBPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.StoreEvent(analytics.Event{Domain: "api.openai.com", Decision: "allow", Protocol: "https"}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, logs, p) }()
	defer func() {
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	waitFor(t, "a heartbeat and an ingest over the certificate", func() bool {
		select {
		case err := <-runErr:
			t.Fatalf("Run ended early: %v", err)
		default:
		}
		cp.mu.Lock()
		defer cp.mu.Unlock()
		return len(cp.heartbeats) > 0 && len(cp.ingestIDs) > 0
	})
	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := cp.enrolls.Load(); n != 1 {
		t.Errorf("enrollments = %d, want 1", n)
	}
	if cp.sawBearer() {
		t.Error("an Authorization header reached the control plane")
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.ingestIDs[0] != "worker-1/worker-1" {
		t.Errorf("ingest identity = %s, want the certificate's worker-1 in both places", cp.ingestIDs[0])
	}
	if cp.heartbeats[0]["_id"] != "worker-1" {
		t.Errorf("heartbeat identity = %v", cp.heartbeats[0]["_id"])
	}
}

// TestCPTransportCloseIdleConnectionsReachesRetiredPools: a request that was in
// flight when the transport rotated finishes on the old pool; closing the idle
// connections at shutdown closes that connection too instead of leaving it to
// the idle timeout.
func TestCPTransportCloseIdleConnectionsReachesRetiredPools(t *testing.T) {
	var open atomic.Int64
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			open.Add(1)
		case http.StateClosed:
			open.Add(-1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	base := srv.Client().Transport.(*http.Transport).Clone()
	tr := newCPTransport(base)
	done := make(chan error, 1)
	go func() {
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	<-entered
	tr.Rotate()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	tr.CloseIdleConnections()
	waitFor(t, "the retired pool's connection to close", func() bool { return open.Load() == 0 })
}
