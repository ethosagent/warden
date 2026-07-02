package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// dlpEnforceScanner builds a DLP scanner in enforce mode with a class default so
// hasPolicy() is true — the shape a managed worker rebuilds from settings.
func dlpEnforceScanner() *DLPScanner {
	return NewDLPScanner(config.DLPConfig{
		Mode:    config.DLPModeEnforce,
		Classes: map[string]config.DLPClassDefault{"credentials": {Action: config.DLPActionBlock}},
	}, false, false)
}

// TestProxy_SetDLP_SwapsBehavior verifies a runtime SetDLP swaps the live scanner
// observed through dlp()/DLPMode(): a proxy seeded with no DLP reads disabled, a
// swap installs an active scanner, and a swap to nil disables it again — the
// hot-swap the control-plane apply loop drives.
func TestProxy_SetDLP_SwapsBehavior(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seeded from a nil cfg.DLP: disabled, byte-identical to before.
	if p.dlp() != nil || p.DLPMode() != "" {
		t.Fatalf("expected DLP disabled at boot, got mode=%q", p.DLPMode())
	}

	// Swap in an enforce scanner: dlp() reflects it immediately.
	p.SetDLP(dlpEnforceScanner())
	if d := p.dlp(); d == nil || d.mode != config.DLPModeEnforce {
		t.Fatalf("SetDLP did not install the enforce scanner: %+v", d)
	}
	if p.DLPMode() != config.DLPModeEnforce {
		t.Errorf("DLPMode = %q, want enforce", p.DLPMode())
	}
	if !p.dlp().hasPolicy() {
		t.Error("swapped scanner should carry the class-default policy")
	}

	// Swap to nil: DLP disabled again (nil scanner = off, no body read).
	p.SetDLP(nil)
	if p.dlp() != nil || p.DLPMode() != "" {
		t.Errorf("SetDLP(nil) should disable DLP, got mode=%q", p.DLPMode())
	}
}

// TestProxy_New_SeedsDLP verifies New seeds the atomic holder from cfg.DLP, so an
// unmanaged worker's boot behavior is unchanged (the seeded scanner is live).
func TestProxy_New_SeedsDLP(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		DLP:        dlpEnforceScanner(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.dlp() == nil || p.DLPMode() != config.DLPModeEnforce {
		t.Fatalf("New should seed dlp() from cfg.DLP, got mode=%q", p.DLPMode())
	}
}

// TestProxy_SetDLP_RaceFree drives the hot-path read (dlp() → scan) concurrently
// with SetDLP (including nil to exercise the disabled path). Under `go test -race`
// the atomic pointer must show no data race, since the read path takes no lock.
func TestProxy_SetDLP_RaceFree(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		DLP:        dlpEnforceScanner(),
	})
	if err != nil {
		t.Fatal(err)
	}

	scanners := []*DLPScanner{
		dlpEnforceScanner(),
		NewDLPScanner(config.DLPConfig{Mode: config.DLPModeMonitor}, false, false),
		nil,
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: alternate the scanner (including nil, the disabled path).
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				p.SetDLP(scanners[i%len(scanners)])
				i++
			}
		}
	}()

	// Readers: snapshot the live scanner and run the hot-path work.
	body := []byte("token=AKIAIOSFODNN7EXAMPLE&note=hello")
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if d := p.dlp(); d != nil {
						_ = d.scan(body)
						_ = p.DLPMode()
					}
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}
