package proxy

import (
	"sync"
	"testing"
	"time"
)

// TestProxy_SetJudge_RaceFree drives the hot-path judge read (judge()) and an
// Evaluate call concurrently with SetJudge. Under `go test -race` the atomic
// pointer must show no data race.
func TestProxy_SetJudge_RaceFree(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		Judge:      &fakeJudge{verdict: Verdict{Decision: "allow"}},
		AgentID:    "default",
	})
	if err != nil {
		t.Fatal(err)
	}

	jA := &fakeJudge{verdict: Verdict{Decision: "allow"}}
	jB := &fakeJudge{verdict: Verdict{Decision: "deny"}}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: alternate the judge (including nil to exercise the disabled path).
	wg.Add(1)
	go func() {
		defer wg.Done()
		judges := []Judge{jA, jB, nil}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				p.SetJudge(judges[i%len(judges)])
				i++
			}
		}
	}()

	// Readers: snapshot the live judge and call the hot-path entry point.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if j := p.judge(); j != nil {
						_ = j.Evaluate("default", "GET", "https://host/x", "host", "application/json", false)
					}
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestProxy_SetJudge_SwapReflected verifies SetJudge swaps the judge the reader
// observes: a fresh judge replaces the seeded one, and SetJudge(nil) disables it.
func TestProxy_SetJudge_SwapReflected(t *testing.T) {
	seed := &fakeJudge{verdict: Verdict{Decision: "allow"}}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		Judge:      seed,
		AgentID:    "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.judge() != seed {
		t.Fatal("expected seeded judge")
	}

	replacement := &fakeJudge{verdict: Verdict{Decision: "deny"}}
	p.SetJudge(replacement)
	if p.judge() != replacement {
		t.Fatal("expected swapped-in judge")
	}
	if v := p.judge().Evaluate("default", "GET", "https://h/x", "h", "", false); v.Decision != "deny" {
		t.Fatalf("swapped judge verdict = %q, want deny", v.Decision)
	}

	p.SetJudge(nil)
	if p.judge() != nil {
		t.Fatal("expected nil judge after disabling swap")
	}
}

// TestProxy_NilJudge_SeedAndNoOp confirms a proxy constructed with no judge loads
// nil through the atomic pointer (judge disabled — today's behavior), matching a
// local-only worker that never received judge settings.
func TestProxy_NilJudge_SeedAndNoOp(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		Judge:      nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.judge() != nil {
		t.Fatal("expected nil judge when none configured")
	}

	j := &fakeJudge{verdict: Verdict{Decision: "allow"}}
	p.SetJudge(j)
	if p.judge() != j {
		t.Fatal("expected swapped-in judge")
	}
}
