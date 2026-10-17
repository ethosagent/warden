//go:build e2e

package compose

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The Docker-driving primitives of the compose target: subprocess plumbing,
// the CA-trusting HTTP reads (recorder, fleet API, health), and the shared
// stack's bring-up/teardown/health. Error-returning only — the harness Target
// methods layer on top, and test/e2e wraps them with its tb-fatalf shims.
//
// Every file in this package that imports os/exec or builds an HTTP client
// carries the `e2e` build tag: the architecture gate (and the default
// `go test ./...`) never sees Docker code, exactly like test/e2e.

// readLimit bounds how much of an HTTP body a read keeps (the fleet views and
// recorder dumps are kilobytes; the bound is against a runaway, not a diet).
const readLimit = 32 << 20

// Result is one finished subprocess.
type Result struct {
	Stdout string
	Stderr string
	Exit   int
}

// RepoRoot finds the module root (the dir holding go.mod) above the cwd.
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// Run executes name in dir with a hard timeout. A process that cannot start
// or is killed by the timeout returns Exit -1 with the reason in Stderr.
func Run(dir string, timeout time.Duration, name string, args ...string) Result {
	return runCmd(dir, nil, timeout, name, args...)
}

// RunStdin is Run with stdin fed to the process (the agent shim's --data-binary @-).
func RunStdin(dir string, timeout time.Duration, stdin []byte, name string, args ...string) Result {
	return runCmd(dir, stdin, timeout, name, args...)
}

func runCmd(dir string, stdin []byte, timeout time.Duration, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := execCommand(ctx, name, args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	switch e := err.(type) {
	case nil:
	case *execExitError:
		res.Exit = e.ExitCode()
		if ctx.Err() != nil {
			res.Exit = -1
			res.Stderr += "\n(timed out after " + timeout.String() + ")"
		}
	default:
		res.Exit = -1
		res.Stderr += err.Error()
	}
	return res
}

// ComposeRun runs `docker compose -f … -f … args…` from the repo root.
func ComposeRun(timeout time.Duration, args ...string) Result {
	root, err := RepoRoot()
	if err != nil {
		return Result{Exit: -1, Stderr: err.Error()}
	}
	return Run(root, timeout, "docker", ComposeArgs(args...)...)
}

// MakeTarget runs `make <target>` from the repo root, streaming its output to
// stderr (a bring-up or teardown failure must show WHY, in place), and returns
// its exit code.
func MakeTarget(target string, timeout time.Duration) int {
	root, err := RepoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "compose:", err)
		return -1
	}
	res := Run(root, timeout, "make", target)
	fmt.Fprint(os.Stderr, res.Stdout, res.Stderr)
	return res.Exit
}

// ExecBroken reports compose's own "cannot exec here" stderr, which a command
// run inside the container never produces.
func ExecBroken(stderr string) bool {
	return strings.Contains(stderr, "is not running") || strings.Contains(stderr, "no such service")
}

// AgentRunRaw runs args inside an agent container (`docker compose exec -T`)
// and returns the result. A failure OF THE EXEC is a harness bug, not blocked
// traffic, so it is an error here: a typo in a negative row can never look
// like a successful block. Docker reserves 125-127 for "docker/exec failed"
// (binary not found, not executable), and compose reports a missing or
// stopped service with exit 1 and ExecBroken's stderr.
func AgentRunRaw(service string, args ...string) (Result, error) {
	return AgentRunStdin(service, nil, args...)
}

// AgentRunStdin is AgentRunRaw with stdin fed to the command (a request body
// on `curl --data-binary @-`).
func AgentRunStdin(service string, stdin []byte, args ...string) (Result, error) {
	root, err := RepoRoot()
	if err != nil {
		return Result{}, err
	}
	res := RunStdin(root, AgentTimeout, stdin, "docker", ComposeArgs(append([]string{"exec", "-T", service}, args...)...)...)
	if res.Exit < 0 || (res.Exit >= 125 && res.Exit <= 127) || ExecBroken(res.Stderr) {
		return res, fmt.Errorf("compose: exec in %s is broken (exit %d), not a network result: %v: %s",
			service, res.Exit, args, strings.TrimSpace(res.Stderr))
	}
	return res, nil
}

// ContainerIP is the service container's address on a compose network.
func ContainerIP(service, network string) (string, error) {
	id := ComposeRun(ComposeDeadline, "ps", "-q", service)
	cid := strings.TrimSpace(id.Stdout)
	if id.Exit != 0 || cid == "" {
		return "", fmt.Errorf("no container for %s: %s", service, id.Stderr)
	}
	res := Run(".", ComposeDeadline, "docker", "inspect", "-f",
		`{{with index .NetworkSettings.Networks "`+network+`"}}{{.IPAddress}}{{end}}`, cid)
	ip := strings.TrimSpace(res.Stdout)
	if res.Exit != 0 || ip == "" {
		return "", fmt.Errorf("%s has no address on %s: %s", service, network, res.Stderr)
	}
	return ip, nil
}

// NetworkGateway is the host-side gateway address of a compose network.
func NetworkGateway(network string) (string, error) {
	res := Run(".", ComposeDeadline, "docker", "network", "inspect", "-f",
		`{{(index .IPAM.Config 0).Gateway}}`, network)
	gw := strings.TrimSpace(res.Stdout)
	if res.Exit != 0 || gw == "" {
		return "", fmt.Errorf("no gateway for network %s: %s", network, res.Stderr)
	}
	return gw, nil
}

// CAPool parses the repo's lab proxy CA into a root pool: the trust the CP's
// server cert (and every worker's MITM leaf) is minted from.
func CAPool() (*x509.CertPool, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(filepath.Join(root, CAPath))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", CAPath)
	}
	return pool, nil
}

// oneShot builds a client whose transport holds NO connection after a read:
// keep-alives are off, because these are one-shot host-side probes and an idle
// keep-alive conn (two goroutines) is exactly what the harness's
// goroutine-leak check flags as a leak. pool, when set, is the root pool for
// TLS (the lab proxy CA for the control plane).
func oneShot(pool *x509.CertPool) *http.Client {
	tr := &http.Transport{DisableKeepAlives: true}
	if pool != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: tr}
}

// CAClient is the host-side HTTPS client for the stack's TLS endpoints (the
// control plane): it trusts the lab proxy CA the CP's server cert is minted
// from — the same trust the operators' dashboard has. TryGet drives it for a
// plain GET; test/e2e re-exports it for callers that need more than a GET.
func CAClient() (*http.Client, error) {
	pool, err := CAPool()
	if err != nil {
		return nil, err
	}
	return oneShot(pool), nil
}

// TryGet GETs url with the CA-trusting client and returns status and body.
func TryGet(url string) (int, []byte, error) {
	cl, err := CAClient()
	if err != nil {
		return 0, nil, err
	}
	resp, err := cl.Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	return resp.StatusCode, body, err
}

// PlainGet GETs an http:// url (the recorder, the workers' admins) and returns
// status and body.
func PlainGet(url string) (int, []byte, error) {
	resp, err := oneShot(nil).Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	return resp.StatusCode, body, err
}

// FleetBody reads one control-plane fleet-API path.
func FleetBody(path string) ([]byte, error) {
	code, body, err := TryGet(CPBase + path)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("fleet API %s returned %d: %.200s", path, code, body)
	}
	return body, nil
}

// WorkerTrafficBody reads one worker's own traffic API (leak-scan surface; in
// central mode it is normally empty — the CP holds the fleet view).
func WorkerTrafficBody(worker string) ([]byte, error) {
	base, ok := WorkerAdminBase(worker)
	if !ok {
		return nil, fmt.Errorf("unknown worker %q", worker)
	}
	code, body, err := PlainGet(base + TrafficPath)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("%s traffic API returned %d", worker, code)
	}
	return body, nil
}

// RecorderRaw is the recorder's /_recorded body, verbatim (a leak-scan surface).
func RecorderRaw() ([]byte, error) {
	code, body, err := PlainGet(RecorderBase + RecordedPath)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("recorder %s returned %d", RecordedPath, code)
	}
	return body, nil
}

// RecorderRequests returns what the fake upstream saw, oldest first.
func RecorderRequests() ([]Request, error) {
	raw, err := RecorderRaw()
	if err != nil {
		return nil, err
	}
	return DecodeRecorded(raw)
}

// ResetRecorder clears the recorder (and any armed DNS rebinds).
func ResetRecorder() error {
	resp, err := oneShot(nil).Post(RecorderBase+ResetPath, "", nil)
	if err != nil {
		return fmt.Errorf("reset the recorder: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reset the recorder: status %d", resp.StatusCode)
	}
	return nil
}

// CPHealthy reports whether the control plane serves /healthz right now.
func CPHealthy(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if code, _, err := TryGet(CPBase + "/healthz"); err == nil && code == http.StatusOK {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// PollUntil polls cond every 500ms until it returns true or the deadline
// passes, then fails with the last observation. The only waiting primitive in
// the package (no fixed sleeps).
func PollUntil(timeout time.Duration, cond func() (bool, string)) error {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		ok, seen := cond()
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("last seen: %s", seen)
		}
		<-tick.C
	}
}

// WaitStackReady waits for the CP and every worker's /healthz, the recorder,
// and the CP's worker registry (every worker online = policy pulled).
func WaitStackReady() error {
	urls := []string{CPBase + "/healthz", WorkerAdmin1 + "/healthz", WorkerAdmin2 + "/healthz",
		WorkerAdmin3 + "/healthz", RecorderBase + RecorderHealth}
	return PollUntil(StackDeadline, func() (bool, string) {
		for _, u := range urls {
			if code, _, err := TryGet(u); err != nil || code != http.StatusOK {
				return false, fmt.Sprintf("%s: status %d err %v", u, code, err)
			}
		}
		body, err := FleetBody("/dashboard/api/workers")
		if err != nil {
			return false, err.Error()
		}
		var ws []struct {
			ProxyID string `json:"proxyID"`
			Online  bool   `json:"online"`
		}
		if err := json.Unmarshal(body, &ws); err != nil {
			return false, err.Error()
		}
		online := map[string]bool{}
		for _, w := range ws {
			online[w.ProxyID] = w.Online
		}
		if !online[SvcWorker1] || !online[SvcWorker2] || !online[SvcWorker3] {
			return false, fmt.Sprintf("workers online: %v", online)
		}
		return true, ""
	})
}
