package controlplane

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	keysigner "github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

const wcaTrustDomain = "warden.local"

// wcaFixture is a worker CA on disk: chain PEM, and the intermediate key file
// at 0600, both outside any state dir.
type wcaFixture struct {
	dir      string
	chain    string
	keyFile  string
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
}

func newWCAFixture(t *testing.T, now time.Time) wcaFixture {
	t.Helper()
	f := wcaFixture{dir: t.TempDir()}
	var err error
	if f.root, f.rootKey, err = wcasigner.NewRoot(now); err != nil {
		t.Fatal(err)
	}
	if f.interKey, err = wcasigner.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	if f.inter, err = wcasigner.NewIntermediate(f.root, f.rootKey, &f.interKey.PublicKey, wcaTrustDomain, now); err != nil {
		t.Fatal(err)
	}
	f.chain = filepath.Join(f.dir, "intermediate-chain.pem")
	if err := os.WriteFile(f.chain, workerca.EncodeCertsPEM(f.inter, f.root), 0o644); err != nil {
		t.Fatal(err)
	}
	pemKey, err := keysigner.MarshalPKCS8PEM(f.interKey)
	if err != nil {
		t.Fatal(err)
	}
	f.keyFile = filepath.Join(f.dir, "intermediate.key")
	if err := os.WriteFile(f.keyFile, pemKey, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// yaml is the workerCA block (plus the extra lines) for the fixture.
func (f wcaFixture) yaml(source string) string {
	s := fmt.Sprintf("workerCA:\n  enabled: true\n  trustDomain: %s\n  certFile: %s\n  keySource: %s\n", wcaTrustDomain, f.chain, source)
	if source == "file" {
		s += "  keyFile: " + f.keyFile + "\n"
	}
	return s
}

func wcaConfig(t *testing.T, extra string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("policy:\n  allowlist:\n    - domain: api.openai.com\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func writeCert(t *testing.T, path string, certs ...*x509.Certificate) string {
	t.Helper()
	if err := os.WriteFile(path, workerca.EncodeCertsPEM(certs...), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveWorkerCA(t *testing.T) {
	now := time.Now()
	f := newWCAFixture(t, now)
	keysOn := config.DefaultKeys()
	keysOn.Enabled = true
	keysOff := config.DefaultKeys()
	resolve := func(cfgExtra, stateDir, caCert string, kc config.KeysConfig) (*workerCAPlan, error) {
		return resolveWorkerCA(wcaConfig(t, cfgExtra), stateDir, caCert, kc, clock.Real(), discardLogger())
	}

	t.Run("disabled by default", func(t *testing.T) {
		if p, err := resolve("", "", "", keysOff); p != nil || err != nil {
			t.Fatalf("plan=%v err=%v", p, err)
		}
		if p, err := resolveWorkerCA("", "", "", keysOff, clock.Real(), discardLogger()); p != nil || err != nil {
			t.Fatalf("no config: plan=%v err=%v", p, err)
		}
	})
	t.Run("keys source needs keys.enabled", func(t *testing.T) {
		_, err := resolve(f.yaml("keys"), "", "", keysOff)
		if err == nil || !strings.Contains(err.Error(), "workerCA.keySource") {
			t.Fatalf("err = %v", err)
		}
		if p, err := resolve(f.yaml("keys"), "", "", keysOn); err != nil || p == nil {
			t.Fatalf("keys enabled: %v", err)
		}
	})
	t.Run("intermediate equal to --ca-cert", func(t *testing.T) {
		_, err := resolve(f.yaml("keys"), "", writeCert(t, filepath.Join(t.TempDir(), "ca.pem"), f.inter), keysOn)
		if err == nil || !strings.Contains(err.Error(), "--ca-cert") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("intermediate chaining to --ca-cert", func(t *testing.T) {
		// The proxy CA is the worker root here: the intermediate chains to it.
		_, err := resolve(f.yaml("keys"), "", writeCert(t, filepath.Join(t.TempDir(), "ca.pem"), f.root), keysOn)
		if err == nil || !strings.Contains(err.Error(), "--ca-cert") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("an unrelated --ca-cert passes", func(t *testing.T) {
		other := newWCAFixture(t, now)
		if _, err := resolve(f.yaml("keys"), "", other.chain, keysOn); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("expired intermediate", func(t *testing.T) {
		old := newWCAFixture(t, now.AddDate(-3, 0, 0))
		_, err := resolve(old.yaml("keys"), "", "", keysOn)
		if err == nil || !strings.Contains(err.Error(), "workerCA.certFile") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing chain file", func(t *testing.T) {
		_, err := resolve("workerCA:\n  enabled: true\n  trustDomain: warden.local\n  certFile: /nonexistent/chain.pem\n", "", "", keysOn)
		if err == nil || !strings.Contains(err.Error(), "workerCA.certFile") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("key file mode", func(t *testing.T) {
		g := newWCAFixture(t, now)
		if err := os.Chmod(g.keyFile, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := resolve(g.yaml("file"), "", "", keysOff)
		if err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("key file inside state dir", func(t *testing.T) {
		g := newWCAFixture(t, now)
		_, err := resolve(g.yaml("file"), g.dir, "", keysOff)
		if err == nil || !strings.Contains(err.Error(), "--state-dir") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("key file outside state dir loads and warns once", func(t *testing.T) {
		g := newWCAFixture(t, now)
		var logs strings.Builder
		lg := slog.New(slog.NewTextHandler(&logs, nil))
		p, err := resolveWorkerCA(wcaConfig(t, g.yaml("file")), t.TempDir(), "", keysOff, clock.Real(), lg)
		if err != nil || p == nil || p.fileSigner == nil {
			t.Fatalf("plan=%v err=%v", p, err)
		}
		if n := strings.Count(logs.String(), "development only"); n != 1 {
			t.Fatalf("dev WARN count = %d\n%s", n, logs.String())
		}
	})
	t.Run("key file that is not a key", func(t *testing.T) {
		g := newWCAFixture(t, now)
		if err := os.WriteFile(g.keyFile, []byte("not a key"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := resolve(g.yaml("file"), "", "", keysOff); err == nil {
			t.Fatal("garbage key file accepted")
		}
	})
}

func TestWorkerCALoad(t *testing.T) {
	now := time.Now()
	f := newWCAFixture(t, now)
	mkPlan := func(g wcaFixture) *workerCAPlan {
		p, err := resolveWorkerCA(wcaConfig(t, g.yaml("file")), "", "", config.DefaultKeys(), clocktest.NewFake(now), discardLogger())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca, err := mkPlan(f).Load(context.Background(), nil)
	if err != nil || ca == nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := ca.Issue(mustCSR(t), "w1", time.Hour); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// A key that is not the intermediate's is a startup error, not degraded.
	other := newWCAFixture(t, now)
	p := mkPlan(f)
	p.fileSigner = other.interKey
	if _, err := p.Load(context.Background(), nil); err == nil || errorsIsDegraded(err) {
		t.Fatalf("mismatch: %v", err)
	}
}

func errorsIsDegraded(err error) bool { return err == errWorkerCADegraded }

func mustCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	k, err := wcasigner.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// healthzBody returns /healthz's body.
func healthzBody(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", resp.StatusCode)
	}
	return string(b)
}

func TestWorkerCAStartupLogsOneLineAndServes(t *testing.T) {
	f := newWCAFixture(t, time.Now())
	base, logs, stop := runCPServing(t, Params{ConfigPath: wcaConfig(t, f.yaml("file"))})
	defer stop()
	if got := healthzBody(t, base); got != "ok\n" {
		t.Fatalf("healthz = %q", got)
	}
	out := logs.String()
	if n := strings.Count(out, `"worker_ca":"enabled"`); n != 1 {
		t.Fatalf("worker_ca enabled lines = %d\n%s", n, out)
	}
	for _, want := range []string{`"trust_domain":"warden.local"`, `"intermediate_subject":`, `"not_after":`, `"key_source":"file"`} {
		if !strings.Contains(out, want) {
			t.Errorf("startup log lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"BEGIN", "PRIVATE"} {
		if strings.Contains(out, bad) {
			t.Errorf("log carries key material marker %q", bad)
		}
	}
}

func TestWorkerCAStartupRefusals(t *testing.T) {
	f := newWCAFixture(t, time.Now())
	run := func(p Params) error {
		p.ListenAddr = "127.0.0.1:0"
		p.AnalyticsProvider = "memory"
		return Run(context.Background(), io.Discard, p)
	}
	// keys source with keys disabled: before listening, naming the key.
	err := run(Params{ConfigPath: wcaConfig(t, f.yaml("keys")), StateDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "workerCA.keySource") {
		t.Fatalf("keys disabled: %v", err)
	}
	// An intermediate equal to the --ca-cert (even without --ca-key it is read).
	err = run(Params{ConfigPath: wcaConfig(t, f.yaml("file")), CACert: f.chain, CAKey: f.keyFile})
	if err == nil || !strings.Contains(err.Error(), "--ca-cert") {
		t.Fatalf("shared CA: %v", err)
	}
	// A key that is not the intermediate's.
	g := newWCAFixture(t, time.Now())
	if err := os.WriteFile(f.keyFile, mustRead(t, g.keyFile), 0o600); err != nil {
		t.Fatal(err)
	}
	err = run(Params{ConfigPath: wcaConfig(t, f.yaml("file"))})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("key mismatch: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWorkerCADegradedUntilTheKeyArrives: with keySource keys and no ca key
// imported the control plane starts degraded (healthz says so) and the 30s
// retry loop installs the CA once `ca init` stores the key.
func TestWorkerCADegradedUntilTheKeyArrives(t *testing.T) {
	stateDir := openKeysStateDir(t)
	f := newWCAFixture(t, time.Now())
	clk := clocktest.NewFake(time.Now())
	cfg := writeKeysPolicy(t, keysEnabledYAML+f.yaml("keys"))
	base, logs, stop := runCPServing(t, Params{ConfigPath: cfg, StateDir: stateDir, Clock: clk})
	defer stop()
	if got := healthzBody(t, base); !strings.HasPrefix(got, "degraded") {
		t.Fatalf("healthz = %q, want degraded", got)
	}
	if !strings.Contains(logs.String(), "worker CA degraded") {
		t.Fatalf("no degraded WARN:\n%s", logs.String())
	}
	ok, err := OpenKeysOffline(context.Background(), stateDir, KeysCLIOptions{ConfigPath: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ok.importCA(context.Background(), f.interKey, false); err != nil {
		t.Fatal(err)
	}
	_ = ok.Close()
	// Drive the fake clock by condition: other loops share it, so a fixed
	// advance could skip the retry timer being armed.
	pollAdvance(t, clk, "the worker CA to recover", func() bool { return healthzBody(t, base) == "ok\n" })
	if !strings.Contains(logs.String(), `"worker_ca":"ready"`) {
		t.Fatalf("no ready line:\n%s", logs.String())
	}
}

func TestCAInit(t *testing.T) {
	t.Run("file source", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "ca")
		state := t.TempDir()
		var so, se strings.Builder
		o := CAInitOptions{
			CAOptions:   CAOptions{KeySource: "file", StateDir: state, Out: &so, ErrOut: &se},
			OutDir:      out,
			TrustDomain: wcaTrustDomain,
		}
		if err := CAInit(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"root.key", "intermediate.key"} {
			fi, err := os.Stat(filepath.Join(out, name))
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v mode %v", name, err, fi)
			}
		}
		if !strings.Contains(se.String(), "root.key") || !strings.Contains(se.String(), "offline") {
			t.Fatalf("no offline warning: %q", se.String())
		}
		// A second run without --force fails and changes nothing.
		before := mustRead(t, filepath.Join(out, "root.key"))
		if err := CAInit(context.Background(), o); err == nil {
			t.Fatal("second run without --force succeeded")
		}
		if string(mustRead(t, filepath.Join(out, "root.key"))) != string(before) {
			t.Fatal("root.key changed without --force")
		}
		o.Force = true
		if err := CAInit(context.Background(), o); err != nil {
			t.Fatalf("--force: %v", err)
		}
		// The chain it wrote is a valid worker CA with the key it wrote.
		chain, err := workerca.ParseCertsPEM(mustRead(t, filepath.Join(out, "intermediate-chain.pem")))
		if err != nil || len(chain) != 2 {
			t.Fatalf("chain: %d %v", len(chain), err)
		}
		key, err := keysigner.ParsePKCS8PEM(mustRead(t, filepath.Join(out, "intermediate.key")))
		if err != nil {
			t.Fatal(err)
		}
		ca, err := workerca.New(workerca.Options{Chain: chain, Signer: key, Create: wcasigner.CreateCertificate, Serial: wcasigner.NewSerial, TrustDomain: wcaTrustDomain})
		if err != nil {
			t.Fatal(err)
		}
		if ca.Intermediate().MaxPathLen != 0 || len(ca.Intermediate().PermittedURIDomains) != 1 {
			t.Fatal("intermediate constraints")
		}
		// The state dir holds no key material.
		entries, _ := os.ReadDir(state)
		if len(entries) != 0 {
			t.Fatalf("state dir not empty: %v", entries)
		}
		// The key file may not be written inside the state dir.
		o.OutDir = filepath.Join(state, "ca")
		if err := CAInit(context.Background(), o); err == nil {
			t.Fatal("out-dir inside state-dir accepted")
		}
	})
	t.Run("bad inputs", func(t *testing.T) {
		base := CAOptions{KeySource: "file", Out: io.Discard, ErrOut: io.Discard}
		for name, o := range map[string]CAInitOptions{
			"trust domain":  {CAOptions: base, OutDir: t.TempDir(), TrustDomain: "Bad Domain"},
			"no out dir":    {CAOptions: base, TrustDomain: wcaTrustDomain},
			"key source":    {CAOptions: CAOptions{KeySource: "kms"}, OutDir: t.TempDir(), TrustDomain: wcaTrustDomain},
			"keys no state": {CAOptions: CAOptions{KeySource: "keys"}, OutDir: t.TempDir(), TrustDomain: wcaTrustDomain},
		} {
			if err := CAInit(context.Background(), o); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
	t.Run("keys source stores the key in the manager", func(t *testing.T) {
		stateDir := openKeysStateDir(t)
		out := filepath.Join(t.TempDir(), "ca")
		var so strings.Builder
		o := CAInitOptions{
			CAOptions:   CAOptions{KeySource: "keys", StateDir: stateDir, Out: &so, ErrOut: io.Discard},
			OutDir:      out,
			TrustDomain: wcaTrustDomain,
		}
		if err := CAInit(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(out, "intermediate.key")); err == nil {
			t.Fatal("keys source wrote an intermediate key file")
		}
		states := keyStatesOf(t, stateDir, keys.PurposeCA)
		if len(states) != 1 {
			t.Fatalf("ca rows = %v", states)
		}
		// The imported key is the intermediate's: the manager hands it out.
		chain, _ := workerca.ParseCertsPEM(mustRead(t, filepath.Join(out, "intermediate-chain.pem")))
		ok, err := OpenKeysOffline(context.Background(), stateDir, KeysCLIOptions{})
		if err != nil {
			t.Fatal(err)
		}
		sg, err := ok.mgr.Signer(context.Background(), keys.PurposeCA)
		if err != nil {
			t.Fatal(err)
		}
		x, isX := sg.(interface{ CryptoSigner() crypto.Signer })
		if !isX {
			t.Fatal("local ca signer exposes no CryptoSigner")
		}
		if _, err := workerca.New(workerca.Options{Chain: chain, Signer: x.CryptoSigner(), Create: wcasigner.CreateCertificate, Serial: wcasigner.NewSerial, TrustDomain: wcaTrustDomain}); err != nil {
			t.Fatalf("manager key does not match the chain: %v", err)
		}
		_ = ok.Close()
		// A second run fails (files and key exist), --force replaces both.
		if err := CAInit(context.Background(), o); err == nil {
			t.Fatal("second run without --force succeeded")
		}
		o.Force = true
		if err := CAInit(context.Background(), o); err != nil {
			t.Fatalf("--force: %v", err)
		}
		if got := keyStatesOf(t, stateDir, keys.PurposeCA); len(got) != 1 {
			t.Fatalf("ca rows after force = %v", got)
		}
	})
}

func TestCACSR(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "k.pem")
	var so strings.Builder
	o := CACSROptions{CAOptions: CAOptions{KeySource: "file", Out: &so, ErrOut: io.Discard}, KeyFile: keyFile}
	if err := CACSR(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	csr, err := workerca.ParseCSRPEM([]byte(so.String()))
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	if fi, err := os.Stat(keyFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v", err)
	}
	if strings.Contains(so.String(), "PRIVATE") {
		t.Fatal("stdout carries a private key")
	}
	if err := CACSR(context.Background(), o); err == nil {
		t.Fatal("existing key file overwritten without --force")
	}
	o.KeyFile = ""
	if err := CACSR(context.Background(), o); err == nil {
		t.Fatal("missing --key-file accepted")
	}
	// keys source.
	stateDir := openKeysStateDir(t)
	var so2 strings.Builder
	ko := CACSROptions{CAOptions: CAOptions{KeySource: "keys", StateDir: stateDir, Out: &so2, ErrOut: io.Discard}}
	if err := CACSR(context.Background(), ko); err != nil {
		t.Fatal(err)
	}
	if _, err := workerca.ParseCSRPEM([]byte(so2.String())); err != nil {
		t.Fatal(err)
	}
	if len(keyStatesOf(t, stateDir, keys.PurposeCA)) != 1 {
		t.Fatal("csr did not store the key")
	}
	if err := CACSR(context.Background(), ko); err == nil {
		t.Fatal("second csr replaced the ca key without --force")
	}
}

// keyStatesOf reads one purpose's kid to state rows from the state database.
func keyStatesOf(t *testing.T, stateDir, purpose string) map[string]string {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT kid, state FROM signing_keys WHERE purpose = ?`, purpose)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var kid, state string
		if err := rows.Scan(&kid, &state); err != nil {
			t.Fatal(err)
		}
		out[kid] = state
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// pollAdvance advances clk by the retry interval until cond holds or the
// deadline passes; it never sleeps a fixed time.
func pollAdvance(t *testing.T, clk *clocktest.Fake, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", desc)
		}
		clk.Advance(workerCARetryInterval)
		<-time.After(5 * time.Millisecond)
	}
}

func TestResolveWorkerCAPrevious(t *testing.T) {
	now := time.Now()
	f := newWCAFixture(t, now)
	keysOn := config.DefaultKeys()
	keysOn.Enabled = true
	withPrev := func(prev string) string {
		return f.yaml("keys") + "  previousCertFile: " + prev + "\n"
	}
	// An expired previous intermediate is dropped with one WARN, startup goes on.
	old := newWCAFixture(t, now.AddDate(-3, 0, 0))
	var logs strings.Builder
	lg := slog.New(slog.NewTextHandler(&logs, nil))
	p, err := resolveWorkerCA(wcaConfig(t, withPrev(old.chain)), "", "", keysOn, clock.Real(), lg)
	if err != nil || p == nil || len(p.previous) != 0 {
		t.Fatalf("expired previous: plan=%v err=%v", p, err)
	}
	if n := strings.Count(logs.String(), "previousCertFile"); n != 1 {
		t.Errorf("WARN count = %d\n%s", n, logs.String())
	}
	// A valid previous is pinned.
	cur := newWCAFixture(t, now)
	p, err = resolveWorkerCA(wcaConfig(t, withPrev(cur.chain)), "", "", keysOn, clock.Real(), discardLogger())
	if err != nil || len(p.previous) == 0 {
		t.Fatalf("valid previous: %v", err)
	}
	// A structurally wrong one (the root: path length 1) is fatal.
	rootOnly := writeCert(t, filepath.Join(t.TempDir(), "root.pem"), f.root)
	if _, err := resolveWorkerCA(wcaConfig(t, withPrev(rootOnly)), "", "", keysOn, clock.Real(), discardLogger()); err == nil ||
		!strings.Contains(err.Error(), "previousCertFile") {
		t.Fatalf("wrong previous: %v", err)
	}
	// The verifier exists with no key: it is what keeps cert auth alive while degraded.
	if p.verifier == nil {
		t.Fatal("plan has no verifier")
	}
}

func TestWorkerCAPlanPrintsNoKey(t *testing.T) {
	f := newWCAFixture(t, time.Now())
	p, err := resolveWorkerCA(wcaConfig(t, f.yaml("file")), "", "", config.DefaultKeys(), clock.Real(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := p.build(p.fileSigner)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(f.interKey)
	rawKey, _ := f.interKey.Bytes()
	for _, v := range []any{p, ca} {
		for _, form := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(form, v)
			if strings.Contains(out, fmt.Sprintf("%v", rawKey)) || strings.Contains(out, string(der)) {
				t.Errorf("%s prints key material: %s", form, out)
			}
		}
	}
}

// TestCAInitForceRefusesBeforeWriting: with the state dir locked (a running
// control plane), `ca init --force` fails before touching any file, and a
// plain re-run fails without changes too.
func TestCAInitForceRefusesBeforeWriting(t *testing.T) {
	stateDir := openKeysStateDir(t)
	out := filepath.Join(t.TempDir(), "ca")
	o := CAInitOptions{
		CAOptions:   CAOptions{KeySource: "keys", StateDir: stateDir, Out: io.Discard, ErrOut: io.Discard},
		OutDir:      out,
		TrustDomain: wcaTrustDomain,
	}
	if err := CAInit(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	snap := func() map[string]string {
		m := map[string]string{}
		ents, _ := os.ReadDir(out)
		for _, e := range ents {
			m[e.Name()] = string(mustRead(t, filepath.Join(out, e.Name())))
		}
		return m
	}
	before := snap()
	if len(before) != 3 {
		t.Fatalf("files = %d, want 3", len(before))
	}
	release, err := cpstate.AcquireDirLock(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	o.Force = true
	err = CAInit(context.Background(), o)
	_ = release()
	if err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("--force under the lock: %v", err)
	}
	after := snap()
	if len(after) != len(before) {
		t.Fatalf("stray files after a refusal: %v", after)
	}
	for name, content := range before {
		if after[name] != content {
			t.Errorf("%s changed by a refused --force", name)
		}
	}
	// And the key manager still holds the original key: one active ca row.
	if got := keyStatesOf(t, stateDir, keys.PurposeCA); len(got) != 1 {
		t.Fatalf("ca rows = %v", got)
	}
}

// TestCAInitKeysSourceLeavesNoKeyInTheDatabase: the intermediate key is in
// the key store, never in warden-cp.db (or its WAL).
func TestCAInitKeysSourceLeavesNoKeyInTheDatabase(t *testing.T) {
	stateDir := openKeysStateDir(t)
	o := CAInitOptions{
		CAOptions:   CAOptions{KeySource: "keys", StateDir: stateDir, Out: io.Discard, ErrOut: io.Discard},
		OutDir:      filepath.Join(t.TempDir(), "ca"),
		TrustDomain: wcaTrustDomain,
	}
	if err := CAInit(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	ok, err := OpenKeysOffline(context.Background(), stateDir, KeysCLIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sg, err := ok.mgr.CertSigner(context.Background())
	_ = ok.Close()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(sg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := sg.(*ecdsa.PrivateKey).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"warden-cp.db", "warden-cp.db-wal"} {
		b, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil {
			continue
		}
		if bytes.Contains(b, der) || bytes.Contains(b, d) {
			t.Errorf("%s holds the intermediate key", name)
		}
	}
}

// TestCAInitClearsStaleTempFiles: staging files an interrupted run left behind
// are removed (and counted) at the next start; other files stay.
func TestCAInitClearsStaleTempFiles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ca")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := []string{".ca-111.tmp", ".ca-222.tmp"}
	for _, n := range stale {
		if err := os.WriteFile(filepath.Join(out, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keep := filepath.Join(out, "notes.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var se strings.Builder
	err := CAInit(context.Background(), CAInitOptions{
		CAOptions:   CAOptions{KeySource: "file", Out: io.Discard, ErrOut: &se},
		OutDir:      out,
		TrustDomain: wcaTrustDomain,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range stale {
		if _, err := os.Stat(filepath.Join(out, n)); err == nil {
			t.Errorf("%s survived", n)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("unrelated file removed: %v", err)
	}
	if !strings.Contains(se.String(), "removed 2 stale") {
		t.Errorf("no count reported: %q", se.String())
	}
	ents, _ := os.ReadDir(out)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left: %s", e.Name())
		}
	}
}
