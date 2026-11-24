package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

// enrollEnv is an enrollment store on a fresh state DB, a worker CA minted at
// the fake clock, and the logs the store wrote.
type enrollEnv struct {
	path  string
	clk   *clocktest.Fake
	db    *cpstate.DB
	store *EnrollmentStore
	ca    *workerca.CA
	fix   wcaFixture
	logs  *syncBuf
}

func newEnrollEnv(t *testing.T) *enrollEnv {
	t.Helper()
	clk := clocktest.NewFake(time.Now().Truncate(time.Second))
	e := &enrollEnv{clk: clk, path: filepath.Join(t.TempDir(), "warden-cp.db"), logs: &syncBuf{}}
	e.fix = newWCAFixture(t, clk.Now())
	var err error
	e.ca, err = workerca.New(workerca.Options{
		Chain: []*x509.Certificate{e.fix.inter, e.fix.root}, Signer: e.fix.interKey, Create: wcasigner.CreateCertificate,
		Serial: wcasigner.NewSerial, TrustDomain: wcaTrustDomain, Clock: clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.db, err = cpstate.Open(context.Background(), e.path, StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.db.Close() })
	e.store, err = NewEnrollmentStore(e.db, EnrollmentOptions{Clock: clk, Logger: slog.New(slog.NewTextHandler(e.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *enrollEnv) create(t *testing.T, o EnrollCreateOpts) (string, EnrollToken) {
	t.Helper()
	if o.Actor == "" {
		o.Actor = "admin"
	}
	pt, tok, created, err := e.store.Create(context.Background(), o)
	if err != nil || !created {
		t.Fatalf("Create(%s): created=%v err=%v", o.Name, created, err)
	}
	return pt, tok
}

// issuer is the Redeem callback: an issue of the env's CA for a fresh key.
func (e *enrollEnv) issuer(t *testing.T) func(string) (*x509.Certificate, error) {
	t.Helper()
	csr := mustCSR(t)
	return func(id string) (*x509.Certificate, error) { return e.ca.Issue(csr, id, time.Hour) }
}

func csrPEM(t *testing.T) string {
	t.Helper()
	k, err := wcasigner.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestEnrollmentTokensHashedAtRest(t *testing.T) {
	e := newEnrollEnv(t)
	pt, tok := e.create(t, EnrollCreateOpts{Name: "n1", WorkerID: "worker-1"})
	if !strings.HasPrefix(pt, "wet_") || len(pt) != 56 || !strings.HasPrefix(tok.ID, "et_") || len(tok.ID) != 19 {
		t.Fatalf("token shapes: %q %q", pt, tok.ID)
	}
	if _, err := e.store.Redeem(context.Background(), pt, "", e.issuer(t)); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Close(); err != nil { // checkpoint the WAL into the file
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(pt))
	for _, name := range []string{e.path, e.path + "-wal"} {
		data, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		if bytes.Contains(data, []byte(pt)) || bytes.Contains(data, []byte(hex.EncodeToString(sum[:]))) {
			t.Errorf("%s holds the plaintext token or its hex hash", name)
		}
	}
	db, err := cpstate.Open(context.Background(), e.path, StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var hash []byte
	if err := db.SQL().QueryRow(`SELECT token_hash FROM worker_enroll_tokens WHERE id = ?`, tok.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash, sum[:]) {
		t.Fatal("token_hash is not the sha256 of the token")
	}
}

func TestEnrollmentTokensCreateValidation(t *testing.T) {
	e := newEnrollEnv(t)
	ctx := context.Background()
	cases := []struct {
		name string
		o    EnrollCreateOpts
	}{
		{"neither id nor prefix", EnrollCreateOpts{Name: "a"}},
		{"both id and prefix", EnrollCreateOpts{Name: "a", WorkerID: "w", WorkerIDPrefix: "p-"}},
		{"bad id", EnrollCreateOpts{Name: "a", WorkerID: "bad id"}},
		{"dotdot id", EnrollCreateOpts{Name: "a", WorkerID: ".."}},
		{"bad prefix", EnrollCreateOpts{Name: "a", WorkerIDPrefix: "p/"}},
		{"too long prefix", EnrollCreateOpts{Name: "a", WorkerIDPrefix: strings.Repeat("a", 128)}},
		{"uses on an id token", EnrollCreateOpts{Name: "a", WorkerID: "w", MaxUses: 2}},
		{"too many uses", EnrollCreateOpts{Name: "a", WorkerIDPrefix: "p-", MaxUses: 101}},
		{"negative uses", EnrollCreateOpts{Name: "a", WorkerIDPrefix: "p-", MaxUses: -1}},
		{"ttl over max", EnrollCreateOpts{Name: "a", WorkerID: "w", TTL: 25 * time.Hour}},
		{"negative ttl", EnrollCreateOpts{Name: "a", WorkerID: "w", TTL: -time.Hour}},
		{"no name", EnrollCreateOpts{WorkerID: "w"}},
		{"bad import", EnrollCreateOpts{Name: "a", WorkerID: "w", Plaintext: "wwt_" + strings.Repeat("a", 52)}},
	}
	for _, c := range cases {
		c.o.Actor = "admin"
		if _, _, _, err := e.store.Create(ctx, c.o); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", c.name, err)
		}
	}
	if _, _, _, err := e.store.Create(ctx, EnrollCreateOpts{Name: "a", WorkerID: "w"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("no actor: %v", err)
	}
	// Maximums are accepted: 100 uses on a prefix, the maximum TTL.
	e.create(t, EnrollCreateOpts{Name: "ok", WorkerIDPrefix: "p-", MaxUses: 100, TTL: 24 * time.Hour})
	// Defaults: one use, one hour.
	_, tok := e.create(t, EnrollCreateOpts{Name: "def", WorkerID: "w"})
	if tok.MaxUses != 1 || tok.ExpiresAt.Sub(tok.CreatedAt) != time.Hour {
		t.Errorf("defaults: %+v", tok)
	}
	// A duplicate name.
	if _, _, _, err := e.store.Create(ctx, EnrollCreateOpts{Name: "def", WorkerID: "w2", Actor: "a"}); !errors.Is(err, ErrEnrollNameTaken) {
		t.Errorf("duplicate name: %v", err)
	}
}

func TestEnrollmentTokensSingleUseAndExpiry(t *testing.T) {
	e := newEnrollEnv(t)
	ctx := context.Background()
	pt, tok := e.create(t, EnrollCreateOpts{Name: "n", WorkerID: "worker-1"})
	if got, err := e.store.Peek(pt); err != nil || got.ID != tok.ID {
		t.Fatalf("Peek = %v, %v", got, err)
	}
	res, err := e.store.Redeem(ctx, pt, "ignored-for-an-id-token", e.issuer(t))
	if err != nil || res.WorkerID != "worker-1" || res.Token.Uses != 1 {
		t.Fatalf("Redeem = %+v, %v", res, err)
	}
	rec, err := e.store.Cert(ctx, res.Cert.SerialNumber.Text(16))
	if err != nil || rec.WorkerID != "worker-1" || rec.IssuedVia != CertIssuedViaEnroll || rec.EnrollTokenID != tok.ID ||
		!rec.NotAfter.Equal(res.Cert.NotAfter.Truncate(time.Second)) || len(rec.SPKISHA256) != 64 {
		t.Fatalf("worker_certs row = %+v, %v", rec, err)
	}
	if _, err := e.store.Redeem(ctx, pt, "", e.issuer(t)); !errors.Is(err, ErrEnrollExhausted) {
		t.Fatalf("second use: %v", err)
	}
	if _, err := e.store.Peek(pt); !errors.Is(err, ErrEnrollExhausted) {
		t.Fatalf("Peek after use: %v", err)
	}

	// Expiry on the fake clock.
	pt2, _ := e.create(t, EnrollCreateOpts{Name: "n2", WorkerID: "worker-2"})
	e.clk.Advance(time.Hour)
	if _, err := e.store.Redeem(ctx, pt2, "", e.issuer(t)); !errors.Is(err, ErrEnrollExpired) {
		t.Fatalf("after 1h: %v", err)
	}
	// Unknown and malformed values.
	for _, v := range []string{"", "wet_", "wwt_" + strings.Repeat("a", 52), "wet_" + strings.Repeat("a", 52)} {
		if _, err := e.store.Redeem(ctx, v, "", e.issuer(t)); !errors.Is(err, ErrEnrollUnknown) {
			t.Errorf("Redeem(%q) = %v", v, err)
		}
		if _, err := e.store.Peek(v); !errors.Is(err, ErrEnrollUnknown) {
			t.Errorf("Peek(%q) = %v", v, err)
		}
	}
}

func TestEnrollmentTokensIssueFailureConsumesNothing(t *testing.T) {
	e := newEnrollEnv(t)
	pt, tok := e.create(t, EnrollCreateOpts{Name: "n", WorkerID: "worker-1"})
	boom := errors.New("boom")
	if _, err := e.store.Redeem(context.Background(), pt, "", func(string) (*x509.Certificate, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("issue failure: %v", err)
	}
	toks, _ := e.store.List(context.Background())
	if len(toks) != 1 || toks[0].ID != tok.ID || toks[0].Uses != 0 {
		t.Fatalf("token after a failed issue: %+v", toks)
	}
	if _, err := e.store.Redeem(context.Background(), pt, "", e.issuer(t)); err != nil {
		t.Fatalf("redeem after a failed issue: %v", err)
	}
}

func TestEnrollmentTokensPrefixPool(t *testing.T) {
	e := newEnrollEnv(t)
	ctx := context.Background()
	pt, _ := e.create(t, EnrollCreateOpts{Name: "pool", WorkerIDPrefix: "pool-a-", MaxUses: 3})
	for _, suffix := range []string{"h1", "h2", "h3"} {
		res, err := e.store.Redeem(ctx, pt, suffix, e.issuer(t))
		if err != nil || res.WorkerID != "pool-a-"+suffix {
			t.Fatalf("suffix %s: %+v, %v", suffix, res, err)
		}
	}
	if _, err := e.store.Redeem(ctx, pt, "h4", e.issuer(t)); !errors.Is(err, ErrEnrollExhausted) {
		t.Fatalf("fourth: %v", err)
	}
	// A bad suffix is refused before a use is spent.
	pt2, _ := e.create(t, EnrollCreateOpts{Name: "pool2", WorkerIDPrefix: "pool-b-", MaxUses: 2})
	for _, bad := range []string{"", "../x", "a/b", "a b", strings.Repeat("x", 128)} {
		if _, err := e.store.Redeem(ctx, pt2, bad, e.issuer(t)); !errors.Is(err, ErrEnrollBadWorkerID) {
			t.Errorf("suffix %q: %v", bad, err)
		}
	}
	if tok, err := e.store.Peek(pt2); err != nil || tok.Uses != 0 {
		t.Fatalf("uses after bad suffixes: %+v, %v", tok, err)
	}
}

func TestEnrollmentTokensConcurrentRedeem(t *testing.T) {
	e := newEnrollEnv(t)
	pt, _ := e.create(t, EnrollCreateOpts{Name: "once", WorkerID: "worker-1"})
	csr := mustCSR(t)
	var wg sync.WaitGroup
	var ok, spent atomic.Int32
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.store.Redeem(context.Background(), pt, "", func(id string) (*x509.Certificate, error) { return e.ca.Issue(csr, id, time.Hour) })
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrEnrollExhausted):
				spent.Add(1)
			default:
				t.Errorf("redeem: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || spent.Load() != 49 {
		t.Fatalf("ok=%d spent=%d, want 1 and 49", ok.Load(), spent.Load())
	}
	var n int
	if err := e.db.SQL().QueryRow(`SELECT COUNT(*) FROM worker_certs`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("worker_certs rows = %d, %v", n, err)
	}
}

func TestEnrollmentTokensRevokeAndList(t *testing.T) {
	e := newEnrollEnv(t)
	ctx := context.Background()
	pt, tok := e.create(t, EnrollCreateOpts{Name: "n", WorkerID: "worker-1"})
	if err := e.store.Revoke(ctx, tok.ID, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("revoke without actor: %v", err)
	}
	if err := e.store.Revoke(ctx, "et_nope", "admin"); !errors.Is(err, ErrEnrollNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if err := e.store.Revoke(ctx, tok.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	first, _ := e.store.List(ctx)
	e.clk.Advance(time.Minute)
	if err := e.store.Revoke(ctx, tok.ID, "other"); err != nil { // idempotent
		t.Fatal(err)
	}
	again, _ := e.store.List(ctx)
	if first[0].RevokedAt.IsZero() || !first[0].RevokedAt.Equal(again[0].RevokedAt) || again[0].RevokedBy != "admin" {
		t.Fatalf("revoke is not idempotent: %+v vs %+v", first[0], again[0])
	}
	if _, err := e.store.Peek(pt); !errors.Is(err, ErrEnrollRevoked) {
		t.Fatalf("Peek revoked: %v", err)
	}
	if _, err := e.store.Redeem(ctx, pt, "", e.issuer(t)); !errors.Is(err, ErrEnrollRevoked) {
		t.Fatalf("Redeem revoked: %v", err)
	}
}

func TestEnrollmentTokensImport(t *testing.T) {
	e := newEnrollEnv(t)
	ctx := context.Background()
	val, err := generateEnrollToken()
	if err != nil {
		t.Fatal(err)
	}
	o := EnrollCreateOpts{Name: "imp", WorkerID: "worker-2", Plaintext: val, Actor: "cli:test"}
	_, tok, created, err := e.store.Create(ctx, o)
	if err != nil || !created {
		t.Fatalf("first import: %v %v", created, err)
	}
	_, again, created, err := e.store.Create(ctx, o)
	if err != nil || created || again.ID != tok.ID {
		t.Fatalf("second import: %+v created=%v err=%v", again, created, err)
	}
	if toks, _ := e.store.List(ctx); len(toks) != 1 {
		t.Fatalf("rows = %d, want 1", len(toks))
	}
	// Same name, different binding or value: a conflict.
	o2 := o
	o2.WorkerID = "worker-3"
	if _, _, _, err := e.store.Create(ctx, o2); !errors.Is(err, ErrEnrollNameTaken) {
		t.Errorf("same name, other binding: %v", err)
	}
	other, _ := generateEnrollToken()
	o3 := o
	o3.Plaintext = other
	if _, _, _, err := e.store.Create(ctx, o3); !errors.Is(err, ErrEnrollNameTaken) {
		t.Errorf("same name, other value: %v", err)
	}
	// Same value under another name.
	o4 := o
	o4.Name = "imp2"
	if _, _, _, err := e.store.Create(ctx, o4); !errors.Is(err, ErrEnrollInUse) {
		t.Errorf("same value, other name: %v", err)
	}
	// A used-up, expired or revoked row is still an idempotent hit, never revived.
	if _, err := e.store.Redeem(ctx, val, "", e.issuer(t)); err != nil {
		t.Fatal(err)
	}
	if _, got, created, err := e.store.Create(ctx, o); err != nil || created || got.Uses != 1 {
		t.Errorf("re-import of a used token: %+v created=%v err=%v", got, created, err)
	}
	e.clk.Advance(2 * time.Hour)
	if _, got, created, err := e.store.Create(ctx, o); err != nil || created || got.Usable(e.clk.Now()) == nil {
		t.Errorf("re-import of an expired token: %+v created=%v err=%v", got, created, err)
	}
	if err := e.store.Revoke(ctx, tok.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, got, created, err := e.store.Create(ctx, o); err != nil || created || got.RevokedAt.IsZero() {
		t.Errorf("re-import of a revoked token: %+v created=%v err=%v", got, created, err)
	}
	if toks, _ := e.store.List(ctx); len(toks) != 1 {
		t.Errorf("rows = %d, want 1", len(toks))
	}
}

func TestEnrollmentTokensCrossProcessReload(t *testing.T) {
	e := newEnrollEnv(t)
	ctx := context.Background()
	// A second handle on the same file, like the offline CLI.
	db2, err := cpstate.Open(ctx, e.path, StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db2.Close() }()
	other, err := NewEnrollmentStore(db2, EnrollmentOptions{Clock: e.clk, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	pt, tok, _, err := other.Create(ctx, EnrollCreateOpts{Name: "cli", WorkerID: "worker-9", Actor: "cli:x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Peek(pt); !errors.Is(err, ErrEnrollUnknown) {
		t.Fatalf("before the poll: %v", err)
	}
	e.store.poll(ctx)
	if got, err := e.store.Peek(pt); err != nil || got.ID != tok.ID {
		t.Fatalf("after the poll: %v %v", got, err)
	}
	if err := other.Revoke(ctx, tok.ID, "cli:x"); err != nil {
		t.Fatal(err)
	}
	e.store.poll(ctx)
	if _, err := e.store.Peek(pt); !errors.Is(err, ErrEnrollRevoked) {
		t.Fatalf("after the revoke poll: %v", err)
	}
}

func TestEnrollmentStoreRunLoopOnFakeClock(t *testing.T) {
	e := newEnrollEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.store.Run(ctx) }()
	db2, err := cpstate.Open(ctx, e.path, StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db2.Close() }()
	other, _ := NewEnrollmentStore(db2, EnrollmentOptions{Clock: e.clk, Logger: slog.New(slog.DiscardHandler)})
	pt, _, _, err := other.Create(ctx, EnrollCreateOpts{Name: "late", WorkerID: "worker-5", Actor: "cli:x"})
	if err != nil {
		t.Fatal(err)
	}
	pollAdvance(t, e.clk, "the run loop to load a token another handle wrote", func() bool {
		_, err := e.store.Peek(pt)
		return err == nil
	})
	cancel()
	<-done
}

func TestWorkerCertStore(t *testing.T) {
	e := newEnrollEnv(t)
	ctx := context.Background()
	cert, err := e.ca.Issue(mustCSR(t), "worker-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rec := RecordFor(cert, "worker-1", CertIssuedViaRenew, e.clk.Now())
	rec.PrevSerial = "abc"
	if err := e.store.RecordCert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordCert(ctx, rec); err == nil {
		t.Fatal("a duplicate serial was accepted")
	}
	got, err := e.store.Cert(ctx, rec.Serial)
	if err != nil || got.PrevSerial != "abc" || got.IssuedVia != CertIssuedViaRenew || !got.RevokedAt.IsZero() {
		t.Fatalf("Cert = %+v, %v", got, err)
	}
	if err := e.store.RevokeCert(ctx, rec.Serial, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RevokeCert(ctx, rec.Serial, "admin", "test"); err != nil { // idempotent
		t.Fatal(err)
	}
	if got, _ = e.store.Cert(ctx, rec.Serial); got.RevokedAt.IsZero() {
		t.Fatal("not revoked")
	}
	if err := e.store.RevokeCert(ctx, "ffff", "admin", "test"); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("unknown serial: %v", err)
	}
	if _, err := e.store.Cert(ctx, "ffff"); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("unknown serial: %v", err)
	}
}

func TestEnrollTokenPrintsNoSecret(t *testing.T) {
	e := newEnrollEnv(t)
	pt, tok := e.create(t, EnrollCreateOpts{Name: "n", WorkerIDPrefix: "p-", MaxUses: 2})
	for _, s := range []string{tok.String(), fmt.Sprintf("%v %+v", tok, tok)} {
		if strings.Contains(s, pt) || !strings.Contains(s, tok.ID) || !strings.Contains(s, "p-*") {
			t.Errorf("printed form %q", s)
		}
	}
	var b bytes.Buffer
	slog.New(slog.NewTextHandler(&b, nil)).Info("x", "token", tok)
	if strings.Contains(b.String(), pt) || !strings.Contains(b.String(), tok.ID) {
		t.Errorf("slog form %q", b.String())
	}
	if e.logs.String() != "" && strings.Contains(e.logs.String(), pt) {
		t.Error("store log holds the token")
	}
}

func TestEnrollmentMigrationsInStateMigrations(t *testing.T) {
	for _, m := range StateMigrations() {
		if m.ID == "workerenroll/0001" {
			return
		}
	}
	t.Fatal("StateMigrations lacks workerenroll/0001")
}

func TestDefaultEnrollName(t *testing.T) {
	seen := map[string]string{}
	for _, c := range []struct{ id, prefix string }{
		{"pool-a", ""}, {"", "pool-a"}, {"", "pool-a-"},
		{strings.Repeat("a", 128), ""}, {strings.Repeat("a", 127) + "b", ""},
		{"", strings.Repeat("a", 127)}, {"", strings.Repeat("a", 126) + "b"},
	} {
		n := defaultEnrollName(c.id, c.prefix)
		if len(n) > maxWorkerTokenName || validateTokenName(n) != nil {
			t.Errorf("%q: name %q is not a valid token name", c, n)
		}
		key := c.id + "|" + c.prefix
		if prev, dup := seen[n]; dup {
			t.Errorf("%q and %q share the name %q", key, prev, n)
		}
		seen[n] = key
	}
	if got := defaultEnrollName("worker-2", ""); got != "enroll-id-worker-2" {
		t.Errorf("short id: %q", got)
	}
	if got := defaultEnrollName("", "pool-a-"); got != "enroll-prefix-pool-a-" {
		t.Errorf("short prefix: %q", got)
	}
}

func TestRecordForIssuerKID(t *testing.T) {
	e := newEnrollEnv(t)
	cert, err := e.ca.Issue(mustCSR(t), "w", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	withAKI := *cert
	withAKI.AuthorityKeyId = []byte{1, 2, 3}
	if got := RecordFor(&withAKI, "w", CertIssuedViaEnroll, e.clk.Now()).IssuerKID; got != "010203" {
		t.Errorf("kid with an authority key id = %q", got)
	}
	// An intermediate without a SubjectKeyId leaves no AuthorityKeyId: the kid
	// falls back to a hash of the issuer, never empty.
	noAKI := *cert
	noAKI.AuthorityKeyId = nil
	kid := RecordFor(&noAKI, "w", CertIssuedViaEnroll, e.clk.Now()).IssuerKID
	sum := sha256.Sum256(cert.RawIssuer)
	if kid == "" || kid != hex.EncodeToString(sum[:]) {
		t.Errorf("fallback kid = %q", kid)
	}
}
