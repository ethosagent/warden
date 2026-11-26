package security

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

// Enrollment and renewal actors (W-P2-SECT-06): a worker certificate the suite
// holds the key of (so a case can present it, renew it, or revoke it without
// touching the two stack workers), crafted CSRs, and the CP state a case must
// leave untouched.

const (
	enrollRoute = "/control/enroll"
	renewRoute  = "/control/renew"
)

// Leaf is a worker certificate issued by the control plane's /control/enroll or
// /control/renew, with the key behind it.
type Leaf struct {
	ID   string
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Serial is the certificate's serial as the CP prints it (lowercase hex).
func (l Leaf) Serial() string { return l.Cert.SerialNumber.Text(16) }

// TLS is the certificate as a client credential.
func (l Leaf) TLS() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{l.Cert.Raw}, PrivateKey: l.Key}
}

// CSROptions shapes a certificate request. Every field is something an
// attacker controls and the CA must ignore.
type CSROptions struct {
	// Key signs the request; nil generates a fresh P-256 key.
	Key crypto.Signer
	// CommonName, DNSNames, Emails, IPs and URIs are the requested subject and
	// SANs.
	CommonName string
	DNSNames   []string
	Emails     []string
	IPs        []net.IP
	URIs       []*url.URL
	// CA adds a BasicConstraints CA:true extension request.
	CA bool
	// Extensions are further extension requests, verbatim.
	Extensions []pkix.Extension
}

var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

// NewCSR builds a PEM certificate request. It returns the key behind it and
// registers the PEM with the leak invariant (a CSR must never be echoed or
// logged).
func (s *Stack) NewCSR(tb testing.TB, o CSROptions) (crypto.Signer, string) {
	tb.Helper()
	key := o.Key
	if key == nil {
		k, err := wcasigner.GenerateKey()
		if err != nil {
			tb.Fatalf("security: generate a CSR key: %v", err)
		}
		key = k
	}
	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: o.CommonName},
		DNSNames:       o.DNSNames,
		EmailAddresses: o.Emails,
		IPAddresses:    o.IPs,
		URIs:           o.URIs,
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, o.Extensions...)
	if o.CA {
		val, err := asn1.Marshal(struct {
			IsCA bool `asn1:"optional"`
		}{IsCA: true})
		if err != nil {
			tb.Fatalf("security: encode basic constraints: %v", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidBasicConstraints, Critical: true, Value: val})
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		tb.Fatalf("security: create a CSR: %v", err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	s.tracker.add("csr", csr)
	// The bare base64 body (no armor, no newlines) is what a handler that logs
	// the decoded request field would print; tracker.add already derives it
	// from the multi-line PEM, and the explicit add pins that.
	s.tracker.add("csr body", base64.StdEncoding.EncodeToString(der))
	return key, csr
}

// RSACSR is a well-formed, correctly self-signed request for an RSA key: the
// CA accepts only P-256 and Ed25519.
func (s *Stack) RSACSR(tb testing.TB) string {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("security: generate an RSA key: %v", err)
	}
	_, csr := s.NewCSR(tb, CSROptions{Key: key})
	return csr
}

// TrackToken registers an enrollment token and its stored hash with the leak
// invariant: neither may appear in any response, log, audit row or metric.
func (s *Stack) TrackToken(token string) {
	h := sha256.Sum256([]byte(token))
	s.tracker.add("enrollment token", token)
	s.tracker.add("enrollment token hash", hex.EncodeToString(h[:]))
	for name, enc := range map[string]*base64.Encoding{
		"std": base64.StdEncoding, "raw std": base64.RawStdEncoding, "url": base64.URLEncoding, "raw url": base64.RawURLEncoding,
	} {
		s.tracker.add("enrollment token hash (base64 "+name+")", enc.EncodeToString(h[:]))
	}
}

// postJSON posts a JSON body through cl and returns the reply in full.
func (s *Stack) postJSON(tb testing.TB, cl *http.Client, path string, body any) Reply {
	tb.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		tb.Fatalf("security: encode the %s request: %v", path, err)
	}
	return s.Send(tb, cl, http.MethodPost, path, http.Header{"Content-Type": {"application/json"}}, raw)
}

// Enroll posts a wet_ token and a CSR to /control/enroll with no credential
// besides the token, as a worker does.
func (s *Stack) Enroll(tb testing.TB, token, csr, suffix string) Reply {
	tb.Helper()
	s.TrackToken(token)
	body := map[string]string{"token": token, "csr": csr}
	if suffix != "" {
		body["workerIdSuffix"] = suffix
	}
	return s.postJSON(tb, s.CP.HTTP, enrollRoute, body)
}

// Renew posts csr to /control/renew presenting l in the TLS handshake.
func (s *Stack) Renew(tb testing.TB, l Leaf, csr string) Reply {
	tb.Helper()
	cert := l.TLS()
	return s.postJSON(tb, s.CPClient(tb, &cert), renewRoute, map[string]string{"csr": csr})
}

// issued is the 201 body of /control/enroll and /control/renew.
type issued struct {
	WorkerID    string   `json:"workerId"`
	SpiffeID    string   `json:"spiffeId"`
	Certificate string   `json:"certificate"`
	Chain       []string `json:"chain"`
	Serial      string   `json:"serial"`
	PrevSerial  string   `json:"prevSerial"`
}

// ParseIssued decodes a 201 body into the certificate it carries. It fails the
// test for anything else.
func (s *Stack) ParseIssued(tb testing.TB, r Reply, key crypto.Signer) (Leaf, issued) {
	tb.Helper()
	var out issued
	if r.Status != http.StatusCreated || json.Unmarshal([]byte(r.Body), &out) != nil {
		tb.Fatalf("security: want a 201 with a certificate, got %d %s", r.Status, tail(r.Body, 200))
	}
	certs, err := workerca.ParseCertsPEM([]byte(out.Certificate))
	if err != nil || len(certs) != 1 {
		tb.Fatalf("security: the issued certificate does not parse (%d certificates): %v", len(certs), err)
	}
	ek, _ := key.(*ecdsa.PrivateKey)
	return Leaf{ID: out.WorkerID, Cert: certs[0], Key: ek}, out
}

// NewLeaf enrolls a fresh key for workerID through the admin API and
// /control/enroll, exactly as an operator and a worker would, and returns the
// certificate. The key PEM is registered with the leak invariant.
func (s *Stack) NewLeaf(tb testing.TB, workerID string) Leaf {
	tb.Helper()
	token := s.AdminSession(tb).CreateEnrollmentToken(tb, workerID)
	key, csr := s.NewCSR(tb, CSROptions{})
	l, _ := s.ParseIssued(tb, s.Enroll(tb, token, csr, ""), key)
	der, err := x509.MarshalPKCS8PrivateKey(l.Key)
	if err != nil {
		tb.Fatalf("security: encode the leaf key: %v", err)
	}
	s.tracker.add("key PEM", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	return l
}

// CookieValue is the raw console session cookie of the session (the credential
// a browser holds), registered with the leak invariant at login.
func (c *Session) CookieValue(tb testing.TB) string {
	tb.Helper()
	u, err := url.Parse(c.s.CP.URL)
	if err != nil {
		tb.Fatalf("security: parse the CP URL: %v", err)
	}
	for _, ck := range c.cl.Jar.Cookies(u) {
		if ck.Name == consoleSessionCookie {
			return ck.Value
		}
	}
	tb.Fatalf("security: the session has no %s cookie", consoleSessionCookie)
	return ""
}

// CertRow is one row of worker_certs.
type CertRow struct {
	Serial, WorkerID, SPKI, Prev, Via, RevokeReason string
	Revoked                                         bool
}

// EnrollRow is one row of worker_enroll_tokens (no hash, no plaintext).
type EnrollRow struct {
	ID, Name        string
	Uses, MaxUses   int
	Revoked         bool
	WorkerID, Pools string
}

func (s *Stack) openState(tb testing.TB) *cpstate.DB {
	tb.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(s.CP.StateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		tb.Fatalf("security: open the CP state db: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	return db
}

// CertRows returns every certificate the CP has issued, oldest first, read
// straight from its state database. workerID "" returns all.
func (s *Stack) CertRows(tb testing.TB, workerID string) []CertRow {
	tb.Helper()
	db := s.openState(tb)
	rows, err := db.SQL().Query(`SELECT serial, worker_id, spki_sha256, COALESCE(prev_serial, ''), issued_via,
		revoked_at IS NOT NULL, COALESCE(revoke_reason, '') FROM worker_certs ORDER BY issued_at, rowid`)
	if err != nil {
		tb.Fatalf("security: read worker_certs: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CertRow
	for rows.Next() {
		var r CertRow
		if err := rows.Scan(&r.Serial, &r.WorkerID, &r.SPKI, &r.Prev, &r.Via, &r.Revoked, &r.RevokeReason); err != nil {
			tb.Fatalf("security: scan a worker_certs row: %v", err)
		}
		if workerID == "" || r.WorkerID == workerID {
			out = append(out, r)
		}
	}
	if err := rows.Err(); err != nil {
		tb.Fatalf("security: read worker_certs: %v", err)
	}
	return out
}

// EnrollRows returns every enrollment token row.
func (s *Stack) EnrollRows(tb testing.TB) []EnrollRow {
	tb.Helper()
	db := s.openState(tb)
	rows, err := db.SQL().Query(`SELECT id, name, uses, max_uses, revoked_at IS NOT NULL, COALESCE(worker_id, ''), COALESCE(worker_id_prefix, '')
		FROM worker_enroll_tokens ORDER BY created_at, rowid`)
	if err != nil {
		tb.Fatalf("security: read worker_enroll_tokens: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []EnrollRow
	for rows.Next() {
		var r EnrollRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Uses, &r.MaxUses, &r.Revoked, &r.WorkerID, &r.Pools); err != nil {
			tb.Fatalf("security: scan a worker_enroll_tokens row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		tb.Fatalf("security: read worker_enroll_tokens: %v", err)
	}
	return out
}

// EnrollRowByName returns the token row of name.
func (s *Stack) EnrollRowByName(tb testing.TB, name string) EnrollRow {
	tb.Helper()
	for _, r := range s.EnrollRows(tb) {
		if r.Name == name {
			return r
		}
	}
	tb.Fatalf("security: no enrollment token named %q", name)
	return EnrollRow{}
}

// State is what an enrollment or renewal attack may change in the CP: the
// certificates issued and revoked, the enrollment token uses and the admin
// audit rows.
type State struct {
	Certs, RevokedCerts, TokenUses, TokensRevoked, Audit int
}

// State reads it.
func (s *Stack) State(tb testing.TB) State {
	tb.Helper()
	var st State
	for _, c := range s.CertRows(tb, "") {
		st.Certs++
		if c.Revoked {
			st.RevokedCerts++
		}
	}
	for _, e := range s.EnrollRows(tb) {
		st.TokenUses += e.Uses
		if e.Revoked {
			st.TokensRevoked++
		}
	}
	st.Audit = len(s.auditSince(tb, 0))
	return st
}

// auditSince returns every admin audit row newer than since. It filters
// nothing: an idle control plane writes no background audit rows (#709 fixed
// the false config.external_change row), so any extra row is a real event
// and fails the case's exact count.
func (s *Stack) auditSince(tb testing.TB, since int64) []AuditRow {
	tb.Helper()
	var out []AuditRow
	for _, r := range s.AuditRows(tb, "") {
		if r.Seq > since {
			out = append(out, r)
		}
	}
	return out
}

// AuditMark is the sequence number of the newest admin audit row.
func (s *Stack) AuditMark(tb testing.TB) int64 {
	tb.Helper()
	rows := s.AuditRows(tb, "")
	if len(rows) == 0 {
		return 0
	}
	return rows[len(rows)-1].Seq
}

// ExpectAudit fails tb unless the admin audit rows written since mark (not
// counting the background drift row) are exactly want, in order, each with the
// outcome given by outcome ("" skips the check).
func (s *Stack) ExpectAudit(tb testing.TB, mark int64, outcome string, want ...string) []AuditRow {
	tb.Helper()
	rows := s.auditSince(tb, mark)
	var got []string
	for _, r := range rows {
		got = append(got, r.Action)
		if outcome != "" && r.Outcome != outcome {
			tb.Errorf("audit row %s has outcome %q, want %q", r.Action, r.Outcome, outcome)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		tb.Errorf("new admin audit rows = %v, want %v", got, want)
	}
	return rows
}
