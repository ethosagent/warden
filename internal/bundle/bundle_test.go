package bundle_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

const secretValue = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func newKey(t testing.TB, alg string) (*signer.LocalSigner, keys.JWK) {
	t.Helper()
	s, err := signer.GenerateLocal(alg)
	if err != nil {
		t.Fatal(err)
	}
	j, err := keys.PublicJWK(s.Public(), alg)
	if err != nil {
		t.Fatal(err)
	}
	return s, j
}

func base(seq int64) bundle.Bundle {
	return bundle.Bundle{
		Seq:           seq,
		PolicyVersion: 3,
		IssuedAt:      t0,
		ExpiresAt:     t0.Add(24 * time.Hour),
		CPID:          "cp-1",
		Policy:        json.RawMessage(`{"allowlist": ["a.example.com"], "note": "<b>&</b>"}`),
		Sections:      map[string]json.RawMessage{"tokenJWKS": json.RawMessage(`{"keys":[]}`)},
	}
}

func opts() bundle.Options {
	return bundle.Options{Now: t0.Add(time.Minute), Skew: 5 * time.Minute, Issuer: "cp-1"}
}

func mustSign(t testing.TB, b bundle.Bundle, c *bundle.Credentials, s ...keys.Signer) []byte {
	t.Helper()
	raw, err := bundle.Sign(context.Background(), b, c, s...)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// resign decodes an envelope, lets edit change its payload bytes, and signs
// the new bytes with s so the signature is valid for them.
func resign(t testing.TB, raw []byte, s keys.Signer, edit func(payload []byte) []byte) []byte {
	t.Helper()
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	payload = edit(payload)
	in := append([]byte(bundle.SigningPrefix+"\x00"), payload...)
	sig, err := s.Sign(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = base64.RawURLEncoding.EncodeToString(payload)
	env.Signatures = []bundle.Signature{{KID: s.KID(), Sig: base64.RawURLEncoding.EncodeToString(sig)}}
	out, _ := json.Marshal(env)
	return out
}

func mutateEnv(t testing.TB, raw []byte, f func(*bundle.Envelope)) []byte {
	t.Helper()
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	f(&env)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func flipB64(t testing.TB, s string, i int) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	b[i] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestSignVerify(t *testing.T) {
	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
		t.Run(alg, func(t *testing.T) {
			s, pin := newKey(t, alg)
			raw := mustSign(t, base(5), nil, s)
			v, err := bundle.Verify(raw, []keys.JWK{pin}, bundle.State{}, opts())
			if err != nil {
				t.Fatal(err)
			}
			if v.Seq != 5 || v.Bundle.Seq != 5 || v.KID != s.KID() || v.Refresh || v.Credentials != nil {
				t.Fatalf("unexpected result %+v", v)
			}
			if len(v.ContentSHA256) != 64 || v.ContentSHA256 != v.Bundle.ContentSHA256 {
				t.Fatalf("content hash %q", v.ContentSHA256)
			}
			if string(v.Bundle.Policy) != `{"allowlist":["a.example.com"],"note":"<b>&</b>"}` {
				t.Fatalf("policy not preserved byte for byte: %s", v.Bundle.Policy)
			}
			if v.Bundle.Typ != bundle.TypV1 {
				t.Fatalf("typ %q", v.Bundle.Typ)
			}
		})
	}
}

func TestSignVerifySameContentSameHash(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	a := mustSign(t, base(5), nil, s)
	later := base(5)
	later.IssuedAt = t0.Add(time.Hour)
	later.ExpiresAt = later.IssuedAt.Add(time.Hour)
	b := mustSign(t, later, nil, s)
	va, _ := bundle.Verify(a, []keys.JWK{pin}, bundle.State{}, opts())
	vb, err := bundle.Verify(b, []keys.JWK{pin}, bundle.State{}, bundle.Options{Now: t0.Add(time.Hour), Issuer: "cp-1"})
	if err != nil || va.ContentSHA256 != vb.ContentSHA256 {
		t.Fatalf("timestamps must not change the content hash: %v", err)
	}
}

func TestSignVerifyTwoSigners(t *testing.T) {
	s1, p1 := newKey(t, keys.AlgEdDSA)
	s2, p2 := newKey(t, keys.AlgES256)
	raw := mustSign(t, base(1), nil, s1, s2)
	for _, pins := range [][]keys.JWK{{p1}, {p2}, {p1, p2}} {
		if _, err := bundle.Verify(raw, pins, bundle.State{}, opts()); err != nil {
			t.Fatalf("pins %d: %v", len(pins), err)
		}
	}
	// A bad signature by one pinned key does not veto a good one by another.
	bad := mutateEnv(t, raw, func(e *bundle.Envelope) { e.Signatures[0].Sig = flipB64(t, e.Signatures[0].Sig, 0) })
	if _, err := bundle.Verify(bad, []keys.JWK{p1, p2}, bundle.State{}, opts()); err != nil {
		t.Fatalf("one good signature must suffice: %v", err)
	}
	if _, err := bundle.Verify(bad, []keys.JWK{p1}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestSignVerifyEveryByteFlipFails(t *testing.T) {
	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
		s, pin := newKey(t, alg)
		raw := mustSign(t, base(5), nil, s)
		var env bundle.Envelope
		_ = json.Unmarshal(raw, &env)
		payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
		for i := range payload {
			bad := mutateEnv(t, raw, func(e *bundle.Envelope) { e.Payload = flipB64(t, e.Payload, i) })
			if _, err := bundle.Verify(bad, []keys.JWK{pin}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrBadSignature) {
				t.Fatalf("%s payload byte %d: got %v", alg, i, err)
			}
		}
		sig, _ := base64.RawURLEncoding.DecodeString(env.Signatures[0].Sig)
		for i := range sig {
			bad := mutateEnv(t, raw, func(e *bundle.Envelope) { e.Signatures[0].Sig = flipB64(t, e.Signatures[0].Sig, i) })
			if _, err := bundle.Verify(bad, []keys.JWK{pin}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrBadSignature) {
				t.Fatalf("%s sig byte %d: got %v", alg, i, err)
			}
		}
	}
}

func TestSignVerifyCredentials(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	creds := &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secretValue}
	raw := mustSign(t, base(2), creds, s)
	v, err := bundle.Verify(raw, []keys.JWK{pin}, bundle.State{}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if v.Credentials == nil || *v.Credentials != *creds || v.Bundle.CredentialsSHA256 == "" {
		t.Fatalf("credentials not returned: %+v", v.Credentials)
	}
	// The signed payload never carries the secret.
	var env bundle.Envelope
	_ = json.Unmarshal(raw, &env)
	payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	if bytes.Contains(payload, []byte(secretValue)) {
		t.Fatal("secret leaked into the signed payload")
	}
}

func TestVerifyRejectsCredentialMismatch(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	raw := mustSign(t, base(2), &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secretValue}, s)
	cases := map[string]func(*bundle.Envelope){
		"swapped secret": func(e *bundle.Envelope) { e.Credentials.SecretAccessKey = secretValue + "X" },
		"swapped key id": func(e *bundle.Envelope) { e.Credentials.AccessKeyID = "AKIAOTHER" },
		"stripped":       func(e *bundle.Envelope) { e.Credentials = nil },
	}
	for name, f := range cases {
		_, err := bundle.Verify(mutateEnv(t, raw, f), []keys.JWK{pin}, bundle.State{}, opts())
		if !errors.Is(err, bundle.ErrCredentialMismatch) {
			t.Fatalf("%s: got %v", name, err)
		}
		if strings.Contains(err.Error(), secretValue) || strings.Contains(err.Error(), "AKIA") {
			t.Fatalf("%s: error leaks a credential: %v", name, err)
		}
	}
	// A sidecar the signed payload never committed to is rejected too.
	plain := mustSign(t, base(2), nil, s)
	extra := mutateEnv(t, plain, func(e *bundle.Envelope) {
		e.Credentials = &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secretValue}
	})
	if _, err := bundle.Verify(extra, []keys.JWK{pin}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrCredentialMismatch) {
		t.Fatalf("uncommitted sidecar: got %v", err)
	}
	// An empty sidecar object is the same as none.
	empty := mutateEnv(t, plain, func(e *bundle.Envelope) { e.Credentials = &bundle.Credentials{} })
	if _, err := bundle.Verify(empty, []keys.JWK{pin}, bundle.State{}, opts()); err != nil {
		t.Fatalf("empty sidecar: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	other, otherPin := newKey(t, keys.AlgEdDSA)
	pins := []keys.JWK{pin}
	good := mustSign(t, base(5), nil, s)

	withPayload := func(edit func(*bundle.Bundle)) []byte {
		return resign(t, good, s, func(p []byte) []byte {
			var b bundle.Bundle
			if err := json.Unmarshal(p, &b); err != nil {
				t.Fatal(err)
			}
			edit(&b)
			out, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			return out
		})
	}

	tests := []struct {
		name    string
		raw     []byte
		pins    []keys.JWK
		applied bundle.State
		opt     bundle.Options
		want    error
		reason  string
	}{
		{"malformed envelope", []byte(`{"payload":`), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"not an object", []byte(`[]`), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"bad payload base64", mutateEnv(t, good, func(e *bundle.Envelope) { e.Payload = "!!!" }), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"empty payload", mutateEnv(t, good, func(e *bundle.Envelope) { e.Payload = "" }), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"too many signatures", mutateEnv(t, good, func(e *bundle.Envelope) {
			for range 20 {
				e.Signatures = append(e.Signatures, e.Signatures[0])
			}
		}), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"too large", bytes.Repeat([]byte(" "), bundle.MaxEnvelopeBytes+1), pins, bundle.State{}, opts(), bundle.ErrTooLarge, "too_large"},
		{"unsigned", mutateEnv(t, good, func(e *bundle.Envelope) { e.Signatures = nil }), pins, bundle.State{}, opts(), bundle.ErrUnsigned, "unsigned"},
		{"unknown kid", good, []keys.JWK{otherPin}, bundle.State{}, opts(), bundle.ErrUnknownKid, "unknown_kid"},
		{"no pins", good, nil, bundle.State{}, opts(), bundle.ErrUnknownKid, "unknown_kid"},
		{"bad signature", mutateEnv(t, good, func(e *bundle.Envelope) { e.Signatures[0].Sig = "AAAA" }), pins, bundle.State{}, opts(), bundle.ErrBadSignature, "bad_signature"},
		{"sig not base64", mutateEnv(t, good, func(e *bundle.Envelope) { e.Signatures[0].Sig = "***" }), pins, bundle.State{}, opts(), bundle.ErrBadSignature, "bad_signature"},
		{"signed by another key", resign(t, good, other, func(p []byte) []byte { return p }), pins, bundle.State{}, opts(), bundle.ErrUnknownKid, "unknown_kid"},
		{"unsupported typ", withPayload(func(b *bundle.Bundle) { b.Typ = "warden-bundle/v2" }), pins, bundle.State{}, opts(), bundle.ErrUnsupportedFormat, "unsupported_format"},
		{"signed garbage payload", resign(t, good, s, func([]byte) []byte { return []byte(`{not json`) }), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"content hash lies", withPayload(func(b *bundle.Bundle) { b.ContentSHA256 = strings.Repeat("0", 64) }), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"zero seq", withPayload(func(b *bundle.Bundle) { b.Seq = 0 }), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"expires before issued", withPayload(func(b *bundle.Bundle) { b.ExpiresAt = b.IssuedAt.Add(-time.Hour) }), pins, bundle.State{}, opts(), bundle.ErrMalformed, "malformed"},
		{"issuer mismatch", good, pins, bundle.State{}, bundle.Options{Now: t0, Issuer: "cp-2"}, bundle.ErrIssuerMismatch, "issuer_mismatch"},
		{"future", good, pins, bundle.State{}, bundle.Options{Now: t0.Add(-10 * time.Minute), Skew: 5 * time.Minute}, bundle.ErrFuture, "future"},
		{"zero now fails closed", good, pins, bundle.State{}, bundle.Options{}, bundle.ErrFuture, "future"},
		{"expired", good, pins, bundle.State{}, bundle.Options{Now: t0.Add(24*time.Hour + 6*time.Minute), Skew: 5 * time.Minute}, bundle.ErrExpired, "expired"},
		{"rollback", good, pins, bundle.State{Seq: 6, ContentSHA256: "x"}, opts(), bundle.ErrRollback, "rollback"},
		{"equivocation", good, pins, bundle.State{Seq: 5, ContentSHA256: "different"}, opts(), bundle.ErrEquivocation, "equivocation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := bundle.Verify(tt.raw, tt.pins, tt.applied, tt.opt)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if got := bundle.Reason(err); got != tt.reason {
				t.Fatalf("reason %q, want %q", got, tt.reason)
			}
		})
	}
}

func TestVerifyBoundaries(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	raw := mustSign(t, base(5), nil, s)
	pins := []keys.JWK{pin}
	// Exactly at the skew edge is accepted on both sides.
	if _, err := bundle.Verify(raw, pins, bundle.State{}, bundle.Options{Now: t0.Add(-5 * time.Minute), Skew: 5 * time.Minute}); err != nil {
		t.Fatalf("issuedAt == now+skew: %v", err)
	}
	if _, err := bundle.Verify(raw, pins, bundle.State{}, bundle.Options{Now: t0.Add(24*time.Hour + 5*time.Minute), Skew: 5 * time.Minute}); err != nil {
		t.Fatalf("now == expiresAt+skew: %v", err)
	}
	// An unsupported alg in a pin cannot be talked into verifying.
	weak := pin
	weak.Alg = "HS256"
	if _, err := bundle.Verify(raw, []keys.JWK{weak}, bundle.State{}, opts()); err == nil {
		t.Fatal("a pin with a foreign alg must not verify")
	}
	// A pin that is not a valid key is ignored, not fatal.
	if _, err := bundle.Verify(raw, []keys.JWK{{Kty: "RSA"}, pin}, bundle.State{}, opts()); err != nil {
		t.Fatal(err)
	}
	// The kid is the thumbprint, not the declared member.
	liar := pin
	liar.Kid = "something-else"
	if _, err := bundle.Verify(raw, []keys.JWK{liar}, bundle.State{}, opts()); err != nil {
		t.Fatalf("declared kid must not matter: %v", err)
	}
}

func TestVerifySequenceRules(t *testing.T) {
	s, pin := newKey(t, keys.AlgES256)
	pins := []keys.JWK{pin}
	cur, err := bundle.Verify(mustSign(t, base(7), nil, s), pins, bundle.State{}, opts())
	if err != nil {
		t.Fatal(err)
	}
	applied := bundle.State{Seq: 7, ContentSHA256: cur.ContentSHA256, IssuedAt: t0}

	if _, err := bundle.Verify(mustSign(t, base(6), nil, s), pins, applied, opts()); !errors.Is(err, bundle.ErrRollback) {
		t.Fatalf("seq 6: %v", err)
	}
	diff := base(7)
	diff.Policy = json.RawMessage(`{"allowlist":["other"]}`)
	if _, err := bundle.Verify(mustSign(t, diff, nil, s), pins, applied, opts()); !errors.Is(err, bundle.ErrEquivocation) {
		t.Fatalf("different content: %v", err)
	}
	newer := base(7)
	newer.IssuedAt = t0.Add(30 * time.Second)
	newer.ExpiresAt = newer.IssuedAt.Add(time.Hour)
	v, err := bundle.Verify(mustSign(t, newer, nil, s), pins, applied, opts())
	if err != nil || !v.Refresh {
		t.Fatalf("refresh: %+v %v", v, err)
	}
	if _, err := bundle.Verify(mustSign(t, base(7), nil, s), pins, applied, opts()); !errors.Is(err, bundle.ErrUnchanged) {
		t.Fatalf("identical: %v", err)
	}
	older := base(7)
	older.IssuedAt = t0.Add(-time.Second)
	if _, err := bundle.Verify(mustSign(t, older, nil, s), pins, applied, opts()); !errors.Is(err, bundle.ErrUnchanged) {
		t.Fatalf("older issuedAt: %v", err)
	}
	if v, err := bundle.Verify(mustSign(t, base(8), nil, s), pins, applied, opts()); err != nil || v.Refresh {
		t.Fatalf("seq 8: %+v %v", v, err)
	}
	if bundle.Reason(bundle.ErrUnchanged) != "" {
		t.Fatal("unchanged is not a rejection")
	}
}

func TestVerifyBadSignatureBeforeDecode(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	good := mustSign(t, base(1), nil, s)
	garbage := mutateEnv(t, good, func(e *bundle.Envelope) {
		e.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"typ": not json at all`))
	})
	_, err := bundle.Verify(garbage, []keys.JWK{pin}, bundle.State{}, opts())
	if !errors.Is(err, bundle.ErrBadSignature) || errors.Is(err, bundle.ErrMalformed) {
		t.Fatalf("got %v, want bad_signature: the payload must not be decoded first", err)
	}
}

func TestReasons(t *testing.T) {
	want := map[error]string{
		bundle.ErrMalformed:          "malformed",
		bundle.ErrTooLarge:           "too_large",
		bundle.ErrUnsupportedFormat:  "unsupported_format",
		bundle.ErrUnsigned:           "unsigned",
		bundle.ErrUnknownKid:         "unknown_kid",
		bundle.ErrBadSignature:       "bad_signature",
		bundle.ErrIssuerMismatch:     "issuer_mismatch",
		bundle.ErrCredentialMismatch: "credential_mismatch",
		bundle.ErrRollback:           "rollback",
		bundle.ErrEquivocation:       "equivocation",
		bundle.ErrExpired:            "expired",
		bundle.ErrFuture:             "future",
	}
	for err, reason := range want {
		if got := bundle.Reason(err); got != reason {
			t.Errorf("Reason(%v) = %q, want %q", err, got, reason)
		}
		if got := bundle.Reason(fmt.Errorf("wrapped: %w", err)); got != reason {
			t.Errorf("wrapped Reason = %q, want %q", got, reason)
		}
	}
	if bundle.Reason(nil) != "" || bundle.Reason(errors.New("x")) != "" {
		t.Fatal("non-rejections have no reason")
	}
}

func TestErrorTextCarriesOnlyFacts(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	b := base(9)
	b.Policy = json.RawMessage(`{"secret":"` + secretValue + `"}`)
	raw := mustSign(t, b, nil, s)
	_, err := bundle.Verify(raw, []keys.JWK{pin}, bundle.State{Seq: 10, ContentSHA256: "x"}, opts())
	if !errors.Is(err, bundle.ErrRollback) {
		t.Fatal(err)
	}
	msg := err.Error()
	if strings.Contains(msg, secretValue) || !strings.Contains(msg, "seq=9") || !strings.Contains(msg, "kid="+s.KID()) {
		t.Fatalf("unexpected error text %q", msg)
	}
	var env bundle.Envelope
	_ = json.Unmarshal(raw, &env)
	payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	sum := sha256.Sum256(payload)
	if !strings.Contains(msg, "digest="+hex.EncodeToString(sum[:8])) {
		t.Fatalf("missing 16-hex digest prefix in %q", msg)
	}
}

func TestSignRejects(t *testing.T) {
	s, _ := newKey(t, keys.AlgEdDSA)
	ctx := context.Background()
	bad := func(edit func(*bundle.Bundle)) bundle.Bundle {
		b := base(1)
		edit(&b)
		return b
	}
	cases := map[string]bundle.Bundle{
		"seq":           bad(func(b *bundle.Bundle) { b.Seq = 0 }),
		"cpID":          bad(func(b *bundle.Bundle) { b.CPID = "" }),
		"times":         bad(func(b *bundle.Bundle) { b.ExpiresAt = b.IssuedAt }),
		"zero issuedAt": bad(func(b *bundle.Bundle) { b.IssuedAt = time.Time{} }),
		"empty policy":  bad(func(b *bundle.Bundle) { b.Policy = nil }),
		"bad policy":    bad(func(b *bundle.Bundle) { b.Policy = json.RawMessage(`{`) }),
		"bad section":   bad(func(b *bundle.Bundle) { b.Sections = map[string]json.RawMessage{"x": json.RawMessage(`{`)} }),
		"oversize": bad(func(b *bundle.Bundle) {
			b.Policy = json.RawMessage(`"` + strings.Repeat("a", bundle.MaxEnvelopeBytes) + `"`)
		}),
	}
	for name, b := range cases {
		if _, err := bundle.Sign(ctx, b, nil, s); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := bundle.Sign(ctx, base(1), nil); err == nil {
		t.Error("zero signers must be rejected")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := bundle.Sign(cancelled, base(1), nil, s); err == nil {
		t.Error("a signer error must surface")
	}
	// Sections may be omitted entirely.
	nb := base(1)
	nb.Sections = nil
	if _, err := bundle.Sign(ctx, nb, nil, s); err != nil {
		t.Error(err)
	}
}

func TestCredentialsRedacted(t *testing.T) {
	c := bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secretValue}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "creds", c, "ptr", &c)
	outs := []string{
		c.String(), fmt.Sprint(c), fmt.Sprint(&c), fmt.Sprintf("%v %+v %#v %s", c, c, c, &c), buf.String(),
	}
	for _, o := range outs {
		if strings.Contains(o, secretValue) || strings.Contains(o, "AKIAEXAMPLE") || !strings.Contains(o, "[redacted]") {
			t.Fatalf("not redacted: %q", o)
		}
	}
}

func FuzzVerify(f *testing.F) {
	s, pin := newKey(f, keys.AlgEdDSA)
	good := mustSign(f, base(5), &bundle.Credentials{AccessKeyID: "a", SecretAccessKey: "b"}, s)
	f.Add(good)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"payload":"e30","signatures":[{"kid":"k","sig":"AA"}]}`))
	f.Add([]byte(``))
	pins := []keys.JWK{pin}
	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := bundle.Verify(raw, pins, bundle.State{Seq: 4}, opts())
		if err == nil && v.Seq < 4 {
			t.Fatalf("accepted seq %d below applied", v.Seq)
		}
		if err != nil && bundle.Reason(err) == "" && !errors.Is(err, bundle.ErrUnchanged) {
			t.Fatalf("unclassified error %v", err)
		}
	})
}

func BenchmarkVerify1MiB(b *testing.B) {
	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
		b.Run(alg, func(b *testing.B) {
			s, pin := newKey(b, alg)
			bb := base(5)
			bb.Policy = json.RawMessage(`{"blob":"` + strings.Repeat("a", 1<<20) + `"}`)
			raw := mustSign(b, bb, nil, s)
			pins := []keys.JWK{pin}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := bundle.Verify(raw, pins, bundle.State{}, opts()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestBundleFieldCoverage signs a bundle with every field set and checks the
// decoded result equals it, so a Bundle field without a setMember case fails.
func TestBundleFieldCoverage(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	in := base(5)
	in.Policy = json.RawMessage(`{"a":1}`)
	in.Sections = map[string]json.RawMessage{"tokenJWKS": json.RawMessage(`{"keys":[]}`), "other": json.RawMessage(`[1]`)}
	in.TokenIssuer = "https://warden.example.com"
	creds := &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secretValue}
	v, err := bundle.Verify(mustSign(t, in, creds, s), []keys.JWK{pin}, bundle.State{}, opts())
	if err != nil {
		t.Fatal(err)
	}
	want := in
	want.Typ = bundle.TypV1
	want.ContentSHA256 = v.Bundle.ContentSHA256
	want.CredentialsSHA256 = v.Bundle.CredentialsSHA256
	if !reflect.DeepEqual(v.Bundle, want) {
		t.Fatalf("decoded bundle differs:\n got %+v\nwant %+v", v.Bundle, want)
	}
	rv := reflect.ValueOf(v.Bundle)
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).IsZero() {
			t.Errorf("field %s is zero: set it in this test and in Bundle.setMember", rv.Type().Field(i).Name)
		}
	}
}

func TestVerifyAllowMissingCredentials(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	raw := mustSign(t, base(2), &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secretValue}, s)
	stripped := mutateEnv(t, raw, func(e *bundle.Envelope) { e.Credentials = nil })
	o := opts()
	o.AllowMissingCredentials = true
	v, err := bundle.Verify(stripped, []keys.JWK{pin}, bundle.State{}, o)
	if err != nil || v.Credentials != nil {
		t.Fatalf("missing sidecar: %+v %v", v, err)
	}
	wrong := mutateEnv(t, raw, func(e *bundle.Envelope) { e.Credentials.SecretAccessKey += "X" })
	if _, err := bundle.Verify(wrong, []keys.JWK{pin}, bundle.State{}, o); !errors.Is(err, bundle.ErrCredentialMismatch) {
		t.Fatalf("wrong sidecar: %v", err)
	}
	if _, err := bundle.Verify(stripped, []keys.JWK{pin}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrCredentialMismatch) {
		t.Fatalf("default must still require the sidecar: %v", err)
	}
	if v, err := bundle.Verify(raw, []keys.JWK{pin}, bundle.State{}, o); err != nil || v.Credentials == nil {
		t.Fatalf("present matching sidecar: %+v %v", v, err)
	}
}

func TestVerifyTriesEachKidOnce(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	raw := mustSign(t, base(1), nil, s)
	dup := mutateEnv(t, raw, func(e *bundle.Envelope) {
		bad := e.Signatures[0]
		bad.Sig = flipB64(t, bad.Sig, 0)
		e.Signatures = []bundle.Signature{bad, bad, bad, e.Signatures[0]}
	})
	// The first attempt for the kid fails and repeats are skipped, so the
	// good signature listed last is never consulted.
	if _, err := bundle.Verify(dup, []keys.JWK{pin}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestSignRejectsInvalidUTF8(t *testing.T) {
	s, _ := newKey(t, keys.AlgEdDSA)
	b := base(1)
	b.CPID = "cp-\xff"
	if _, err := bundle.Sign(context.Background(), b, nil, s); err == nil {
		t.Error("cpID with invalid UTF-8 must be rejected")
	}
	b = base(1)
	b.Sections = map[string]json.RawMessage{"bad\xff": json.RawMessage(`1`)}
	if _, err := bundle.Sign(context.Background(), b, nil, s); err == nil {
		t.Error("section name with invalid UTF-8 must be rejected")
	}
}

// TestBundleTokenIssuerSigned: the token issuer rides in the signed payload and
// the content hash. Editing it without re-signing is a bad signature; editing it
// and re-signing with the right key still fails, because contentSha256 no
// longer matches. Two bundles that differ only in issuer have different hashes.
func TestBundleTokenIssuerSigned(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	in := base(5)
	in.TokenIssuer = "https://warden.example.com"
	raw := mustSign(t, in, nil, s)
	v, err := bundle.Verify(raw, []keys.JWK{pin}, bundle.State{}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if v.Bundle.TokenIssuer != in.TokenIssuer {
		t.Fatalf("tokenIssuer %q, want %q", v.Bundle.TokenIssuer, in.TokenIssuer)
	}

	swap := func(p []byte) []byte {
		out := bytes.Replace(p, []byte("warden.example.com"), []byte("evil.example.com"), 1)
		if bytes.Equal(out, p) {
			t.Fatal("issuer not found in the payload")
		}
		return out
	}
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	tampered := mutateEnv(t, raw, func(e *bundle.Envelope) { e.Payload = base64.RawURLEncoding.EncodeToString(swap(payload)) })
	if _, err := bundle.Verify(tampered, []keys.JWK{pin}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("unsigned edit: got %v, want bad signature", err)
	}
	if _, err := bundle.Verify(resign(t, raw, s, swap), []keys.JWK{pin}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrMalformed) {
		t.Fatalf("re-signed edit: got %v, want malformed (content hash)", err)
	}

	other := in
	other.TokenIssuer = "https://other.example.com"
	ov, err := bundle.Verify(mustSign(t, other, nil, s), []keys.JWK{pin}, bundle.State{}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if ov.ContentSHA256 == v.ContentSHA256 {
		t.Error("the token issuer must change contentSha256")
	}

	// Without an issuer the member is omitted and the bundle verifies.
	none := base(5)
	nv, err := bundle.Verify(mustSign(t, none, nil, s), []keys.JWK{pin}, bundle.State{}, opts())
	if err != nil || nv.Bundle.TokenIssuer != "" {
		t.Fatalf("bundle without issuer: %+v %v", nv.Bundle.TokenIssuer, err)
	}
	var env2 bundle.Envelope
	_ = json.Unmarshal(mustSign(t, none, nil, s), &env2)
	p2, _ := base64.RawURLEncoding.DecodeString(env2.Payload)
	if bytes.Contains(p2, []byte("tokenIssuer")) {
		t.Error("an empty tokenIssuer must be omitted from the payload")
	}
}

func TestSignRejectsInvalidUTF8TokenIssuer(t *testing.T) {
	s, _ := newKey(t, keys.AlgEdDSA)
	b := base(1)
	b.TokenIssuer = "https://x\xff"
	if _, err := bundle.Sign(context.Background(), b, nil, s); err == nil {
		t.Error("tokenIssuer with invalid UTF-8 must be rejected")
	}
}

// TestVerifyEnvelopeMemberNamesAreExact refuses, as malformed, an envelope
// member that only case-folds to payload, signatures or credentials, and a
// repeated one of those. encoding/json would accept both (case-insensitive
// match, last duplicate wins), and a reader that parsed the envelope another
// way would then see a different sidecar than Verify did.
func TestVerifyEnvelopeMemberNamesAreExact(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	pins := []keys.JWK{pin}
	creds := &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secretValue}
	good := string(mustSign(t, base(5), creds, s))
	if _, err := bundle.Verify([]byte(good), pins, bundle.State{}, opts()); err != nil {
		t.Fatalf("the unedited envelope: %v", err)
	}
	var env struct {
		Payload     json.RawMessage `json:"payload"`
		Signatures  json.RawMessage `json:"signatures"`
		Credentials json.RawMessage `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(good), &env); err != nil {
		t.Fatal(err)
	}
	members := map[string]json.RawMessage{"payload": env.Payload, "signatures": env.Signatures, "credentials": env.Credentials}
	// build writes the members in order, each as name:value.
	build := func(kv ...string) []byte {
		parts := make([]string, 0, len(kv)/2)
		for i := 0; i < len(kv); i += 2 {
			parts = append(parts, fmt.Sprintf("%q:%s", kv[i], kv[i+1]))
		}
		return []byte("{" + strings.Join(parts, ",") + "}")
	}
	for _, name := range []string{"payload", "signatures", "credentials"} {
		val := string(members[name])
		others := func(renamed string) []string {
			var kv []string
			for _, n := range []string{"payload", "signatures", "credentials"} {
				if n == name {
					kv = append(kv, renamed, val)
				} else {
					kv = append(kv, n, string(members[n]))
				}
			}
			return kv
		}
		variants := []string{
			strings.ToUpper(name[:1]) + name[1:],
			strings.ToUpper(name),
			name[:len(name)-1] + strings.ToUpper(name[len(name)-1:]),
		}
		if strings.Contains(name, "s") {
			variants = append(variants, strings.Replace(name, "s", "\u017f", 1)) // U+017F (long s) folds to s
		}
		for _, v := range variants {
			t.Run(name+"/variant "+v, func(t *testing.T) {
				// Renamed in place, and next to the exact name.
				for _, raw := range [][]byte{build(others(v)...), build(append(others(name), v, val)...)} {
					if _, err := bundle.Verify(raw, pins, bundle.State{}, opts()); !errors.Is(err, bundle.ErrMalformed) {
						t.Fatalf("%s: got %v, want ErrMalformed", raw[:min(len(raw), 80)], err)
					}
				}
			})
		}
		t.Run(name+"/duplicate", func(t *testing.T) {
			// An escaped spelling of the same name is still a duplicate.
			escaped := fmt.Sprintf(`\u%04x`, name[0]) + name[1:]
			plain := build(others(name)...)
			for _, raw := range [][]byte{
				build(append([]string{name, val}, others(name)...)...),
				build(append(others(name), name, val)...),
				[]byte(string(plain[:len(plain)-1]) + `,"` + escaped + `":` + val + "}"),
			} {
				if _, err := bundle.Verify(raw, pins, bundle.State{}, opts()); !errors.Is(err, bundle.ErrMalformed) {
					t.Fatalf("%.80s: got %v, want ErrMalformed", raw, err)
				}
			}
		})
	}

	// Still accepted: an escape that decodes to the exact name, and unknown
	// members (repeated or not), which later envelope fields may use.
	for _, raw := range []string{
		strings.Replace(good, `"credentials"`, `"cred\u0065ntials"`, 1),
		strings.Replace(good, `{"payload"`, `{"extra":1,"extra":[2],"Extra":{},"payload"`, 1),
		strings.Replace(good, `{"payload"`, `{"pay": "x", "payloads": "y", "payload"`, 1),
	} {
		v, err := bundle.Verify([]byte(raw), pins, bundle.State{}, opts())
		if err != nil || v.Credentials == nil {
			t.Fatalf("%.60s: got %+v %v, want accepted with the sidecar", raw, v.Credentials, err)
		}
	}
}

// TestVerifiedWithoutCredentials is what the worker caches: only the verified
// payload and signatures, under the exact names, re-verifiable with
// AllowMissingCredentials and never carrying a sidecar or an extra member.
func TestVerifiedWithoutCredentials(t *testing.T) {
	s1, pin1 := newKey(t, keys.AlgEdDSA)
	s2, pin2 := newKey(t, keys.AlgES256)
	creds := &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secretValue}
	good := string(mustSign(t, base(5), creds, s1, s2))
	for _, raw := range []string{
		good,
		strings.Replace(good, `{"payload"`, `{"extra":{"secretAccessKey":"`+secretValue+`"},"payload"`, 1),
		strings.Replace(good, `"credentials"`, `"cred\u0065ntials"`, 1),
	} {
		v, err := bundle.Verify([]byte(raw), []keys.JWK{pin1}, bundle.State{}, opts())
		if err != nil {
			t.Fatal(err)
		}
		out, err := v.WithoutCredentials()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), secretValue) || strings.Contains(string(out), "AKIAEXAMPLE") {
			t.Fatalf("the stripped envelope carries the credential: %s", out)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(out, &m); err != nil || len(m) != 2 || m["payload"] == nil || m["signatures"] == nil {
			t.Fatalf("members = %v %v, want exactly payload and signatures", m, err)
		}
		o := opts()
		o.AllowMissingCredentials = true
		// Both signatures are kept, so a pin rotated to the second key still verifies.
		for _, pins := range [][]keys.JWK{{pin1}, {pin2}} {
			w, err := bundle.Verify(out, pins, bundle.State{}, o)
			if err != nil || w.Credentials != nil || w.ContentSHA256 != v.ContentSHA256 {
				t.Fatalf("re-verify: %+v %v", w.Credentials, err)
			}
		}
		if _, err := bundle.Verify(out, []keys.JWK{pin1}, bundle.State{}, opts()); !errors.Is(err, bundle.ErrCredentialMismatch) {
			t.Fatalf("without AllowMissingCredentials: %v", err)
		}
	}
	if _, err := (bundle.Verified{}).WithoutCredentials(); err == nil {
		t.Fatal("a zero Verified must not produce an envelope")
	}
}
