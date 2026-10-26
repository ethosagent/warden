package fakes

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/identitytest"
)

type verifierResult struct {
	c identity.Claims
	s identity.Status
	r identity.Reason
}

// Verifier is an in-memory identity.Verifier: a map from raw token to a
// canned outcome. A token nobody registered is malformed. Safe for concurrent
// use; Calls counts every Verify.
type Verifier struct {
	mu    sync.Mutex
	m     map[string]verifierResult
	calls atomic.Int64
}

var _ identity.Verifier = (*Verifier)(nil)

// NewVerifier returns an empty fake.
func NewVerifier() *Verifier { return &Verifier{m: map[string]verifierResult{}} }

// Set registers the outcome returned for token.
func (v *Verifier) Set(token string, c identity.Claims, s identity.Status, r identity.Reason) {
	v.mu.Lock()
	v.m[token] = verifierResult{c, s, r}
	v.mu.Unlock()
}

// Verify returns the registered outcome for raw.
func (v *Verifier) Verify(_ context.Context, raw string, _ ...identity.VerifyOption) (identity.Claims, identity.Status, identity.Reason) {
	v.calls.Add(1)
	v.mu.Lock()
	x, ok := v.m[raw]
	v.mu.Unlock()
	if !ok {
		return identity.Claims{}, identity.StatusInvalid, identity.ReasonMalformed
	}
	return x.c, x.s, x.r
}

// Calls reports how many times Verify ran.
func (v *Verifier) Calls() int { return int(v.calls.Load()) }

// VerifierSuiteFixture adapts f to the conformance suite: Prepare registers a
// token carrying the outcome each Case demands.
func VerifierSuiteFixture(f *Verifier) identitytest.Fixture {
	return identitytest.Fixture{Verifier: f, Prepare: func(c identitytest.Case) string {
		base := identity.Claims{Sub: identitytest.SuiteSub, Email: identitytest.SuiteEmail, EmailVerified: true}
		tok := "fake-token-" + string(c)
		st, r := identity.StatusInvalid, identity.Reason("")
		switch c {
		case identitytest.CaseValid:
			st = identity.StatusValid
		case identitytest.CaseTruncatedGroups:
			st = identity.StatusValid
			for i := 0; i < identity.MaxGroups; i++ {
				base.Groups = append(base.Groups, fmt.Sprintf("g%03d", i))
			}
			base.GroupsTruncated = true
		case identitytest.CaseExpired:
			st = identity.StatusExpired
		case identitytest.CaseWrongAud:
			r = identity.ReasonWrongAud
		case identitytest.CaseWrongAZP:
			r = identity.ReasonWrongAZP
		case identitytest.CaseUnknownKID:
			r = identity.ReasonUnknownKID
		case identitytest.CaseIssuerDown:
			base, st, r = identity.Claims{}, identity.StatusUnverified, identity.ReasonJWKSUnavailable
		}
		f.Set(tok, base, st, r)
		return tok
	}}
}
