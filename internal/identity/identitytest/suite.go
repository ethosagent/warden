// Package identitytest holds the one conformance suite for identity.Verifier.
// The real OIDC verifier and fakes.Verifier both run it. It imports only
// internal/identity and the standard library, so test/fakes and test/harness
// can import it without a cycle.
package identitytest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

// Case names one world the verifier must handle.
type Case string

const (
	CaseValid           Case = "valid"
	CaseExpired         Case = "expired"
	CaseWrongAud        Case = "wrong_aud"
	CaseWrongAZP        Case = "wrong_azp"
	CaseUnknownKID      Case = "unknown_kid"
	CaseTruncatedGroups Case = "truncated_groups"
	CaseIssuerDown      Case = "issuer_down"
)

// Cases lists every case the suite runs.
func Cases() []Case {
	return []Case{CaseValid, CaseExpired, CaseWrongAud, CaseWrongAZP, CaseUnknownKID, CaseTruncatedGroups, CaseIssuerDown}
}

// Sub and email every fixture must put in its tokens.
const (
	SuiteSub   = "suite-user"
	SuiteEmail = "suite.user@example.com"
)

// Fixture is a verifier plus the means to arrange the world for a Case.
// Prepare returns the raw token to present.
type Fixture struct {
	Verifier identity.Verifier
	Prepare  func(c Case) string
}

// Factory builds a fresh Fixture (cold cache) for one subtest.
type Factory func(t *testing.T) Fixture

// RunVerifierSuite runs every Case against a fresh fixture from factory.
func RunVerifierSuite(t *testing.T, factory Factory) {
	t.Helper()
	for _, c := range Cases() {
		t.Run(string(c), func(t *testing.T) {
			fx := factory(t)
			raw := fx.Prepare(c)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			claims, st, r := fx.Verifier.Verify(ctx, raw)
			check(t, c, claims, st, r)
			if out := fmt.Sprintf("%+v|%s|%s", claims, st, r); raw != "" && strings.Contains(out, raw) {
				t.Error("raw token appears in verifier output")
			}
		})
	}
}

func check(t *testing.T, c Case, claims identity.Claims, st identity.Status, r identity.Reason) {
	t.Helper()
	wantSt, wantR := identity.StatusInvalid, identity.Reason("")
	carries := true
	switch c {
	case CaseValid, CaseTruncatedGroups:
		wantSt = identity.StatusValid
	case CaseExpired:
		wantSt = identity.StatusExpired
	case CaseWrongAud:
		wantR = identity.ReasonWrongAud
	case CaseWrongAZP:
		wantR = identity.ReasonWrongAZP
	case CaseUnknownKID:
		wantR = identity.ReasonUnknownKID
	case CaseIssuerDown:
		wantSt, wantR, carries = identity.StatusUnverified, identity.ReasonJWKSUnavailable, false
	}
	if st != wantSt || r != wantR {
		t.Fatalf("status/reason = %s/%q, want %s/%q", st, r, wantSt, wantR)
	}
	sub := identity.SubjectFrom(claims, st)
	if carries {
		if claims.Sub != SuiteSub || claims.Email != SuiteEmail {
			t.Errorf("claims sub/email = %q/%q", claims.Sub, claims.Email)
		}
	} else if claims.Sub != "" || claims.Email != "" {
		t.Errorf("claims not empty: %+v", claims)
	}
	if wantSt != identity.StatusValid {
		if sub != nil {
			t.Error("non-valid status yielded a subject")
		}
		return
	}
	if sub == nil {
		t.Fatal("valid status yielded no subject")
	}
	if c == CaseTruncatedGroups {
		if len(claims.Groups) != identity.MaxGroups || !claims.GroupsTruncated || !sub.GroupsTruncated {
			t.Errorf("groups=%d truncated=%v subject=%v", len(claims.Groups), claims.GroupsTruncated, sub.GroupsTruncated)
		}
	}
}
