package identitytest_test

import (
	"context"
	"testing"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/identitytest"
)

type stub map[string]result

type result struct {
	c identity.Claims
	s identity.Status
	r identity.Reason
}

func (m stub) Verify(_ context.Context, raw string, _ ...identity.VerifyOption) (identity.Claims, identity.Status, identity.Reason) {
	x := m[raw]
	return x.c, x.s, x.r
}

func TestSuiteOnStub(t *testing.T) {
	identitytest.RunVerifierSuite(t, func(*testing.T) identitytest.Fixture {
		m := stub{}
		return identitytest.Fixture{Verifier: m, Prepare: func(c identitytest.Case) string {
			base := identity.Claims{Sub: identitytest.SuiteSub, Email: identitytest.SuiteEmail, EmailVerified: true}
			tok := "stub-" + string(c)
			switch c {
			case identitytest.CaseValid:
				m[tok] = result{base, identity.StatusValid, ""}
			case identitytest.CaseTruncatedGroups:
				base.Groups = make([]string, identity.MaxGroups)
				base.GroupsTruncated = true
				m[tok] = result{base, identity.StatusValid, ""}
			case identitytest.CaseExpired:
				m[tok] = result{base, identity.StatusExpired, ""}
			case identitytest.CaseWrongAud:
				m[tok] = result{base, identity.StatusInvalid, identity.ReasonWrongAud}
			case identitytest.CaseWrongAZP:
				m[tok] = result{base, identity.StatusInvalid, identity.ReasonWrongAZP}
			case identitytest.CaseUnknownKID:
				m[tok] = result{base, identity.StatusInvalid, identity.ReasonUnknownKID}
			case identitytest.CaseIssuerDown:
				m[tok] = result{identity.Claims{}, identity.StatusUnverified, identity.ReasonJWKSUnavailable}
			}
			return tok
		}}
	})
}
