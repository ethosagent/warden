package oidc

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/identitytest"
)

func TestVerifierSuite(t *testing.T) {
	identitytest.RunVerifierSuite(t, func(t *testing.T) identitytest.Fixture {
		rs, ec := newRSASigner(t, "rs"), newECSigner(t, "ec")
		srv := newJWKSServer(t, "", rs, ec)
		v := newTestVerifier(t, srv, &clock{t: testNow}, func(c *Config) { c.AllowedAZP = []string{"suite-client"} })
		return identitytest.Fixture{Verifier: v, Prepare: func(c identitytest.Case) string {
			cl := baseClaims(srv.URL, testNow)
			cl["sub"], cl["email"], cl["azp"] = identitytest.SuiteSub, identitytest.SuiteEmail, "suite-client"
			signer := rs
			switch c {
			case identitytest.CaseExpired:
				cl["iat"], cl["exp"] = testNow.Add(-time.Hour).Unix(), testNow.Add(-10*time.Minute).Unix()
			case identitytest.CaseWrongAud:
				cl["aud"] = "other"
			case identitytest.CaseWrongAZP:
				cl["azp"] = "other-client"
			case identitytest.CaseUnknownKID:
				signer = newECSigner(t, "not-published")
			case identitytest.CaseTruncatedGroups:
				g := make([]string, 100)
				for i := range g {
					g[i] = fmt.Sprintf("g%03d", i)
				}
				cl["groups"] = g
				signer = ec
			case identitytest.CaseIssuerDown:
				tok := signer.sign(cl)
				srv.Close()
				return tok
			}
			return signer.sign(cl)
		}}
	})
}

var _ identity.Verifier = (*verifier)(nil)
