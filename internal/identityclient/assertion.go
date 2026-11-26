package identityclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/keys"
)

// AssertionLifetime is exp - iat of a client assertion. It is far below the
// 5 minutes the token endpoint accepts, and a new assertion with a fresh jti is
// built for every exchange (a jti is single use).
const AssertionLifetime = 60 * time.Second

// assertionClaims are the RFC 7523 claims of a private_key_jwt client
// assertion: the agent is both issuer and subject, the audience is the token
// endpoint.
type assertionClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	JTI string `json:"jti"`
}

// SignClientAssertion builds a compact EdDSA JWT for the token endpoint: header
// alg EdDSA, the key's kid and typ JWT; claims iss=sub=agentID, aud=audience
// exactly, iat=now, exp=iat+60s and a 128-bit crypto/rand base64url jti.
func SignClientAssertion(ctx context.Context, key AgentKey, agentID, audience string, now time.Time) (string, error) {
	if err := agentid.ValidID(agentID); err != nil {
		return "", err
	}
	if audience == "" {
		return "", errors.New("identityclient: no token endpoint audience for the assertion")
	}
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", fmt.Errorf("identityclient: assertion jti: %w", err)
	}
	iat := now.Unix()
	return keys.SignCompact(ctx, key, keys.Header{Alg: keys.AlgEdDSA, Kid: key.KID(), Typ: "JWT"}, assertionClaims{
		Iss: agentID, Sub: agentID, Aud: audience,
		Iat: iat, Exp: iat + int64(AssertionLifetime/time.Second),
		JTI: base64.RawURLEncoding.EncodeToString(jti[:]),
	})
}
