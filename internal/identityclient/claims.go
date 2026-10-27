package identityclient

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// claims are the ID token claims the client reads. The signature is NOT
// verified here (the worker verifies); the values only schedule refreshes and
// describe the login to the user.
type claims struct {
	Issuer           string
	Subject          string
	Email            string
	Groups           []string
	Aud              []string
	IssuedAt, Expiry time.Time
}

func parseClaims(jwt string) (claims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return claims{}, errors.New("identityclient: ID token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, errors.New("identityclient: ID token payload is not base64url")
	}
	var m struct {
		Iss    string          `json:"iss"`
		Sub    string          `json:"sub"`
		Email  string          `json:"email"`
		Groups []string        `json:"groups"`
		Aud    json.RawMessage `json:"aud"`
		Iat    json.Number     `json:"iat"`
		Exp    json.Number     `json:"exp"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return claims{}, errors.New("identityclient: ID token payload is not valid JSON claims")
	}
	c := claims{Issuer: m.Iss, Subject: m.Sub, Email: m.Email, Groups: m.Groups}
	var one string
	var many []string
	if json.Unmarshal(m.Aud, &one) == nil && one != "" {
		c.Aud = []string{one}
	} else if json.Unmarshal(m.Aud, &many) == nil {
		c.Aud = many
	}
	exp, err1 := m.Exp.Int64()
	iat, err2 := m.Iat.Int64()
	if err1 != nil || err2 != nil || exp <= 0 || iat <= 0 || exp <= iat {
		return claims{}, errors.New("identityclient: ID token has no usable iat and exp")
	}
	c.IssuedAt, c.Expiry = time.Unix(iat, 0), time.Unix(exp, 0)
	return c, nil
}

// Fingerprint is the first 8 hex characters of sha256(token): the only
// derivative of a token that may be logged.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:8]
}
