package oidc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

type tokenHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Crit json.RawMessage `json:"crit"`
}

// parsedToken is the unverified payload, mapped. Nothing in it is trusted
// until the signature has been checked.
type parsedToken struct {
	claims identity.Claims
	aud    []string
	nbf    *time.Time
}

var errMalformed = errors.New("oidc: malformed token")

// parseToken decodes header and payload of a compact JWS. Errors are fixed
// and never carry token text.
func parseToken(raw, groupsClaim string, maxGroups int) (tokenHeader, parsedToken, error) {
	var h tokenHeader
	var p parsedToken
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return h, p, errMalformed
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return h, p, errMalformed
	}
	if err := json.Unmarshal(hb, &h); err != nil || h.Crit != nil {
		return h, p, errMalformed
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return h, p, errMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return h, p, errMalformed
	}
	p, err = mapClaims(m, groupsClaim, maxGroups)
	return h, p, err
}

// mapClaims is the one place token claims become identity.Claims.
func mapClaims(m map[string]any, groupsClaim string, maxGroups int) (parsedToken, error) {
	var p parsedToken
	c := &p.claims
	var ok bool
	if c.Sub, ok = m["sub"].(string); !ok || c.Sub == "" {
		return p, errMalformed
	}
	if c.Issuer, ok = m["iss"].(string); !ok {
		return p, errMalformed
	}
	var err error
	if c.Expiry, err = unixClaim(m, "exp", true); err != nil {
		return p, err
	}
	if c.IssuedAt, err = unixClaim(m, "iat", true); err != nil {
		return p, err
	}
	nbf, err := unixClaim(m, "nbf", false)
	if err != nil {
		return p, err
	}
	if !nbf.IsZero() {
		p.nbf = &nbf
	}
	switch a := m["aud"].(type) {
	case string:
		p.aud = []string{a}
	case []any:
		for _, e := range a {
			s, ok := e.(string)
			if !ok {
				return p, errMalformed
			}
			p.aud = append(p.aud, s)
		}
	case nil:
	default:
		return p, errMalformed
	}
	for k, dst := range map[string]*string{"azp": &c.AZP, "sid": &c.SID, "nonce": &c.Nonce} {
		if v, present := m[k]; present {
			s, ok := v.(string)
			if !ok {
				return p, errMalformed
			}
			*dst = s
		}
	}
	if e, ok := m["email"].(string); ok {
		c.Email = strings.ToLower(strings.TrimSpace(e))
	}
	switch ev := m["email_verified"].(type) {
	case bool:
		c.EmailVerified = ev
		if !ev {
			c.Email = ""
		}
	case string:
		if strings.EqualFold(ev, "false") {
			c.Email = ""
		}
	}
	var groups []string
	switch g := m[groupsClaim].(type) {
	case string:
		groups = []string{g}
	case []any:
		for _, e := range g {
			if s, ok := e.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	c.Groups, c.GroupsTruncated = identity.NormalizeGroupsMax(groups, maxGroups)
	return p, nil
}

func unixClaim(m map[string]any, name string, required bool) (time.Time, error) {
	v, present := m[name]
	if !present {
		if required {
			return time.Time{}, errMalformed
		}
		return time.Time{}, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, errMalformed
	}
	i, err := n.Int64()
	if err != nil {
		return time.Time{}, errMalformed
	}
	return time.Unix(i, 0), nil
}
