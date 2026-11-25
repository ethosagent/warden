package identityclient

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// WardenInfo describes an issued Warden token for `status`. It carries no
// token. The signature is not verified here (the worker verifies).
type WardenInfo struct {
	Subject  string
	ActorSub string
	JKT      string
	Scope    string
	Expiry   time.Time
}

// ParseWardenToken reads the claims `warden identity status --agent-id` shows.
func ParseWardenToken(token string) (WardenInfo, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return WardenInfo{}, errors.New("identityclient: the Warden token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return WardenInfo{}, errors.New("identityclient: the Warden token payload is not base64url")
	}
	var c struct {
		Sub   string `json:"sub"`
		Scope string `json:"scope"`
		Exp   int64  `json:"exp"`
		Act   struct {
			Sub string `json:"sub"`
		} `json:"act"`
		Cnf struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Exp <= 0 {
		return WardenInfo{}, errors.New("identityclient: the Warden token payload is not valid claims")
	}
	return WardenInfo{Subject: c.Sub, ActorSub: c.Act.Sub, JKT: c.Cnf.JKT, Scope: c.Scope, Expiry: time.Unix(c.Exp, 0)}, nil
}
