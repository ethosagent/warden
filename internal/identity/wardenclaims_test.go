package identity

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestWardenClaimsJSON(t *testing.T) {
	full := WardenClaims{
		Ver: WardenTokenVer, Iss: "https://cp.example", Aud: WardenAudience, Sub: "u", IdPIss: "https://idp",
		Email: "a@b.co", EmailVerified: true, Groups: []string{"g"}, GroupsTruncated: true,
		Act: WardenActor{Sub: "agent-1"}, SID: "wts_x", IdPSID: "s", JTI: "j", Iat: 1, Nbf: 1, Exp: 2,
		Scope: "read", Cnf: WardenConfirmation{JKT: "t"},
	}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var back WardenClaims
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, full) {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"ver", "iss", "aud", "sub", "idp_iss", "email", "email_verified", "groups", "groups_truncated",
		"act", "sid", "idp_sid", "jti", "iat", "nbf", "exp", "scope", "cnf"} {
		if _, ok := m[k]; !ok {
			t.Errorf("claim %q missing from %s", k, b)
		}
	}

	min, _ := json.Marshal(WardenClaims{Ver: 1})
	for _, k := range []string{"email", "email_verified", "groups", "groups_truncated", "idp_sid", "scope"} {
		if strings.Contains(string(min), `"`+k+`"`) {
			t.Errorf("optional claim %q present when empty: %s", k, min)
		}
	}
	if WardenTokenTyp != "wt+jwt" || WardenAudience != "warden-worker" || WardenTokenVer != 1 {
		t.Error("contract constants changed")
	}
}
