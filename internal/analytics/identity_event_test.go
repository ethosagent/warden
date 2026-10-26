package analytics

import (
	"encoding/json"
	"strings"
	"testing"
)

// An attributed Event carries the snake_case identity keys; an empty identity
// adds none of them.
func TestEventIdentityJSONKeys(t *testing.T) {
	e := goldenEvent()
	e.UserSub, e.UserEmail, e.UserSID = "sub-1", "a@corp.example", "sid-1"
	e.UserGroups = []string{"cn=eng,ou=groups,dc=corp"}
	e.UserGroupsTruncated = true
	e.IdentityStatus, e.IdentityReason = "valid", "ok"
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"user_sub":"sub-1"`, `"user_email":"a@corp.example"`,
		`"user_groups":["cn=eng,ou=groups,dc=corp"]`, `"user_groups_truncated":true`,
		`"user_sid":"sid-1"`, `"identity_status":"valid"`, `"identity_reason":"ok"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing %s in %s", k, b)
		}
	}
	var back Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.UserSub != "sub-1" || back.UserGroups[0] != "cn=eng,ou=groups,dc=corp" || !back.UserGroupsTruncated {
		t.Fatalf("round trip lost identity: %+v", back)
	}
}

func TestEncodeDecodeGroups(t *testing.T) {
	if EncodeGroups(nil) != "" || DecodeGroups("") != nil {
		t.Fatal("empty groups must encode to \"\" and decode to nil")
	}
	in := []string{"cn=eng,ou=groups,dc=corp", "plain"}
	enc := EncodeGroups(in)
	if enc != `["cn=eng,ou=groups,dc=corp","plain"]` {
		t.Fatalf("encoded = %s", enc)
	}
	out := DecodeGroups(enc)
	if len(out) != 2 || out[0] != in[0] || out[1] != in[1] {
		t.Fatalf("decoded = %v", out)
	}
	if DecodeGroups("not json") != nil {
		t.Fatal("garbage must decode to nil, never panic")
	}
}
