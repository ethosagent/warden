package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func remoteProviderFor(t *testing.T, body *string) *RemoteProvider {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(*body))
	}))
	t.Cleanup(srv.Close)
	rp, err := NewRemoteProvider(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewRemoteProvider: %v", err)
	}
	rp.client = srv.Client()
	return rp
}

func TestRemoteProvider_DecodesBlockedUsers(t *testing.T) {
	body := `{"allowlist":[{"domain":"a.example.com"}],"blockedUsers":[{"sub":"u1"},{"email":"Alice@Corp.com "}]}`
	rp := remoteProviderFor(t, &body)
	if err := rp.Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	pol, err := rp.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	want := []BlockedUser{{Email: "alice@corp.com"}, {Sub: "u1"}}
	if !reflect.DeepEqual(pol.BlockedUsers, want) {
		t.Errorf("BlockedUsers = %+v, want %+v", pol.BlockedUsers, want)
	}
}

func TestBlockedUsersNormalize(t *testing.T) {
	in := []BlockedUser{
		{Sub: " b ", Email: "X@Y.com"},
		{Sub: "a"},
		{Sub: "b", Email: "x@y.com "},
		{Email: "Z@y.com"},
	}
	got := normalizeBlockedUsers(in)
	want := []BlockedUser{{Email: "z@y.com"}, {Sub: "a"}, {Sub: "b", Email: "x@y.com"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalize = %+v, want %+v", got, want)
	}
	if normalizeBlockedUsers(nil) != nil || normalizeBlockedUsers([]BlockedUser{}) != nil {
		t.Error("empty list must normalize to nil")
	}
}

func TestBlockedUsersValidation(t *testing.T) {
	cases := []struct {
		name string
		list []BlockedUser
		want string
	}{
		{"neither field", []BlockedUser{{Sub: "ok"}, {}}, "blockedUsers[1]"},
		{"blank after trim", []BlockedUser{{Sub: "  "}}, "blockedUsers[0]"},
		{"long sub", []BlockedUser{{Sub: strings.Repeat("s", 256)}}, "blockedUsers[0]: sub"},
		{"long email", []BlockedUser{{Email: strings.Repeat("e", 250) + "@x.co"}}, "blockedUsers[0]: email"},
		{"email without at", []BlockedUser{{Email: "nobody"}}, "blockedUsers[0]: email"},
		{"control char sub", []BlockedUser{{Sub: "a\x00b"}}, "control character"},
		{"control char email", []BlockedUser{{Email: "a\n@b.co"}}, "control character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBlockedUsers(tc.list)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
	if err := ValidateBlockedUsers(nil); err != nil {
		t.Errorf("nil list: %v", err)
	}

	// YAML path: error names the (normalized) index and the parse fails.
	y := "policy:\n  allowlist:\n    - domain: a.example.com\n  blockedUsers:\n    - sub: ok\n    - email: nobody\n"
	if _, err := parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "blockedUsers[0]") {
		t.Errorf("yaml err = %v, want blockedUsers[0]", err)
	}

	// Remote path: a bad list is refused and the last-known-good policy stays.
	body := `{"allowlist":[{"domain":"a.example.com"}],"blockedUsers":[{"sub":"keep"}]}`
	rp := remoteProviderFor(t, &body)
	if err := rp.Pull(); err != nil {
		t.Fatalf("good pull: %v", err)
	}
	body = `{"allowlist":[{"domain":"b.example.com"}],"blockedUsers":[{"sub":"u1"},{}]}`
	if err := rp.Pull(); err == nil || !strings.Contains(err.Error(), "blockedUsers[0]") {
		t.Fatalf("bad pull err = %v, want blockedUsers[0]", err)
	}
	pol, err := rp.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if pol.Allowlist[0].Domain != "a.example.com" || len(pol.BlockedUsers) != 1 || pol.BlockedUsers[0].Sub != "keep" {
		t.Errorf("last-known-good lost: %+v / %+v", pol.Allowlist, pol.BlockedUsers)
	}
}

func TestBlockedUsersCountLimit(t *testing.T) {
	mk := func(n int) []BlockedUser {
		l := make([]BlockedUser, n)
		for i := range l {
			l[i] = BlockedUser{Sub: fmt.Sprintf("sub-%016d", i)}
		}
		return l
	}
	if err := ValidateBlockedUsers(mk(MaxBlockedUsers)); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	err := ValidateBlockedUsers(mk(MaxBlockedUsers + 1))
	if err == nil || !strings.Contains(err.Error(), "blockedUsers") || strings.Contains(err.Error(), "sub-0000") {
		t.Fatalf("over limit err = %v", err)
	}
	// Remote path rejects it too.
	b, _ := json.Marshal(map[string]any{
		"allowlist":    []map[string]string{{"domain": "a.example.com"}},
		"blockedUsers": mk(MaxBlockedUsers + 1),
	})
	if _, _, err := parseRemotePolicy(b); err == nil {
		t.Error("remote over-limit list accepted")
	}
}

func TestBlockedUsersSizeLimit(t *testing.T) {
	// 5000 short entries: valid and well under the byte cap.
	short := make([]BlockedUser, MaxBlockedUsers)
	for i := range short {
		short[i] = BlockedUser{Sub: fmt.Sprintf("%020d", i)}
	}
	if err := ValidateBlockedUsers(short); err != nil {
		t.Fatalf("5000 short entries: %v", err)
	}
	if b, _ := json.Marshal(short); len(b) >= MaxBlockedUsersBytes {
		t.Fatalf("5000 short entries marshal to %d bytes, want < %d", len(b), MaxBlockedUsersBytes)
	}

	// 1000 maximum-length entries exceed the byte cap; the error names the
	// total size and carries no entry value.
	big := make([]BlockedUser, 1000)
	for i := range big {
		big[i] = BlockedUser{
			Sub:   fmt.Sprintf("S%04d", i) + strings.Repeat("s", 250),
			Email: strings.Repeat("e", 240) + fmt.Sprintf("%04d", i) + "@x.co"[:4],
		}
	}
	err := ValidateBlockedUsers(big)
	if err == nil || !strings.Contains(err.Error(), "total size") {
		t.Fatalf("err = %v, want total size", err)
	}
	if strings.Contains(err.Error(), "sss") || strings.Contains(err.Error(), "eee") {
		t.Errorf("error leaks entry values: %v", err)
	}
}

func TestPolicyDeepCopyBlockedUsers(t *testing.T) {
	p := Policy{BlockedUsers: []BlockedUser{{Sub: "u1"}, {Email: "a@b.co"}}}
	cp := p.DeepCopy()
	cp.BlockedUsers[0].Sub = "mutated"
	if p.BlockedUsers[0].Sub != "u1" {
		t.Error("DeepCopy shares the BlockedUsers backing array")
	}

	body := `{"allowlist":[{"domain":"a.example.com"}],"blockedUsers":[{"sub":"u1"}]}`
	rp := remoteProviderFor(t, &body)
	if err := rp.Pull(); err != nil {
		t.Fatal(err)
	}
	first, _ := rp.GetPolicy()
	first.BlockedUsers[0].Sub = "mutated"
	second, _ := rp.GetPolicy()
	if second.BlockedUsers[0].Sub != "u1" {
		t.Errorf("GetPolicy shares state: %+v", second.BlockedUsers)
	}
}
