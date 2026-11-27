package oauthbroker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func sampleRecord() TokenRecord {
	return TokenRecord{
		V: 1, GrantID: "g-123", Provider: "google", ClientID: "cid", TokenType: "Bearer",
		AccessToken: "ACCESS-TOKEN-VALUE", RefreshToken: "REFRESH-TOKEN-VALUE",
		Scope: "drive openid", Expiry: 1900000000, RefreshExpiry: 0, ObtainedAt: 1800000000,
	}
}

func TestTokenRecordRoundTrip(t *testing.T) {
	in := sampleRecord()
	b, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"v":1`)) {
		t.Errorf("JSON = %s, want v 1", b)
	}
	out, err := ParseTokenRecord(b)
	if err != nil || out != in {
		t.Fatalf("round trip = %+v, %v; want %+v", out, err, in)
	}
	// Marshal pins the version even when the caller left V zero.
	in.V = 0
	if b, err = in.Marshal(); err != nil || !bytes.Contains(b, []byte(`"v":1`)) {
		t.Errorf("V=0 marshal = %s, %v", b, err)
	}
	// A never-expiring token with no refresh token is valid; refresh_token is omitted.
	in.RefreshToken, in.Expiry = "", 0
	b, _ = in.Marshal()
	if bytes.Contains(b, []byte("refresh_token")) {
		t.Errorf("empty refresh_token must be omitted: %s", b)
	}
	if got, err := ParseTokenRecord(b); err != nil || got.HasRefreshToken() || got.Expiry != 0 {
		t.Errorf("parse = %+v, %v", got, err)
	}
	if got := sampleRecord().Scopes(); len(got) != 2 || got[0] != "drive" {
		t.Errorf("Scopes = %v", got)
	}
}

func TestTokenRecordParseRejects(t *testing.T) {
	good := `{"v":1,"grant_id":"g","provider":"p","client_id":"c","token_type":"Bearer","access_token":"a","scope":"s","expiry":0,"refresh_expiry":0,"obtained_at":5}`
	if _, err := ParseTokenRecord([]byte(good)); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	cases := map[string]string{
		"unknown version": strings.Replace(good, `"v":1`, `"v":2`, 1),
		"zero version":    strings.Replace(good, `"v":1`, `"v":0`, 1),
		"missing version": strings.Replace(good, `"v":1,`, ``, 1),
		"unknown field":   strings.Replace(good, `"scope"`, `"extra":"x","scope"`, 1),
		"no grant id":     strings.Replace(good, `"grant_id":"g"`, `"grant_id":""`, 1),
		"no provider":     strings.Replace(good, `"provider":"p"`, `"provider":""`, 1),
		"no access token": strings.Replace(good, `"access_token":"a"`, `"access_token":""`, 1),
		"negative expiry": strings.Replace(good, `"expiry":0`, `"expiry":-1`, 1),
		"trailing data":   good + `{}`,
		"not json":        `nope`,
		"empty":           ``,
		"wrong type":      strings.Replace(good, `"expiry":0`, `"expiry":"soon"`, 1),
	}
	for name, in := range cases {
		_, err := ParseTokenRecord([]byte(in))
		if !errors.Is(err, ErrTokenRecord) {
			t.Errorf("%s: err = %v, want ErrTokenRecord", name, err)
		}
	}
	if _, err := ParseTokenRecord(bytes.Repeat([]byte(" "), maxTokenRecordBytes+1)); !errors.Is(err, ErrTokenRecord) {
		t.Errorf("oversized: %v", err)
	}
	// Errors never echo token bytes.
	_, err := ParseTokenRecord([]byte(strings.Replace(good, `"access_token":"a"`, `"access_token":"LEAKME","x":1`, 1)))
	if err == nil || strings.Contains(err.Error(), "LEAKME") {
		t.Errorf("error = %v", err)
	}
	bad := sampleRecord()
	bad.AccessToken = ""
	if _, err := bad.Marshal(); !errors.Is(err, ErrTokenRecord) {
		t.Errorf("Marshal of an invalid record = %v", err)
	}
}

func TestTokenRecordRedaction(t *testing.T) {
	r := sampleRecord()
	var logs bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&logs, nil))
	l.Info("rec", "record", r, "ptr", &r)
	l.Info("rec2", slog.Any("r", r))
	outs := []string{
		fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r),
		fmt.Sprintf("%v", &r), fmt.Sprintf("%+v", struct{ R TokenRecord }{r}), fmt.Sprint(r), logs.String(),
	}
	for i, o := range outs {
		if strings.Contains(o, "ACCESS-TOKEN-VALUE") || strings.Contains(o, "REFRESH-TOKEN-VALUE") {
			t.Errorf("output %d leaks a token: %s", i, o)
		}
	}
	if !strings.Contains(logs.String(), `"grant_id":"g-123"`) || !strings.Contains(logs.String(), `"has_refresh_token":true`) {
		t.Errorf("slog output lacks the safe fields: %s", logs.String())
	}
}

func TestTokenRecordRedactionInsideWrapper(t *testing.T) {
	type wrap struct {
		Rec  TokenRecord
		Ptr  *TokenRecord
		Map  map[string]TokenRecord
		Name string
	}
	r := sampleRecord()
	w := wrap{Rec: r, Ptr: &r, Map: map[string]TokenRecord{"k": r}, Name: "n"}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("w", "wrap", w, "ptr", &w)
	for _, o := range []string{string(b), logs.String(), fmt.Sprintf("%+v", w), fmt.Sprintf("%#v", w)} {
		if strings.Contains(o, "ACCESS-TOKEN-VALUE") || strings.Contains(o, "REFRESH-TOKEN-VALUE") {
			t.Errorf("wrapper output leaks a token: %s", o)
		}
	}
	// The stored format is unaffected.
	stored, err := r.Marshal()
	if err != nil || !bytes.Contains(stored, []byte("ACCESS-TOKEN-VALUE")) {
		t.Errorf("Marshal must still carry the token: %s, %v", stored, err)
	}
}

// A caller that bypasses Marshal gets the redacted JSON, which Parse refuses:
// a stored grant written that way fails closed instead of using a placeholder token.
func TestTokenRecordParseRejectsRedactedJSON(t *testing.T) {
	b, err := json.Marshal(sampleRecord())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTokenRecord(b); !errors.Is(err, ErrTokenRecord) {
		t.Errorf("ParseTokenRecord(json.Marshal(record)) = %v, want ErrTokenRecord", err)
	}
}
