package oauthbroker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// TokenRecordVersion is the only TokenRecord format version.
const TokenRecordVersion = 1

// maxTokenRecordBytes bounds Parse; a real record is well under 8 KiB.
const maxTokenRecordBytes = 64 << 10

// ErrTokenRecord is wrapped by every Marshal and Parse failure. Errors never
// contain token bytes.
var ErrTokenRecord = errors.New("oauthbroker: invalid token record")

// TokenRecord is the one stored grant format: the JSON the broker writes at
// users/<userKey>/<provider> in consent.store (W-P3-BRKR-04), the refresh
// engine rewrites (W-P3-PUS-03) and portal revoke reads (W-P3-PORT-02).
//
// Expiry, RefreshExpiry and ObtainedAt are absolute UTC Unix seconds; 0 means
// "never expires" for the two expiries and is not valid for ObtainedAt of a
// written record. (The cpstate broker tables use epoch milliseconds; this
// record does not.) Scope is the granted scopes, space separated and sorted.
//
// The type redacts itself: String, GoString and LogValue never print the
// tokens, so a record passed to a logger or %v stays safe. A plain
// json.Marshal of the struct does include the tokens, so go through Marshal.
type TokenRecord struct {
	V             int    `json:"v"`
	GrantID       string `json:"grant_id"`
	Provider      string `json:"provider"`
	ClientID      string `json:"client_id"`
	TokenType     string `json:"token_type"`
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	Scope         string `json:"scope"`
	Expiry        int64  `json:"expiry"`
	RefreshExpiry int64  `json:"refresh_expiry"`
	ObtainedAt    int64  `json:"obtained_at"`
}

func (r TokenRecord) validate() error {
	switch {
	case r.V != TokenRecordVersion:
		return fmt.Errorf("%w: unsupported version %d (want %d)", ErrTokenRecord, r.V, TokenRecordVersion)
	case r.GrantID == "":
		return fmt.Errorf("%w: grant_id is empty", ErrTokenRecord)
	case r.Provider == "":
		return fmt.Errorf("%w: provider is empty", ErrTokenRecord)
	case r.AccessToken == "":
		return fmt.Errorf("%w: access_token is empty", ErrTokenRecord)
	case r.Expiry < 0 || r.RefreshExpiry < 0 || r.ObtainedAt < 0:
		return fmt.Errorf("%w: negative timestamp", ErrTokenRecord)
	}
	return nil
}

// Marshal encodes the record as JSON. V is set to TokenRecordVersion, so a
// caller cannot write an unreadable version; an invalid record is refused.
func (r TokenRecord) Marshal() ([]byte, error) {
	r.V = TokenRecordVersion
	if err := r.validate(); err != nil {
		return nil, err
	}
	type plain TokenRecord // no methods: avoids recursion if one is added
	return json.Marshal(plain(r))
}

// ParseTokenRecord decodes and validates a stored record. Unknown versions,
// unknown fields, trailing data and oversized input are rejected.
func ParseTokenRecord(data []byte) (TokenRecord, error) {
	if len(data) > maxTokenRecordBytes {
		return TokenRecord{}, fmt.Errorf("%w: larger than %d bytes", ErrTokenRecord, maxTokenRecordBytes)
	}
	type plain TokenRecord
	var p plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		// json errors do not echo values, but keep the message generic anyway.
		return TokenRecord{}, fmt.Errorf("%w: malformed JSON", ErrTokenRecord)
	}
	if dec.More() {
		return TokenRecord{}, fmt.Errorf("%w: trailing data", ErrTokenRecord)
	}
	r := TokenRecord(p)
	if err := r.validate(); err != nil {
		return TokenRecord{}, err
	}
	return r, nil
}

// Scopes returns the granted scopes (sorted, de-duplicated).
func (r TokenRecord) Scopes() []string { return ParseScopes(r.Scope) }

// HasRefreshToken reports whether a refresh token is stored.
func (r TokenRecord) HasRefreshToken() bool { return r.RefreshToken != "" }

func (r TokenRecord) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "TokenRecord{grant_id=%s provider=%s client_id=%s token_type=%s scope=%q expiry=%d refresh_expiry=%d obtained_at=%d access_token=%s",
		r.GrantID, r.Provider, r.ClientID, r.TokenType, r.Scope, r.Expiry, r.RefreshExpiry, r.ObtainedAt, redacted)
	if r.RefreshToken != "" {
		b.WriteString(" refresh_token=" + redacted)
	}
	b.WriteString("}")
	return b.String()
}

func (r TokenRecord) GoString() string { return r.String() }

// LogValue implements slog.LogValuer with the non-secret fields only.
func (r TokenRecord) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("grant_id", r.GrantID),
		slog.String("provider", r.Provider),
		slog.String("scope", r.Scope),
		slog.Int64("expiry", r.Expiry),
		slog.Bool("has_refresh_token", r.RefreshToken != ""),
		slog.String("access_token", redacted),
	)
}
