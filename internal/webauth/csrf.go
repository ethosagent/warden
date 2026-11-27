package webauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"mime"
	"net/http"
)

// CSRFHeader carries the per-session CSRF token on state-changing requests.
const CSRFHeader = "X-Warden-CSRF"

// CSRFToken derives the CSRF token for a raw session id: HMAC-SHA256 keyed by
// the id over the front door's label. Different labels give unrelated tokens,
// so one front door's token never validates on another. The token is never
// stored.
func CSRFToken(rawID []byte, label string) string {
	m := hmac.New(sha256.New, rawID)
	m.Write([]byte(label))
	return hex.EncodeToString(m.Sum(nil))
}

// CSRF is one front door's CSRF rule for requests that carry a live session.
type CSRF struct {
	// Label is the HMAC label of CSRFToken.
	Label string
	// Origin, when a request sends an Origin header, is the only value
	// accepted (Cookie.Origin).
	Origin string
	// FormField, when set, is also read from an
	// application/x-www-form-urlencoded body when the header is absent. Empty
	// accepts the header only.
	FormField string
}

// Valid applies the rule to a request with the live session rawID. Safe
// methods pass. Otherwise an Origin header, when present, must equal c.Origin
// and the token (header, or form field) must equal the session's token,
// compared in constant time.
func (c CSRF) Valid(r *http.Request, rawID string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if o := r.Header.Get("Origin"); o != "" && o != c.Origin {
		return false
	}
	got := r.Header.Get(CSRFHeader)
	if got == "" && c.FormField != "" {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "application/x-www-form-urlencoded" {
			got = r.PostFormValue(c.FormField)
		}
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(CSRFToken([]byte(rawID), c.Label))) == 1
}
