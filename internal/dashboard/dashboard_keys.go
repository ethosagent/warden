package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// The signing-key admin API (W-P2-KEYS-04): list the keys the control plane
// holds and request a rotation. The handlers reach the key manager through
// KeysSource (internal/controlplane imports this package, not the other way
// round). The routes answer only when SetKeysSource was called, which the
// control plane does when keys.enabled; a worker or a control plane without
// keys answers 404.
//
// Nothing here can carry private material: KeyView has no field for it, and
// the public JWK is the same document the JWKS serves.

// maxKeysRotateBody caps a rotate body ({purpose, emergency, confirmPinned}).
const maxKeysRotateBody = 1 << 10

// Purposes the console can name. Bundle rotation is staged through the CLI.
const (
	keyPurposeToken  = "token"
	keyPurposeBundle = "bundle"
)

// Errors a KeysSource returns from Rotate. The handlers answer each with a
// fixed status and message.
var (
	// ErrKeysInvalid: the purpose is not one the manager rotates (400).
	ErrKeysInvalid = errors.New("invalid key rotation request")
	// ErrKeysConflict: the next key is missing or not published long enough, or
	// another writer moved the keys first (409).
	ErrKeysConflict = errors.New("key rotation conflict")
	// ErrKeysNoActor: the request carries no console identity to attribute the
	// rotation to (401).
	ErrKeysNoActor = errors.New("no console identity")
)

// KeyJWK is a key's public JWK as the JWKS publishes it.
type KeyJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// KeyView is one signing key's metadata. Times are RFC 3339 in UTC; an unset
// time is omitted.
type KeyView struct {
	KID         string `json:"kid"`
	Purpose     string `json:"purpose"`
	Alg         string `json:"alg"`
	State       string `json:"state"`
	Backend     string `json:"backend"`
	CreatedAt   string `json:"createdAt,omitempty"`
	PublishAt   string `json:"publishAt,omitempty"`
	ActivateAt  string `json:"activateAt,omitempty"`
	RetireAt    string `json:"retireAt,omitempty"`
	DestroyedAt string `json:"destroyedAt,omitempty"`
	PublicJWK   KeyJWK `json:"publicJwk"`
}

// KeyPurposeView is whether a purpose has an active key loaded and, when it
// does not, why (a short reason, never key material).
type KeyPurposeView struct {
	Purpose   string `json:"purpose"`
	Loaded    bool   `json:"loaded"`
	LastError string `json:"lastError,omitempty"`
}

// KeysResponse is the body of GET /dashboard/api/keys.
type KeysResponse struct {
	Keys     []KeyView        `json:"keys"`
	Purposes []KeyPurposeView `json:"purposes"`
}

// KeyRotateRequest is a rotation. ConfirmPinned is the operator's assertion
// that workers hold the next key; only the bundle purpose needs it, and the
// console does not rotate that purpose.
type KeyRotateRequest struct {
	Purpose       string `json:"purpose"`
	Emergency     bool   `json:"emergency"`
	ConfirmPinned bool   `json:"confirmPinned"`
}

// KeysSource is the control plane's key manager as the dashboard sees it. ctx
// carries the caller's console identity, which Rotate records as the actor.
type KeysSource interface {
	Keys(ctx context.Context) KeysResponse
	Rotate(ctx context.Context, req KeyRotateRequest) error
}

// SetKeysSource enables the key routes. Only the control plane calls it, and
// only with keys.enabled; elsewhere the routes answer 404.
func (s *Server) SetKeysSource(k KeysSource) { s.keys = k }

// handleKeys serves GET /dashboard/api/keys.
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.keys == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	resp := s.keys.Keys(r.Context())
	if resp.Keys == nil {
		resp.Keys = []KeyView{}
	}
	if resp.Purposes == nil {
		resp.Purposes = []KeyPurposeView{}
	}
	writeJSON(w, resp)
}

// handleKeysRotate serves POST /dashboard/api/keys/rotate.
func (s *Server) handleKeysRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.keys == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.keyWritesAllowed(w) {
		return
	}
	var req KeyRotateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKeysRotateBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// One JSON value only: trailing data is a malformed request.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	switch req.Purpose {
	case keyPurposeToken:
	case keyPurposeBundle:
		writeJSONStatus(w, http.StatusConflict, map[string]string{
			"error":   "use_cli",
			"message": "bundle keys are pinned on workers, so their rotation is staged: use `warden keys rotate --purpose bundle` on the control plane host",
		})
		return
	default:
		writeError(w, http.StatusBadRequest, "purpose must be token")
		return
	}
	if err := s.keys.Rotate(r.Context(), req); err != nil {
		writeKeysError(w, err)
		return
	}
	writeJSON(w, s.keys.Keys(r.Context()))
}

// keyWritesAllowed refuses a rotation unless the console has real identities
// (oidc), for the reason worker token writes do: without one there is nobody to
// attribute it to. It fails closed: an unset or unknown mode refuses.
func (s *Server) keyWritesAllowed(w http.ResponseWriter) bool {
	if s.authMode == "oidc" {
		return true
	}
	writeJSONStatus(w, http.StatusForbidden, map[string]string{
		"error":   "use_cli",
		"message": "keys are not rotated from the console without sign-in (console.auth: none); use `warden keys rotate` on the control plane host",
	})
	return false
}

// writeKeysError answers a KeysSource error with a fixed message; the
// manager's own text stays server-side (the control plane logs it).
func writeKeysError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrKeysInvalid):
		writeError(w, http.StatusBadRequest, "invalid key rotation request")
	case errors.Is(err, ErrKeysConflict):
		writeError(w, http.StatusConflict, "the next key is missing, not published long enough, or another writer rotated first")
	case errors.Is(err, ErrKeysNoActor):
		writeError(w, http.StatusUnauthorized, "console session required")
	default:
		writeError(w, http.StatusInternalServerError, "key rotation failed")
	}
}
