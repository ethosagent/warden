package fakes

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// This file adds the RFC 8628 device authorization endpoint to the OIDC issuer
// fake (#558), so a worker in identity challenge mode has an issuer to start a
// sign-in at, and the device-code grant on the token endpoint (#621), so the
// client's poll can be driven: it answers authorization_pending until a test
// calls ApproveDevice, then hands out the tokens the test supplied. The fake
// mints nothing itself here; the test signs the ID token with Mint.

// deviceGrant is the RFC 8628 grant type of a device-code token request.
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceRequest is one device authorization the fake accepted.
type DeviceRequest struct{ ClientID, Scope string }

type deviceState struct {
	mu        sync.Mutex
	requests  []DeviceRequest
	status    int
	base      string // overrides the verification URI origin ("" = this issuer)
	expiresIn int
	n         int
	codes     []string             // every device code handed out, in order
	issued    map[string]bool      // device codes handed out and not yet redeemed
	approved  map[string][2]string // device_code -> {id_token, refresh_token}
}

// DeviceRequests returns the device authorizations accepted so far.
func (i *OIDCIssuer) DeviceRequests() []DeviceRequest {
	i.device.mu.Lock()
	defer i.device.mu.Unlock()
	return append([]DeviceRequest(nil), i.device.requests...)
}

// SetDeviceStatus makes the device endpoint answer with this HTTP status and no
// authorization (an issuer that is up for discovery but fails the start), until
// called with 0.
func (i *OIDCIssuer) SetDeviceStatus(status int) {
	i.device.mu.Lock()
	defer i.device.mu.Unlock()
	i.device.status = status
}

// SetDeviceVerificationBase makes the verification URIs start with base instead
// of this issuer's URL (a misbehaving issuer pointing users at another site),
// until called with "".
func (i *OIDCIssuer) SetDeviceVerificationBase(base string) {
	i.device.mu.Lock()
	defer i.device.mu.Unlock()
	i.device.base = strings.TrimRight(base, "/")
}

// SetDeviceExpiresIn sets the expires_in the device endpoint answers (seconds;
// 0 = 300).
func (i *OIDCIssuer) SetDeviceExpiresIn(seconds int) {
	i.device.mu.Lock()
	defer i.device.mu.Unlock()
	i.device.expiresIn = seconds
}

// DeviceCodes returns the device codes handed out so far, oldest first, so a
// test can approve the one a worker started.
func (i *OIDCIssuer) DeviceCodes() []string {
	i.device.mu.Lock()
	defer i.device.mu.Unlock()
	return append([]string(nil), i.device.codes...)
}

// ApproveDevice marks a device code as approved by the user: the next token
// request for it (once) returns idToken and refreshToken. Until then the token
// endpoint answers authorization_pending for a code it issued.
func (i *OIDCIssuer) ApproveDevice(deviceCode, idToken, refreshToken string) {
	i.device.mu.Lock()
	defer i.device.mu.Unlock()
	if i.device.approved == nil {
		i.device.approved = map[string][2]string{}
	}
	i.device.approved[deviceCode] = [2]string{idToken, refreshToken}
}

// handleDeviceToken answers a device-code grant (r's form is parsed): approved
// codes get the tokens once, a code this fake issued but nobody approved is
// authorization_pending, anything else invalid_grant.
func (i *OIDCIssuer) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("device_code")
	d := &i.device
	d.mu.Lock()
	tokens, approved := d.approved[code]
	delete(d.approved, code)
	issued := d.issued[code]
	if approved {
		delete(d.issued, code)
	}
	d.mu.Unlock()
	switch {
	case approved:
		writeJSON(w, map[string]any{
			"access_token":  "fake-access-token",
			"token_type":    "Bearer",
			"expires_in":    int(OIDCTokenTTL.Seconds()),
			"id_token":      tokens[0],
			"refresh_token": tokens[1],
		})
	case issued:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}
}

func (i *OIDCIssuer) handleDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	d := &i.device
	d.mu.Lock()
	if d.status != 0 {
		status := d.status
		d.mu.Unlock()
		http.Error(w, "device endpoint failing", status)
		return
	}
	d.n++
	n := d.n
	d.requests = append(d.requests, DeviceRequest{ClientID: r.PostForm.Get("client_id"), Scope: r.PostForm.Get("scope")})
	base, expires := d.base, d.expiresIn
	deviceCode := fmt.Sprintf("device-code-%d", n)
	if d.issued == nil {
		d.issued = map[string]bool{}
	}
	d.issued[deviceCode] = true
	d.codes = append(d.codes, deviceCode)
	d.mu.Unlock()
	if base == "" {
		base = i.Issuer()
	}
	if expires == 0 {
		expires = 300
	}
	code := fmt.Sprintf("ABCD-%04d", n)
	writeJSON(w, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 code,
		"verification_uri":          base + "/device",
		"verification_uri_complete": base + "/device?user_code=" + url.QueryEscape(code),
		"expires_in":                expires,
		"interval":                  5,
	})
}
