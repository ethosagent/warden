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
// sign-in at. It never mints a token: the worker only starts the authorization,
// and the client (not under test here) would poll the token endpoint.

// DeviceRequest is one device authorization the fake accepted.
type DeviceRequest struct{ ClientID, Scope string }

type deviceState struct {
	mu        sync.Mutex
	requests  []DeviceRequest
	status    int
	base      string // overrides the verification URI origin ("" = this issuer)
	expiresIn int
	n         int
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
	d.mu.Unlock()
	if base == "" {
		base = i.Issuer()
	}
	if expires == 0 {
		expires = 300
	}
	code := fmt.Sprintf("ABCD-%04d", n)
	writeJSON(w, map[string]any{
		"device_code":               fmt.Sprintf("device-code-%d", n),
		"user_code":                 code,
		"verification_uri":          base + "/device",
		"verification_uri_complete": base + "/device?user_code=" + url.QueryEscape(code),
		"expires_in":                expires,
		"interval":                  5,
	})
}
