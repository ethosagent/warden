package fakes

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestOIDCIssuerDeviceAuthorization: discovery advertises the device endpoint,
// each accepted request gets fresh codes and is recorded, and the levers change
// the verification origin, the lifetime and the status.
func TestOIDCIssuerDeviceAuthorization(t *testing.T) {
	iss := NewOIDCIssuer(t, WithPublicIssuer("http://localhost:5556/dex"))
	resp, err := http.Get(iss.URL() + "/dex/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	_ = resp.Body.Close()
	if doc["device_authorization_endpoint"] != "http://localhost:5556/dex/device/code" {
		t.Fatalf("discovery device endpoint = %v", doc["device_authorization_endpoint"])
	}

	form := url.Values{"client_id": {"warden-cli"}, "scope": {"openid email"}}
	// The listener serves the public path prefix.
	resp, err = http.PostForm(iss.URL()+"/dex/device/code", form)
	if err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&first)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || first["device_code"] == "" || first["user_code"] == "" ||
		!strings.HasPrefix(first["verification_uri_complete"].(string), "http://localhost:5556/dex/device?user_code=") {
		t.Fatalf("first = %d %v", resp.StatusCode, first)
	}
	if reqs := iss.DeviceRequests(); len(reqs) != 1 || reqs[0].ClientID != "warden-cli" || reqs[0].Scope != "openid email" {
		t.Fatalf("recorded requests = %+v", reqs)
	}

	iss.SetDeviceVerificationBase("https://evil.example.org/")
	iss.SetDeviceExpiresIn(7)
	resp, _ = http.PostForm(iss.URL()+"/dex/device/code", form)
	var second map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&second)
	_ = resp.Body.Close()
	if second["verification_uri"] != "https://evil.example.org/device" || second["expires_in"] != float64(7) || second["device_code"] == first["device_code"] {
		t.Fatalf("second = %v", second)
	}

	iss.SetDeviceStatus(503)
	resp, _ = http.PostForm(iss.URL()+"/dex/device/code", form)
	_ = resp.Body.Close()
	if resp.StatusCode != 503 || len(iss.DeviceRequests()) != 2 {
		t.Fatalf("failing endpoint: status %d, %d recorded", resp.StatusCode, len(iss.DeviceRequests()))
	}
	// Only POST is served.
	iss.SetDeviceStatus(0)
	gr, _ := http.Get(iss.URL() + "/dex/device/code")
	_ = gr.Body.Close()
	if gr.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status %d, want 405", gr.StatusCode)
	}
}

// TestOIDCIssuerDeviceToken: the device-code grant answers authorization_pending
// for an issued code, hands out the supplied tokens once after ApproveDevice,
// and invalid_grant for a code it never issued or already redeemed.
func TestOIDCIssuerDeviceToken(t *testing.T) {
	iss := NewOIDCIssuer(t)
	resp, err := http.PostForm(iss.URL()+"/device/code", url.Values{"client_id": {"warden-cli"}})
	if err != nil {
		t.Fatal(err)
	}
	var da map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&da)
	_ = resp.Body.Close()
	code, _ := da["device_code"].(string)

	poll := func(c string) (int, map[string]any) {
		t.Helper()
		resp, err := http.PostForm(iss.URL()+"/token", url.Values{
			"grant_type": {deviceGrant}, "device_code": {c}, "client_id": {"warden-cli"},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if st, out := poll(code); st != 400 || out["error"] != "authorization_pending" {
		t.Fatalf("before approval: %d %v", st, out)
	}
	if st, out := poll("device-code-unknown-to-the-fake"); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("a code that was never issued: %d %v", st, out)
	}
	iss.ApproveDevice(code, "id-token-value", "refresh-token-value")
	st, out := poll(code)
	if st != 200 || out["id_token"] != "id-token-value" || out["refresh_token"] != "refresh-token-value" {
		t.Fatalf("after approval: %d %v", st, out)
	}
	if st, out := poll(code); st != 400 || out["error"] == nil {
		t.Fatalf("a redeemed code: %d %v", st, out)
	}
}
