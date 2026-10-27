package harness

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"

	"github.com/ethosagent/warden/internal/controlplane"
)

// The control plane's own admin bearer (W-P1-WTOK-07): with
// WithControlPlaneAdminToken the control plane boots with --admin-token-env
// pointing at a fresh random token, separate from the shared worker token
// (cpTokenEnv), so a scenario can prove which of the two opens what.

// cpAdminTokenEnv is the env var the harness's control plane reads its admin
// bearer from (Params.AdminTokenEnv). Set via t.Setenv, like cpTokenEnv.
const cpAdminTokenEnv = "WARDEN_HARNESS_CP_ADMIN_TOKEN"

// WithControlPlaneAdminToken boots the control plane with its own admin bearer
// (--admin-token-env). In-process only: it cannot combine with WithTarget.
func WithControlPlaneAdminToken() Option {
	return func(h *H) { h.wantCPAdmin = true }
}

// prepareCPAdmin sets the admin token env before the control plane boots.
func (h *H) prepareCPAdmin() {
	if h.suppliedTarget != nil {
		h.tb.Fatal("harness: WithControlPlaneAdminToken boots an in-process control plane; it cannot combine with WithTarget")
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		h.tb.Fatalf("harness: generate control-plane admin token: %v", err)
	}
	h.tb.Setenv(cpAdminTokenEnv, hex.EncodeToString(tok))
}

func (h *H) applyCPAdmin(p *controlplane.Params) {
	if h.wantCPAdmin {
		p.AdminTokenEnv = cpAdminTokenEnv
	}
}

// ControlPlaneAdminToken is the control plane's admin bearer, or "" when the
// harness was not booted WithControlPlaneAdminToken.
func (h *H) ControlPlaneAdminToken() string {
	if !h.wantCPAdmin {
		return ""
	}
	return os.Getenv(cpAdminTokenEnv)
}

// Do sends one request to a control-plane path with an explicit bearer ("" =
// no Authorization header) and returns the status and up to 64 KiB of the
// body. Unlike GetJSON/PostJSON it does not use the shared worker token, so a
// scenario can compare credentials route by route.
func (c *CPClient) Do(method, path, bearer string, body []byte) (int, string, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+c.addr+path, r)
	if err != nil {
		return 0, "", err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.cl.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b), nil
}

// Token is the shared worker token this client authenticates with.
func (c *CPClient) Token() string { return c.token }
