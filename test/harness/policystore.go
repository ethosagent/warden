package harness

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"

	"github.com/ethosagent/warden/internal/controlplane"
)

// WithVersionedPolicyStore boots the control plane with
// --policy-store=versioned and a state dir, so /policy serves the head of the
// versioned policy store (the YAML while the store is empty). In-process only.
func WithVersionedPolicyStore() Option {
	return func(h *H) { h.versionedPolicy = true }
}

// applyPolicyStore sets the control-plane params WithVersionedPolicyStore asks
// for. The state dir is the one WithConsoleOIDC uses, so the two combine.
func (h *H) applyPolicyStore(p *controlplane.Params) {
	if !h.versionedPolicy {
		return
	}
	p.StateDir = filepath.Join(h.root, "cp-state")
	p.PolicyStore = controlplane.PolicyStoreVersioned
}

// ControlPlaneStateDB is the path of the control plane's state database, for a
// scenario that plays an out-of-process writer (the CLI). It needs
// WithVersionedPolicyStore, WithConsoleOIDC or WithWorkerTokens.
func (h *H) ControlPlaneStateDB() string {
	h.tb.Helper()
	if !h.versionedPolicy && !h.wantConsole && !h.wantWorkerTokens {
		h.tb.Fatal("harness: ControlPlaneStateDB needs WithVersionedPolicyStore, WithConsoleOIDC or WithWorkerTokens")
	}
	return filepath.Join(h.root, "cp-state", "warden-cp.db")
}

// WithWorkerTokens boots the control plane with a state dir, so it builds the
// per-worker token store (W-P1-WTOK-02) on the harness's fake clock. The
// workers keep using the shared token; a scenario mints tokens out of process
// (ControlPlaneStateDB) and presents them through CP().DoWorker. In-process only.
func WithWorkerTokens() Option {
	return func(h *H) { h.wantWorkerTokens = true }
}

// CPResponse is one control-plane reply: status, headers and up to 64 KiB of
// the body.
type CPResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// Send sends one request to a control-plane path with the shared bearer and
// the extra headers hdr (for example If-Match), and returns the reply whatever
// its status, so a scenario can assert on a 4xx and on response headers.
func (c *CPClient) Send(method, path string, hdr http.Header, body []byte) (CPResponse, error) {
	return c.SendBearer(c.token, method, path, hdr, body)
}

// SendBearer is Send with an explicit bearer ("" = none), for the routes that
// need the control plane's admin token (WithControlPlaneAdminToken).
func (c *CPClient) SendBearer(bearer, method, path string, hdr http.Header, body []byte) (CPResponse, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+c.addr+path, r)
	if err != nil {
		return CPResponse{}, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.cl.Do(req)
	if err != nil {
		return CPResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return CPResponse{}, err
	}
	return CPResponse{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}
