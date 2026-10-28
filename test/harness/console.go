package harness

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The console OIDC login (W-P1-SSO-03): the control plane boots with
// console.auth oidc against the in-process issuer fake, and a scenario plays the
// browser through /auth/login, the issuer and /auth/callback.

const (
	// ConsoleClientID is the OIDC client the control plane registers as.
	ConsoleClientID = "warden-console"
	// ConsoleAdminGroup and ConsoleViewerGroup are the groups console.roles maps.
	ConsoleAdminGroup  = "console-admins"
	ConsoleViewerGroup = "console-viewers"

	consoleSecretEnv   = "WARDEN_HARNESS_CONSOLE_SECRET"
	consoleSecretValue = "harness-console-client-secret"
)

// WithConsoleOIDC boots the control plane with console.auth oidc: issuer and
// internalIssuerURL are the issuer fake (implies WithOIDCIssuer), the redirect
// URL is the control plane's own https origin, state lives in a state dir, and
// the control plane's clock is the harness's fake clock, so a scenario can
// expire a session with h.Clock().Advance. The fake is registered as the console
// client and, until SetLogin says otherwise, signs users in with no groups.
func WithConsoleOIDC() Option {
	return func(h *H) {
		h.wantIssuer = true
		h.wantConsole = true
	}
}

// prepareConsole sets the client secret and reserves the control plane's
// address: the redirect URL in its config needs the port before it listens.
func (h *H) prepareConsole() {
	if h.suppliedTarget != nil {
		h.tb.Fatal("harness: WithConsoleOIDC boots an in-process control plane; it cannot combine with WithTarget")
	}
	h.tb.Setenv(consoleSecretEnv, consoleSecretValue)
	h.issuer.RegisterClient(ConsoleClientID, consoleSecretValue)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.tb.Fatalf("harness: reserve the control-plane address: %v", err)
	}
	h.consoleAddr = ln.Addr().String()
	// Closed again at once; cpProc.start binds the recorded address, exactly as a
	// restart after StopControlPlane does.
	_ = ln.Close()
}

func (h *H) applyConsole(p *controlplane.Params, addr *string) {
	if h.wantWorkerTokens {
		p.StateDir = filepath.Join(h.root, "cp-state")
		// The token store polls for out-of-process revokes on the CP's clock:
		// h.Clock().Advance drives it.
		p.Clock = h.fake
	}
	if h.wantAdminAudit {
		p.StateDir = filepath.Join(h.root, "cp-state")
		// The checkpoint loop runs on the CP's clock: h.Clock().Advance drives it.
		p.Clock = h.fake
	}
	if !h.wantConsole {
		return
	}
	*addr = h.consoleAddr
	p.StateDir = filepath.Join(h.root, "cp-state")
	p.Clock = h.fake
}

// consoleYAML renders the console block for the control plane's config file.
func (h *H) consoleYAML() string {
	audit := ""
	if h.wantAdminAudit {
		audit = "  adminAudit:\n    enabled: true\n"
	}
	if !h.wantConsole {
		if audit == "" {
			return ""
		}
		return "\nconsole:\n" + audit
	}
	return fmt.Sprintf(`
console:
`+audit+`  auth: oidc
  oidc:
    issuer: %[1]s
    internalIssuerURL: %[1]s
    clientID: %[2]s
    clientSecretEnv: %[3]s
    redirectURL: %[4]s
  roles:
    admin: [%[5]s]
    viewer: [%[6]s]
`, h.issuer.Issuer(), ConsoleClientID, consoleSecretEnv, h.ConsoleURL()+"/auth/callback", ConsoleAdminGroup, ConsoleViewerGroup)
}

// ConsoleURL is the control plane's https origin, the one the IdP redirects to.
func (h *H) ConsoleURL() string {
	h.tb.Helper()
	if !h.wantConsole {
		h.tb.Fatal("harness: ConsoleURL needs the WithConsoleOIDC option")
	}
	return "https://" + h.consoleAddr
}

// ConsoleBrowser returns a browser for the console: it trusts the control
// plane's CA, keeps cookies in a jar and never follows a redirect on its own,
// so a scenario sees each hop. It reaches the issuer fake over plain http.
func (h *H) ConsoleBrowser() *Browser {
	h.tb.Helper()
	pool, err := h.target.ControlPlaneCA()
	if err != nil {
		h.tb.Fatalf("harness: control-plane CA: %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		h.tb.Fatalf("harness: cookie jar: %v", err)
	}
	noFollow := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	h.tb.Cleanup(tr.CloseIdleConnections)
	return &Browser{
		h:    h,
		base: h.ConsoleURL(),
		jar:  jar,
		cl:   &http.Client{Transport: tr, Jar: jar, CheckRedirect: noFollow},
	}
}

// Browser is the harness's console user agent (see ConsoleBrowser).
type Browser struct {
	h    *H
	base string
	jar  *cookiejar.Jar
	cl   *http.Client
}

// Do sends one request with the browser's cookies. url is absolute, or a path
// on the console. The response body is read by the caller, who closes it.
func (b *Browser) Do(method, target string, hdr http.Header) (*http.Response, error) {
	return b.DoBody(method, target, hdr, nil)
}

// DoBody is Do with a request body (sent as application/json when not nil).
func (b *Browser) DoBody(method, target string, hdr http.Header, body []byte) (*http.Response, error) {
	if len(target) > 0 && target[0] == '/' {
		target = b.base + target
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	return b.cl.Do(req)
}

// Cookies returns the cookies the browser would send to the console.
func (b *Browser) Cookies() []*http.Cookie {
	u, _ := url.Parse(b.base)
	return b.jar.Cookies(u)
}

// ConsoleSession is one row of the control plane's sessions table.
type ConsoleSession struct {
	Iss, Sub, Email string
	CreatedAt       int64
	LastSeenAt      int64
	ExpiresAt       int64
}

// ConsoleSessions reads the sessions table of the control plane's state
// database, read-only: what the control plane stored, independent of its API.
func (h *H) ConsoleSessions() []ConsoleSession {
	h.tb.Helper()
	if !h.wantConsole {
		h.tb.Fatal("harness: ConsoleSessions needs the WithConsoleOIDC option")
	}
	path := filepath.Join(h.root, "cp-state", "warden-cp.db")
	if _, err := os.Stat(path); err != nil {
		h.tb.Fatalf("harness: control-plane state db: %v", err)
	}
	db, err := cpstate.OpenReadOnly(context.Background(), path, controlplane.StateMigrations())
	if err != nil {
		h.tb.Fatalf("harness: open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT iss, sub, email, created_at, last_seen_at, expires_at FROM sessions ORDER BY created_at, id_hash`)
	if err != nil {
		h.tb.Fatalf("harness: read sessions: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ConsoleSession
	for rows.Next() {
		var s ConsoleSession
		if err := rows.Scan(&s.Iss, &s.Sub, &s.Email, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt); err != nil {
			h.tb.Fatalf("harness: scan a session: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		h.tb.Fatalf("harness: read sessions: %v", err)
	}
	return out
}
