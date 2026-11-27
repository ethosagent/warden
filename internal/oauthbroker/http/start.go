// Package oauthbrokerhttp is the transport of the OAuth broker's connect
// routes: it parses the form, calls oauthbroker.Broker.Start and maps the
// result to an HTTP response. It holds no business logic and never sees a
// database or a provider; the control plane mounts it behind the portal
// session middleware (session, CSRF and Origin checks live there), so the
// handler reads the signed-in user only from portal.PrincipalFrom.
package oauthbrokerhttp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/portal"
)

// Paths of the connect routes. The control plane registers them as literal
// constants of its own and pins them to these (TestConnectRoutePaths).
const (
	// StartPath starts a consent flow (POST); GET only redirects.
	StartPath = "/connect/start"
	// CallbackPath is the provider's redirect target (W-P3-BRKR-04).
	CallbackPath = "/connect/callback"
	// LandingPrefix is the portal landing page of a pending authorization
	// (W-P3-PORT-03): LandingPrefix + <pending id>.
	LandingPrefix = "/portal/connect/"
)

// CookieBase is the connect cookie's base name; on an https deployment the
// control plane prefixes it with "__Host-".
const CookieBase = "warden_connect"

// Cookie is the connect binding cookie's spec, derived by assembly from the
// portal's redirect URL like the other portal cookies.
type Cookie struct {
	Name   string
	Secure bool
}

// Starter is the part of oauthbroker.Broker the handler calls.
type Starter interface {
	Start(ctx context.Context, req oauthbroker.StartRequest) (oauthbroker.StartResult, error)
}

// Config is what New needs.
type Config struct {
	Broker Starter
	// Callback serves GET /connect/callback; nil leaves Callback() answering 404.
	Callback Callbacker
	Cookie   Cookie
	Logger   *slog.Logger
}

// Handler serves the connect routes.
type Handler struct {
	broker     Starter
	callbacker Callbacker
	cookie     Cookie
	logger     *slog.Logger
}

// New returns a Handler.
func New(cfg Config) *Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{broker: cfg.Broker, callbacker: cfg.Callback, cookie: cfg.Cookie, logger: logger}
}

// maxPendingParam bounds the pending id a GET reflects into its redirect.
const maxPendingParam = 64

// Start serves /connect/start. GET writes nothing and sends the browser to the
// landing page (a cross-site link cannot start a flow); POST starts one.
func (h *Handler) Start() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			http.Redirect(w, r, landing(r.URL.Query().Get("pending")), http.StatusSeeOther)
		case http.MethodPost:
			h.post(w, r)
		default:
			w.Header().Set("Allow", "GET, HEAD, POST")
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", nil)
		}
	})
}

// landing is the page a GET goes to: the pending's landing page for a
// plausible id, else the portal home. The id is never trusted: it is
// restricted to the id alphabet and path-escaped.
func landing(pending string) string {
	if pending == "" || len(pending) > maxPendingParam {
		return portal.Home
	}
	for _, c := range pending {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return portal.Home
		}
	}
	return LandingPrefix + url.PathEscape(pending)
}

func (h *Handler) post(w http.ResponseWriter, r *http.Request) {
	p, ok := portal.PrincipalFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, portal.CodeUnauthenticated, nil)
		return
	}
	// Only the body: a query string cannot set a field.
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, oauthbroker.CodeInvalidRequest, nil)
		return
	}
	res, err := h.broker.Start(r.Context(), oauthbroker.StartRequest{
		Iss: p.Iss, Sub: p.Sub, Email: p.Email,
		Provider:  strings.TrimSpace(r.PostForm.Get("provider")),
		Scopes:    oauthbroker.ParseScopes(r.PostForm.Get("scopes")),
		PendingID: strings.TrimSpace(r.PostForm.Get("pending")),
	})
	if err != nil {
		h.refuse(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: h.cookie.Name, Value: res.BrowserToken, Path: "/",
		MaxAge: int(res.CookieMaxAge / time.Second), Secure: h.cookie.Secure,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, res.RedirectURL, http.StatusSeeOther)
}

// refuse maps a Start error to a status and a fixed {"error":code} body. The
// error text is never echoed: it could name a store.
func (h *Handler) refuse(w http.ResponseWriter, err error) {
	var se *oauthbroker.StartError
	if !errors.As(err, &se) {
		writeError(w, http.StatusInternalServerError, oauthbroker.CodeInternal, nil)
		return
	}
	switch se.Code {
	case oauthbroker.CodeRateLimited:
		secs := int((se.RetryAfter + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, se.Code, nil)
	case oauthbroker.CodeTooManyAttempts:
		w.Header().Set("Retry-After", strconv.Itoa(int(oauthbroker.AttemptTTL/time.Second)))
		writeError(w, http.StatusTooManyRequests, se.Code, nil)
	case oauthbroker.CodeScopeNotAllowed:
		writeError(w, http.StatusBadRequest, se.Code, se.Scopes)
	default:
		writeError(w, statusOf(se.Code), se.Code, nil)
	}
}

func statusOf(code string) int {
	switch code {
	case oauthbroker.CodeInvalidRequest:
		return http.StatusBadRequest
	case oauthbroker.CodeUnknownProvider, oauthbroker.CodePendingNotFound:
		return http.StatusNotFound
	case oauthbroker.CodeUserBlocked:
		return http.StatusForbidden
	case oauthbroker.CodePendingNotActive:
		return http.StatusConflict
	case oauthbroker.CodeBlockListUnavailable, oauthbroker.CodeStoreUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// writeError answers {"error":code} (the CP convention), with detail only for
// the scope names a caller itself asked for.
func writeError(w http.ResponseWriter, status int, code string, detail []string) {
	body := map[string]any{"error": code}
	if len(detail) > 0 {
		body["detail"] = detail
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
