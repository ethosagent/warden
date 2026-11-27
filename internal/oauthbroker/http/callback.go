package oauthbrokerhttp

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"time"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/portal"
)

// Callbacker is the part of oauthbroker.Broker the callback handler calls.
type Callbacker interface {
	Callback(ctx context.Context, req oauthbroker.CallbackRequest) (oauthbroker.CallbackResult, error)
}

// Bounds on the query values a callback passes to the broker. A real state is
// 43 characters, a real code well under 512; anything longer is refused as an
// invalid state without being looked up.
const (
	maxStateParam = 256
	maxCodeParam  = 2048
	maxErrorParam = 128
)

// Callback serves GET /connect/callback behind the portal session middleware:
// the provider's redirect target. It reads only the query's state, code and
// error and the connect cookie; error_description is never read, and no page or
// redirect carries provider text. Success is a 303 to a fixed internal path; a
// failure is a generic page with a fixed message and the status the broker
// names. The connect cookie is cleared on every response, because the attempt
// it was bound to is single use.
func (h *Handler) Callback() http.Handler {
	if h.callbacker == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeErrorPage(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		p, ok := portal.PrincipalFrom(r.Context())
		if !ok {
			writeErrorPage(w, http.StatusUnauthorized, portal.CodeUnauthenticated)
			return
		}
		h.clearCookie(w)
		q := r.URL.Query()
		state, code, perr := q.Get("state"), q.Get("code"), q.Get("error")
		if len(state) > maxStateParam || len(code) > maxCodeParam || len(perr) > maxErrorParam {
			writeErrorPage(w, http.StatusBadRequest, oauthbroker.CodeStateInvalid)
			return
		}
		browser := ""
		if c, err := r.Cookie(h.cookie.Name); err == nil {
			browser = c.Value
		}
		res, err := h.callbacker.Callback(r.Context(), oauthbroker.CallbackRequest{
			Iss: p.Iss, Sub: p.Sub, Email: p.Email,
			State: state, Code: code, ProviderError: perr, BrowserToken: browser,
		})
		if err != nil {
			var ce *oauthbroker.CallbackError
			if !errors.As(err, &ce) {
				writeErrorPage(w, http.StatusInternalServerError, oauthbroker.CodeInternal)
				return
			}
			writeErrorPage(w, ce.Status(), ce.Code)
			return
		}
		http.Redirect(w, r, resultLocation(res), http.StatusSeeOther)
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: h.cookie.Name, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0),
		Secure: h.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// resultLocation is the fixed internal path a finished callback goes to: the
// pending's landing page, or the portal home for a portal-started connect. The
// only variable parts are a broker-issued id or a configured provider id,
// escaped, and a fixed reason code.
func resultLocation(res oauthbroker.CallbackResult) string {
	v := url.Values{}
	if res.PendingID != "" {
		v.Set("result", res.Result)
		if res.Reason != "" {
			v.Set("reason", res.Reason)
		}
		return LandingPrefix + url.PathEscape(res.PendingID) + "?" + v.Encode()
	}
	if res.Result == oauthbroker.ResultGranted {
		v.Set("connected", res.Provider)
	} else {
		v.Set("connect_denied", res.Provider)
		if res.Reason != "" {
			v.Set("reason", res.Reason)
		}
	}
	return portal.Home + "?" + v.Encode()
}

// pageText is the fixed explanation of each failure code. A code outside the
// table gets the generic line; nothing from the provider or the request is
// ever put on a page.
var pageText = map[string]string{
	oauthbroker.CodeStateInvalid:        "This connection link is not valid any more. Start the connection again from the portal.",
	oauthbroker.CodeSessionMismatch:     "This connection was started by a different user. Sign in as that user, or start again.",
	oauthbroker.CodeUserBlocked:         "Your account cannot connect services.",
	oauthbroker.CodeExchangeFailed:      "The provider did not accept the connection. Start the connection again from the portal.",
	oauthbroker.CodeScopeExceeded:       "The provider granted access that this deployment does not allow, so nothing was saved.",
	oauthbroker.CodeProviderUnreachable: "The provider could not be reached. Try again in a moment.",
}

func writeErrorPage(w http.ResponseWriter, status int, code string) {
	msg, ok := pageText[code]
	if !ok {
		msg = "The connection could not be completed. Try again later."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
		"<title>Connection failed</title><style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}</style></head><body>" +
		"<h1>Connection failed</h1><p>" + html.EscapeString(msg) + "</p><p><a href=\"" + portal.Home + "\">Back to the portal</a></p>" +
		"<p><small>Reference: " + html.EscapeString(code) + "</small></p></body></html>"))
}
