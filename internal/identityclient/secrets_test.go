package identityclient_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/identityclient"
)

// TestNoSecretsInErrorsOrLogs drives every path (login, success and failure;
// refresh, success and failure; issuer down) with the logger at debug level and
// checks no token, refresh token, device code or IdP error body shows up in any
// returned error, warning, prompt-free log line or Status.
func TestNoSecretsInErrorsOrLogs(t *testing.T) {
	r := newRig(t)
	var texts []string
	add := func(err error) {
		if err != nil {
			texts = append(texts, err.Error())
		}
	}
	var secrets []string
	collect := func() {
		e, err := r.cl.Store().Load()
		if err == nil {
			secrets = append(secrets, e.IDToken, e.RefreshToken)
			parts := strings.Split(e.IDToken, ".")
			secrets = append(secrets, parts[1], parts[2])
		}
	}

	// Failed logins carry IdP error bodies.
	for _, outcome := range []string{"denied", "expired"} {
		r.idp.setScript(outcome)
		_, err := r.cl.Login(context.Background(), r.out)
		add(err)
	}
	r.idp.setScript()
	w, err := r.cl.Login(context.Background(), r.out)
	add(err)
	texts = append(texts, w...)
	collect()

	// Successful refresh, then a refresh with a revoked token, then 5xx bodies.
	r.clock.Advance(tokenTTL)
	_, err = r.cl.Token(context.Background())
	add(err)
	collect()
	r.idp.mu.Lock()
	r.idp.refresh = "other"
	r.idp.mu.Unlock()
	r.clock.Advance(tokenTTL)
	_, err = r.cl.Token(context.Background())
	add(err)
	r.idp.setDown(true)
	_, err = r.cl.Token(context.Background())
	add(err)
	_, err = r.cl.Login(context.Background(), r.out)
	add(err)
	if st, err := r.cl.Status(); err == nil {
		texts = append(texts, st.Issuer, st.Subject, st.Email, st.CachePath, strings.Join(st.Groups, ","))
	}
	texts = append(texts, r.logs.String())

	secrets = append(secrets, deviceCode, markerBody, baseRefresh, "access-token-secret")
	if r.logs.Len() == 0 {
		t.Fatal("expected debug log lines")
	}
	for _, txt := range texts {
		if s := contains(txt, secrets...); s != "" {
			t.Fatalf("secret %q... found in %q", s[:min(len(s), 12)], txt)
		}
	}
	if !strings.Contains(r.logs.String(), "token_fp=") {
		t.Fatal("log lines should carry the token fingerprint")
	}
}

func TestLoginContextCancel(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.cl.Login(ctx, r.out); err == nil || !errors.Is(err, context.Canceled) && !errors.Is(err, identityclient.ErrIssuerUnreachable) {
		t.Fatalf("got %v", err)
	}
}
