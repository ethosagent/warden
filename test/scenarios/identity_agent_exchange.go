package scenarios

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/test/harness"
)

// The agent half of the identity client (W-P2-RCP-01): the real
// identityclient — an enrolled Ed25519 key, a fresh private_key_jwt assertion
// per exchange, the WardenTokenSource schedule — against the real token
// endpoint of the control plane. The agent is registered with the public JWK
// `warden identity enroll` prints, so a wrong claim, header or audience in the
// client's assertion fails here exactly as it would in production.

// identityAgentExchange: a key made by the client library registers, exchanges
// a user's ID token for a Warden token bound to that key (cnf.jkt is the
// enrolled thumbprint), is served from memory until 2/3 of the lifetime, then
// re-exchanges into the same session with a new token; a first-key 503 is
// reported with its Retry-After; a disabled agent is refused as invalid_client
// and never retried, while a still-valid token keeps being served until exp.
func identityAgentExchange(t *testing.T, h *harness.H) {
	key, err := identityclient.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	const agentID = "harness-agent"
	h.RegisterTokenAgentKey(agentID, key.PublicJWK(), []string{"eng"}, []string{"read", "write"})

	subjectFile := filepath.Join(t.TempDir(), "subject")
	writeSubject := func() string {
		tok := tokenUser(h, "user-42", "eng")
		if err := os.WriteFile(subjectFile, []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return tok
	}
	user := writeSubject()
	newSource := func() (*identityclient.WardenTokenSource, *identityclient.Exchanger) {
		ex := &identityclient.Exchanger{
			Endpoint: h.CP().TokenEndpointURL(), Audience: harness.TokenAudience(),
			AgentID: agentID, Key: key, Scope: "read", HTTP: h.CP().HTTPClient(), Now: h.Clock().Now,
		}
		src := identityclient.NewWardenTokenSource(ex, identityclient.FileSubject{Path: subjectFile})
		src.Now, src.Attempts = h.Clock().Now, 1
		return src, ex
	}
	src, ex := newSource()

	// The control plane's first signing key is not published yet: a 503 whose
	// Retry-After the client reports.
	_, err = ex.Exchange(context.Background(), user)
	var unavailable identityclient.ErrUnavailable
	if !errors.As(err, &unavailable) || unavailable.RetryAfter != 5*time.Second {
		t.Fatalf("exchange before the key is published = %v, want ErrUnavailable{5s}", err)
	}
	waitTokenKeyPublished(h)
	user = writeSubject()

	first, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("first token: %v", err)
	}
	_, c := verifyWardenToken(t, h, first.AccessToken)
	switch {
	case c.Sub != "user-42" || c.Act.Sub != agentID || c.Scope != "read":
		t.Errorf("claims = sub %q act %q scope %q", c.Sub, c.Act.Sub, c.Scope)
	case c.Cnf.JKT != key.PublicJWK().Kid:
		t.Errorf("cnf.jkt = %q, want the enrolled thumbprint %q", c.Cnf.JKT, key.PublicJWK().Kid)
	case first.Lifetime() != 15*time.Minute || c.Exp-c.Iat != 900:
		t.Errorf("lifetime = %v (claims %d s), want 15 minutes", first.Lifetime(), c.Exp-c.Iat)
	}
	issued := len(h.TokenEvents())

	// Served from memory: no new exchange, no new record.
	h.Clock().Advance(5 * time.Second)
	if again, err := src.Token(context.Background()); err != nil || again.AccessToken != first.AccessToken || len(h.TokenEvents()) != issued {
		t.Fatalf("second call: %v, token changed or exchanged again", err)
	}

	// The refresh point is between 540s and 600s after receipt (2/3 of 900s,
	// up to 10% earlier). Step through it: the token changes once, inside it.
	start := h.Clock().Now()
	var second identityclient.WardenToken
	for second.AccessToken == "" {
		h.Clock().Advance(5 * time.Second)
		cur, err := src.Token(context.Background())
		if err != nil {
			t.Fatalf("token while approaching the refresh point: %v", err)
		}
		if cur.AccessToken != first.AccessToken {
			second = cur
		}
		if h.Clock().Now().Sub(start) > 15*time.Minute {
			t.Fatal("the token was never refreshed")
		}
	}
	if age := second.ReceivedAt.Sub(first.ReceivedAt); age < 540*time.Second || age > 605*time.Second {
		t.Errorf("refreshed %v after the first token, want 540s to 600s", age)
	}
	_, c2 := verifyWardenToken(t, h, second.AccessToken)
	if c2.SID != c.SID || c2.JTI == c.JTI {
		t.Errorf("refresh: sid %s jti %s, want sid %s and a fresh jti", c2.SID, c2.JTI, c.SID)
	}
	if n := len(h.TokenEvents()); n != issued+1 {
		t.Errorf("token events = %d, want %d (one record per exchange)", n, issued+1)
	}

	// A disabled agent is invalid_client; a fresh source gets nothing, and an
	// exchange is made once, not retried.
	h.DisableTokenAgent(agentID)
	var denied identityclient.ErrExchangeDenied
	h.Eventually("the control plane refuses the disabled agent", func() bool {
		h.Clock().Advance(3 * time.Second)
		fresh, _ := newSource()
		_, err := fresh.Token(context.Background())
		return errors.As(err, &denied)
	})
	if denied.Code != "invalid_client" {
		t.Errorf("disabled agent = %q, want invalid_client", denied.Code)
	}
	// The held token keeps working until its own exp, then the denial shows.
	h.Clock().Advance(10 * time.Minute)
	if cur, err := src.Token(context.Background()); err != nil || cur.AccessToken != second.AccessToken {
		t.Errorf("past the refresh point with the agent disabled: %v, want the held token", err)
	}
	h.Clock().Advance(10 * time.Minute)
	writeSubject()
	if _, err := src.Token(context.Background()); !errors.As(err, &denied) || denied.Code != "invalid_client" {
		t.Errorf("past exp = %v, want ErrExchangeDenied{invalid_client}", err)
	}
	requireNoCredentialsInLogs(t, h, user, first.AccessToken, second.AccessToken)
}
