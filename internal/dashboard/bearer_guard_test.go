package dashboard

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testBearerGuard(token string, lg *slog.Logger) WriteGuard {
	return NewBearerWriteGuard(BearerGuardConfig{
		Token: token, Logger: lg, Component: "worker", TokenName: "worker admin token",
		ConfigHint: "Start it with --admin-token-env <ENV> or admin.tokenEnv",
	})
}

func guardCall(g WriteGuard, auth string) (int, string) {
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return g(req)
}

func TestBearerWriteGuard_Decisions(t *testing.T) {
	g := testBearerGuard("s3cret", nil)
	if st, _ := guardCall(g, "Bearer s3cret"); st != 0 {
		t.Errorf("right token = %d, want 0 (allow)", st)
	}
	for _, auth := range []string{"", "Bearer wrong", "s3cret", "Bearer s3cret "} {
		if st, _ := guardCall(g, auth); st != http.StatusUnauthorized {
			t.Errorf("auth %q = %d, want 401", auth, st)
		}
	}
}

func TestBearerWriteGuard_FailsClosedWithoutToken(t *testing.T) {
	for _, tok := range []string{"", "   ", "\t\n"} {
		g := testBearerGuard(tok, nil)
		for _, auth := range []string{"", "Bearer ", "Bearer anything"} {
			st, msg := guardCall(g, auth)
			if st != http.StatusForbidden || !strings.Contains(msg, "--admin-token-env") || !strings.Contains(msg, "admin.tokenEnv") {
				t.Errorf("token %q auth %q = %d %q, want 403 naming the flag and config key", tok, auth, st, msg)
			}
		}
	}
}

func TestBearerWriteGuard_TrimsToken(t *testing.T) {
	g := testBearerGuard("s3cret\n", nil)
	if st, _ := guardCall(g, "Bearer s3cret"); st != 0 {
		t.Errorf("trimmed token rejected: %d", st)
	}
}

func TestBearerWriteGuard_LogsRefusalWithoutToken(t *testing.T) {
	var buf bytes.Buffer
	g := testBearerGuard("s3cret", slog.New(slog.NewTextHandler(&buf, nil)))
	guardCall(g, "Bearer leaked-guess")
	out := buf.String()
	if !strings.Contains(out, "worker dashboard write refused") || !strings.Contains(out, "/dashboard/api/policy") {
		t.Fatalf("refusal not logged: %q", out)
	}
	if strings.Contains(out, "leaked-guess") || strings.Contains(out, "s3cret") {
		t.Fatalf("log line contains a token: %q", out)
	}
}
