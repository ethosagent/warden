package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
)

// cliFailRecorder fails every audit append.
type cliFailRecorder struct{}

func (cliFailRecorder) Record(context.Context, adminaudit.Input) (adminaudit.Entry, error) {
	return adminaudit.Entry{}, errors.New("disk full")
}

func openOffline(t *testing.T) *OfflineWorkerTokens {
	t.Helper()
	o, err := OpenWorkerTokensOffline(context.Background(), filepath.Join(t.TempDir(), "state"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

// TestOfflineWorkerTokensAuditFailureRevokes: an audit append that fails after
// a create leaves no usable token; a failed revoke audit reports it.
func TestOfflineWorkerTokensAuditFailureRevokes(t *testing.T) {
	ctx := context.Background()
	o := openOffline(t)
	o.rec = cliFailRecorder{}
	out := filepath.Join(t.TempDir(), "t")
	if _, err := o.Create(ctx, OfflineCreate{Name: "a", ProxyID: "p", OutFile: out}); err == nil || !strings.Contains(err.Error(), "token not kept") {
		t.Fatalf("create err = %v", err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("--out file left behind: %v", err)
	}
	toks, _ := o.List(ctx)
	if len(toks) != 1 || toks[0].RevokedAt.IsZero() {
		t.Fatalf("tokens = %+v, want the one revoked", toks)
	}

	o.rec = nil
	tok, err := o.Create(ctx, OfflineCreate{Name: "b", ProxyID: "p"})
	if err != nil {
		t.Fatal(err)
	}
	o.rec = cliFailRecorder{}
	if _, changed, err := o.Revoke(ctx, tok.Token.ID); err == nil || !changed {
		t.Errorf("revoke with a failing audit = changed %v err %v", changed, err)
	}
}

func TestOfflineWorkerTokensValidation(t *testing.T) {
	ctx := context.Background()
	o := openOffline(t)
	if _, err := o.Create(ctx, OfflineCreate{Name: "a", ProxyID: "p", ExpiresIn: -time.Hour}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("negative expiry err = %v", err)
	}
	if _, err := o.Create(ctx, OfflineCreate{Name: "a", ProxyID: "bad id"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("bad proxy id err = %v", err)
	}
	if _, err := OpenWorkerTokensOffline(ctx, "", ""); err == nil {
		t.Error("empty state dir accepted")
	}
	if _, err := OpenWorkerTokensOfflineReadOnly(ctx, ""); err == nil {
		t.Error("empty state dir accepted read-only")
	}
}

func TestWriteWorkerTokenList(t *testing.T) {
	ctx := context.Background()
	o := openOffline(t)
	res, err := o.Create(ctx, OfflineCreate{Name: "a", ProxyID: "p", ExpiresIn: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Revoke(ctx, res.Token.ID); err != nil {
		t.Fatal(err)
	}
	toks, _ := o.List(ctx)
	for _, asJSON := range []bool{false, true} {
		var b bytes.Buffer
		if err := WriteWorkerTokenList(&b, toks, asJSON); err != nil {
			t.Fatal(err)
		}
		if got := b.String(); !strings.Contains(got, "revoked") || strings.Contains(got, res.Plaintext) {
			t.Errorf("json=%v output = %q", asJSON, got)
		}
	}
	if got := tokenStatus(Token{ExpiresAt: time.Unix(1, 0)}, time.Now()); got != "expired" {
		t.Errorf("status = %q", got)
	}
}
