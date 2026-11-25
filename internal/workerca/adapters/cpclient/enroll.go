package cpclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// ErrNoToken is returned when the worker has no usable certificate and no
// enrollment token to get one with.
var ErrNoToken = errors.New("cpclient: no usable worker certificate and no enrollment token")

// Enroller trades an enrollment token for a worker certificate (POST
// /control/enroll), or reuses the certificate persisted in the state directory.
type Enroller struct {
	// Endpoint is the full URL of /control/enroll.
	Endpoint string
	// HTTP must present no client certificate: the token is the credential. It
	// verifies the control plane's TLS certificate like the worker's other
	// control-plane connections do.
	HTTP *http.Client
	// StateDir holds cert/worker-key.pem and cert/worker-cert.pem.
	StateDir string
	// Token is the wet_ token, read from the environment once by the caller. It
	// is never logged.
	Token string
	// Suffix is the worker id suffix a prefix-bound token appends to its prefix.
	Suffix string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Logger receives the (secret-free) reasons a persisted certificate was not
	// reused. May be nil.
	Logger *slog.Logger
}

func (e *Enroller) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// LoadOrEnroll returns the persisted certificate when it is still valid (no
// request is made), and otherwise enrolls: it generates a new P-256 key, posts
// its CSR with the token, verifies the response and persists key and
// certificate. A control plane refusal that retrying cannot fix is reported as
// a *ControlPlaneError for which IsPermanent is true.
func (e *Enroller) LoadOrEnroll(ctx context.Context) (*Credential, error) {
	if err := ensureDirs(e.StateDir); err != nil {
		return nil, err
	}
	now := e.now()
	cred, err := loadPersisted(e.StateDir, now)
	switch {
	case err != nil:
		e.log("the persisted worker certificate is unusable; enrolling again", "error", err.Error())
	case cred != nil && cred.Expired(now):
		e.log("the persisted worker certificate has expired; enrolling again", "serial", cred.Serial())
	case cred != nil:
		return cred, nil
	}
	if e.Token == "" {
		return nil, ErrNoToken
	}
	key, csr, err := newKeyCSR()
	if err != nil {
		return nil, err
	}
	resp, err := post(ctx, e.HTTP, e.Endpoint, map[string]string{"token": e.Token, "csr": csr, "workerIdSuffix": e.Suffix})
	if err != nil {
		return nil, fmt.Errorf("cpclient: enroll: %w", err)
	}
	got, err := verifyIssued(resp, key, e.now(), "", "")
	if err != nil {
		return nil, fmt.Errorf("cpclient: enroll: %w", err)
	}
	if err := persist(e.StateDir, got); err != nil {
		return nil, err
	}
	return got, nil
}

func (e *Enroller) log(msg string, args ...any) {
	if e.Logger != nil {
		e.Logger.Warn("worker cert: "+msg, args...)
	}
}
