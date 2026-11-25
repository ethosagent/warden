package cpclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/workerca"
)

// maxResponseBytes caps what a certificate response may be.
const maxResponseBytes = 1 << 20

// maxChain bounds the chain a control plane may send above the leaf.
const maxChain = 4

// issuedResponse is the body of a 201 from /control/enroll and /control/renew.
type issuedResponse struct {
	WorkerID    string   `json:"workerId"`
	SpiffeID    string   `json:"spiffeId"`
	Certificate string   `json:"certificate"`
	Chain       []string `json:"chain"`
	Serial      string   `json:"serial"`
	NotAfter    string   `json:"notAfter"`
	PrevSerial  string   `json:"prevSerial,omitempty"`
}

// ControlPlaneError is a refusal from the control plane. Permanent says that
// retrying the same request cannot help (a rejected token, a refused CSR).
type ControlPlaneError struct {
	Status int
	// Code is the control plane's machine-readable error code, if it sent one.
	Code string
}

func (e *ControlPlaneError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("cpclient: control plane answered %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("cpclient: control plane answered %d", e.Status)
}

// Permanent reports whether the same request will keep failing: anything but a
// rate limit or a server error.
func (e *ControlPlaneError) Permanent() bool {
	return e.Status != http.StatusTooManyRequests && e.Status < 500
}

// IsPermanent reports whether err is a control plane refusal retrying cannot fix.
func IsPermanent(err error) bool {
	var cpe *ControlPlaneError
	return errors.As(err, &cpe) && cpe.Permanent()
}

// newKeyCSR returns a fresh P-256 key and its PEM certificate request. The
// request carries no subject: the control plane ignores everything but the key.
func newKeyCSR() (crypto.Signer, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", errors.New("cpclient: generate the worker key")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, "", errors.New("cpclient: create the certificate request")
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// post sends body as JSON and decodes a 201 into an issuedResponse. A transport
// failure or a non-201 is an error; the response body is never echoed except
// for the control plane's short error code.
func post(ctx context.Context, client *http.Client, url string, body any) (*issuedResponse, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("cpclient: encode the request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("cpclient: build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// The URL and the transport error carry no secret (the body is not in them).
		return nil, fmt.Errorf("cpclient: POST %s: %w", req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("cpclient: read the response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		cpe := &ControlPlaneError{Status: resp.StatusCode}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && len(e.Error) <= 64 {
			cpe.Code = e.Error
		}
		return nil, cpe
	}
	var out issuedResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, errors.New("cpclient: the control plane's response is not valid JSON")
	}
	return &out, nil
}

// verifyIssued is what a worker checks before it trusts or writes a certificate
// the control plane returned: the leaf was signed by Chain[0], each chain
// element by the next, the leaf is a client certificate whose SPIFFE id is the
// worker id the response names (and wantID, on a renewal), the leaf carries
// key's public key, and it is valid now. wantTrustDomain, when set, pins the
// trust domain a renewal must keep.
func verifyIssued(r *issuedResponse, key crypto.Signer, now time.Time, wantID, wantTrustDomain string) (*Credential, error) {
	leafs, err := workerca.ParseCertsPEM([]byte(r.Certificate))
	if err != nil || len(leafs) != 1 {
		return nil, errors.New("cpclient: the response carries no single worker certificate")
	}
	leaf := leafs[0]
	var chain []*x509.Certificate
	for _, p := range r.Chain {
		cs, err := workerca.ParseCertsPEM([]byte(p))
		if err != nil {
			return nil, errors.New("cpclient: the response chain does not parse")
		}
		chain = append(chain, cs...)
	}
	if len(chain) == 0 || len(chain) > maxChain {
		return nil, errors.New("cpclient: the response chain is empty or too long")
	}
	if err := leaf.CheckSignatureFrom(chain[0]); err != nil {
		return nil, errors.New("cpclient: the certificate is not signed by the chain's first certificate")
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, errors.New("cpclient: the response chain is not a chain: a certificate is not signed by the next")
		}
	}
	if leaf.IsCA || !hasClientAuth(leaf) {
		return nil, errors.New("cpclient: the certificate is not a client certificate")
	}
	if len(leaf.URIs) != 1 {
		return nil, errors.New("cpclient: the certificate carries no single SPIFFE id")
	}
	td := leaf.URIs[0].Host
	id, err := workerca.WorkerIDFromCert(leaf, td)
	if err != nil {
		return nil, errors.New("cpclient: the certificate's SPIFFE id is not a worker id")
	}
	switch {
	case r.WorkerID != id || r.SpiffeID != leaf.URIs[0].String():
		return nil, errors.New("cpclient: the response's worker id does not match the certificate")
	case wantID != "" && id != wantID:
		return nil, errors.New("cpclient: the certificate names a different worker id than the one renewing")
	case wantTrustDomain != "" && td != wantTrustDomain:
		return nil, errors.New("cpclient: the certificate is in a different trust domain than the one renewing")
	case !keyMatches(key, leaf):
		return nil, errors.New("cpclient: the certificate does not carry the key this worker generated")
	case !now.Before(leaf.NotAfter):
		return nil, errors.New("cpclient: the certificate is already expired")
	}
	return &Credential{Leaf: leaf, Chain: chain, Key: key, ReceivedAt: now}, nil
}

func hasClientAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
