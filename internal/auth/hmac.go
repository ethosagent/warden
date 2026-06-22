package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

// HMACSigner computes an HMAC of the request body and sets the result as a
// header value.
type HMACSigner struct {
	secret    []byte
	header    string // e.g. "X-Signature-256"
	algorithm string // "sha256", "sha512", "sha1"
	hashFunc  func() hash.Hash
}

// NewHMACSigner creates an HMACSigner. algorithm must be "sha256", "sha512", or "sha1".
func NewHMACSigner(secret []byte, header, algorithm string) (*HMACSigner, error) {
	var hf func() hash.Hash
	switch algorithm {
	case "sha256":
		hf = sha256.New
	case "sha512":
		hf = sha512.New
	case "sha1":
		hf = sha1.New
	default:
		return nil, fmt.Errorf("auth: unsupported HMAC algorithm %q", algorithm)
	}
	return &HMACSigner{
		secret:    secret,
		header:    header,
		algorithm: algorithm,
		hashFunc:  hf,
	}, nil
}

// Transform reads the request body, computes the HMAC, sets the header, and
// resets the body so downstream consumers can still read it.
func (h *HMACSigner) Transform(req *http.Request) error {
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("auth: read body for HMAC: %w", err)
		}
	}

	mac := hmac.New(h.hashFunc, h.secret)
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set(h.header, sig)

	// Reset body
	if body != nil {
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		req.ContentLength = int64(len(body))
	}
	return nil
}
