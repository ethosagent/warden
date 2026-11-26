package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ethosagent/warden/internal/keys"
)

// errNoBundlePins is the load error of a control-plane-managed worker that
// requires signed bundles (the default) and pins no keys. It never falls back
// to unsigned policy: the operator must pin keys or opt out in writing.
const errNoBundlePins = "config: controlPlane.requireSignedBundles is true (the default since the Phase 2 release) but controlPlane.bundleKeys and controlPlane.bundleKeysFile pin no keys: " +
	"export the control plane's bundle keys with `warden control-plane keys export --purpose bundle` and set controlPlane.bundleKeysFile, " +
	"or, only temporarily, set controlPlane.requireSignedBundles: false to take unsigned policy (see docs/control-plane.md, Upgrading to required signed bundles)"

// maxBundleKeys bounds the pin set: inline and file keys together.
const maxBundleKeys = 16

// parseBundleOptions fills the signed-bundle fields of c from r: defaults,
// the skew and expiry values, and the merged, validated pin set.
func parseBundleOptions(r *rawControlPlane, c *ControlPlaneConfig) error {
	// Signed bundles are required unless the operator opts out explicitly.
	c.RequireSignedBundles = r.RequireSignedBundles == nil || *r.RequireSignedBundles
	c.BundleIssuer = strings.TrimSpace(r.BundleIssuer)
	c.BundleClockSkew = defaultBundleClockSkew
	if err := parseDurationField("controlPlane.bundleClockSkew", r.BundleClockSkew, &c.BundleClockSkew); err != nil {
		return err
	}
	if c.BundleClockSkew > maxBundleClockSkew {
		return fmt.Errorf("config: controlPlane.bundleClockSkew %s exceeds the maximum %s", c.BundleClockSkew, maxBundleClockSkew)
	}
	switch BundleExpiry(r.BundleExpiry) {
	case "":
		c.BundleExpiry = BundleExpiryKeep
	case BundleExpiryKeep, BundleExpiryDeny:
		c.BundleExpiry = BundleExpiry(r.BundleExpiry)
	default:
		return fmt.Errorf("config: controlPlane.bundleExpiry %q must be %q or %q", r.BundleExpiry, BundleExpiryKeep, BundleExpiryDeny)
	}

	total := len(r.BundleKeys)
	var fileDocs []json.RawMessage
	if path := strings.TrimSpace(r.BundleKeysFile); path != "" {
		docs, err := readPinFile(path)
		if err != nil {
			return err
		}
		fileDocs = docs
		total += len(docs)
	}
	if total > maxBundleKeys {
		return fmt.Errorf("config: controlPlane.bundleKeys and bundleKeysFile pin %d keys, the maximum is %d", total, maxBundleKeys)
	}

	var pins []keys.JWK
	seen := map[string]string{} // kid -> where it was first declared
	add := func(field string, i int, doc []byte) error {
		where := fmt.Sprintf("%s[%d]", field, i)
		jwk, err := parsePin(where, doc)
		if err != nil {
			return err
		}
		if prev, dup := seen[jwk.Kid]; dup {
			return fmt.Errorf("config: %s has the same kid as %s", where, prev)
		}
		seen[jwk.Kid] = where
		pins = append(pins, jwk)
		return nil
	}
	for i, m := range r.BundleKeys {
		doc, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("config: controlPlane.bundleKeys[%d] is not a JWK object", i)
		}
		if err := add("controlPlane.bundleKeys", i, doc); err != nil {
			return err
		}
	}
	for i, doc := range fileDocs {
		if err := add("controlPlane.bundleKeysFile", i, doc); err != nil {
			return err
		}
	}
	c.BundleKeys = pins
	return nil
}

// readPinFile reads a JWKS document and returns each key as raw JSON, so
// keys.ParseJWK sees the original members.
func readPinFile(path string) ([]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("config: controlPlane.bundleKeysFile %q: %w", path, err)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil || set.Keys == nil {
		return nil, fmt.Errorf("config: controlPlane.bundleKeysFile %q is not a JWKS document with a \"keys\" array", path)
	}
	return set.Keys, nil
}

// privateMembers are the JWK members that carry private key material for some
// kty. keys.ParseJWK rejects "d"; the rest are rejected here on any kty.
var privateMembers = map[string]bool{"d": true, "p": true, "q": true, "dp": true, "dq": true, "qi": true, "k": true}

// parsePin parses one pin through keys.ParseJWK (public members only, valid
// type and point) and requires kid to be its RFC 7638 thumbprint. Errors name
// where and never carry key material.
func parsePin(where string, doc []byte) (keys.JWK, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(doc, &members); err == nil {
		for name := range members {
			if m := strings.ToLower(name); privateMembers[m] {
				return keys.JWK{}, fmt.Errorf("config: %s: private member %q is not allowed in a pinned key", where, m)
			}
		}
	}
	jwk, err := keys.ParseJWK(doc)
	if err != nil {
		return keys.JWK{}, fmt.Errorf("config: %s: %w", where, err)
	}
	tp, err := keys.Thumbprint(jwk)
	if err != nil {
		return keys.JWK{}, fmt.Errorf("config: %s: %w", where, err)
	}
	if jwk.Kid != tp {
		return keys.JWK{}, fmt.Errorf("config: %s: kid must be the key's RFC 7638 thumbprint %q", where, tp)
	}
	return jwk, nil
}
