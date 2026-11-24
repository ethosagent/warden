package agentreg

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/keys"
)

// Field limits.
const (
	MaxKeys          = 2
	MaxJWKBytes      = 2048
	MaxScopes        = 32
	MaxDisplayRunes  = 128
	maxKIDBytes      = 128
	maxOwnerBytes    = 256
	maxActorBytes    = 256
	thumbprintPrefix = 8
)

var scopeRE = regexp.MustCompile(`^[a-z0-9:._-]{1,64}$`)

// rejectedMembers are JWK members that may never appear in a registered key,
// in the order they are reported: the private members of every key type, and
// the members that make a verifier fetch or trust something external.
var rejectedMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth", "x5u", "jku", "x5c"}

// Validate checks a and returns it normalized: groups and scopes sorted and
// de-duplicated, Status defaulted to active, and every key reduced to its
// canonical document with JKT, Alg and KID filled in. The input is not
// modified. Errors are *InvalidError (errors.Is ErrInvalid) naming the field.
//
// Revision and the audit fields are not validated here; the store owns them.
func Validate(a Agent) (Agent, error) {
	out := a
	if err := agentid.ValidID(a.ID); err != nil {
		return Agent{}, invalid("id", "must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
	}
	if out.Status == "" {
		out.Status = StatusActive
	}
	if !out.Status.Valid() {
		return Agent{}, invalid("status", "must be active or disabled")
	}
	if err := checkText("display_name", a.DisplayName, MaxDisplayRunes, true); err != nil {
		return Agent{}, err
	}
	for _, f := range []struct{ name, v string }{
		{"owner_iss", a.OwnerIss}, {"owner_sub", a.OwnerSub}, {"owner_email", a.OwnerEmail},
	} {
		if err := checkText(f.name, f.v, maxOwnerBytes, false); err != nil {
			return Agent{}, err
		}
	}
	groups, err := config.NormalizeGroups(a.AllowedGroups)
	if err != nil {
		return Agent{}, invalid("allowed_groups", "must be at most 256 non-empty values of at most 256 bytes")
	}
	if out.Status == StatusActive && len(groups) == 0 {
		return Agent{}, invalid("allowed_groups", "an active agent needs at least one group")
	}
	out.AllowedGroups = groups
	scopes, err := normalizeScopes(a.AllowedScopes)
	if err != nil {
		return Agent{}, err
	}
	out.AllowedScopes = scopes
	ks, err := validateKeys(a.Keys)
	if err != nil {
		return Agent{}, err
	}
	out.Keys = ks
	return out, nil
}

// checkText bounds a free-text field and rejects control characters. runes
// selects the unit of the limit.
func checkText(field, v string, limit int, runes bool) error {
	if !utf8.ValidString(v) {
		return invalid(field, "must be valid UTF-8")
	}
	n := len(v)
	if runes {
		n = utf8.RuneCountInString(v)
	}
	if n > limit {
		unit := "bytes"
		if runes {
			unit = "characters"
		}
		return invalid(field, fmt.Sprintf("must be at most %d %s", limit, unit))
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return invalid(field, "must not contain control characters")
		}
	}
	return nil
}

func normalizeScopes(in []string) ([]string, error) {
	if len(in) > MaxScopes {
		return nil, invalid("allowed_scopes", fmt.Sprintf("at most %d values", MaxScopes))
	}
	if len(in) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for i, s := range in {
		if !scopeRE.MatchString(s) {
			return nil, invalid(fmt.Sprintf("allowed_scopes[%d]", i), "must match ^[a-z0-9:._-]{1,64}$")
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func validateKeys(in []Key) ([]Key, error) {
	if len(in) < 1 || len(in) > MaxKeys {
		return nil, invalid("keys", fmt.Sprintf("an agent needs 1 to %d keys", MaxKeys))
	}
	out := make([]Key, len(in))
	kids := make(map[string]struct{}, len(in))
	jkts := make(map[string]struct{}, len(in))
	for i, k := range in {
		v, err := validateKey(i, k)
		if err != nil {
			return nil, err
		}
		if _, dup := kids[v.KID]; dup {
			return nil, invalid(fmt.Sprintf("keys[%d].kid", i), "duplicate kid within the agent")
		}
		if _, dup := jkts[v.JKT]; dup {
			return nil, invalid(fmt.Sprintf("keys[%d]", i), "the same key is listed twice")
		}
		kids[v.KID] = struct{}{}
		jkts[v.JKT] = struct{}{}
		out[i] = v
	}
	return out, nil
}

// validateKey checks one key through the internal/keys parser and returns its
// canonical form. Messages are fixed phrases: neither the parser's error text
// nor any member value is echoed.
func validateKey(i int, k Key) (Key, error) {
	path := func(member string) string { return fmt.Sprintf("keys[%d].%s", i, member) }
	if len(k.JWK) == 0 {
		return Key{}, invalid(path("jwk"), "missing")
	}
	if len(k.JWK) > MaxJWKBytes {
		return Key{}, invalid(fmt.Sprintf("keys[%d]", i), fmt.Sprintf("jwk is over %d bytes", MaxJWKBytes))
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(k.JWK, &members); err != nil || members == nil {
		return Key{}, invalid(fmt.Sprintf("keys[%d]", i), "jwk is not a json object")
	}
	for _, name := range rejectedMembers {
		for have := range members {
			if strings.EqualFold(have, name) {
				return Key{}, invalid(path(name), "member is not allowed in a registered public key")
			}
		}
	}
	if err := checkMembers(i, members); err != nil {
		return Key{}, err
	}
	j, err := keys.ParseJWK(k.JWK)
	if err != nil {
		return Key{}, invalid(fmt.Sprintf("keys[%d]", i), parseReason(err))
	}
	alg := keys.AlgEdDSA
	if j.Kty == "EC" {
		alg = keys.AlgES256
	}
	jkt, err := keys.Thumbprint(j)
	if err != nil {
		return Key{}, invalid(fmt.Sprintf("keys[%d]", i), "cannot compute the key thumbprint")
	}
	kid := k.KID
	if kid == "" {
		kid = j.Kid
	}
	if kid == "" {
		kid = jkt
	}
	if err := checkKID(kid); err != nil {
		return Key{}, invalid(path("kid"), err.Error())
	}
	canon := keys.JWK{Kty: j.Kty, Crv: j.Crv, X: j.X, Y: j.Y, Kid: kid, Alg: alg, Use: "sig"}
	doc, err := json.Marshal(canon)
	if err != nil {
		return Key{}, invalid(fmt.Sprintf("keys[%d]", i), "cannot encode the key")
	}
	return Key{KID: kid, JKT: jkt, Alg: alg, JWK: doc}, nil
}

// checkMembers validates the members the parser leaves open: use, key_ops and
// the algorithm and curve, so each failure names its own field.
func checkMembers(i int, members map[string]json.RawMessage) error {
	str := func(name string) (string, bool, error) {
		for have, raw := range members {
			if have != name {
				continue
			}
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return "", true, invalid(fmt.Sprintf("keys[%d].%s", i, name), "must be a string")
			}
			return s, true, nil
		}
		return "", false, nil
	}
	kty, _, err := str("kty")
	if err != nil {
		return err
	}
	crv, _, err := str("crv")
	if err != nil {
		return err
	}
	switch kty {
	case "OKP":
		if crv != "Ed25519" {
			return invalid(fmt.Sprintf("keys[%d].crv", i), "an OKP key must use Ed25519")
		}
	case "EC":
		if crv != "P-256" {
			return invalid(fmt.Sprintf("keys[%d].crv", i), "an EC key must use P-256")
		}
	default:
		return invalid(fmt.Sprintf("keys[%d].kty", i), "must be OKP (Ed25519) or EC (P-256)")
	}
	wantAlg := keys.AlgEdDSA
	if kty == "EC" {
		wantAlg = keys.AlgES256
	}
	if alg, ok, err := str("alg"); err != nil {
		return err
	} else if ok && alg != wantAlg {
		return invalid(fmt.Sprintf("keys[%d].alg", i), "does not match the key type")
	}
	if use, ok, err := str("use"); err != nil {
		return err
	} else if ok && use != "sig" {
		return invalid(fmt.Sprintf("keys[%d].use", i), "must be sig")
	}
	if raw, ok := members["key_ops"]; ok {
		var ops []string
		if err := json.Unmarshal(raw, &ops); err != nil || len(ops) != 1 || ops[0] != "verify" {
			return invalid(fmt.Sprintf("keys[%d].key_ops", i), "must be [\"verify\"]")
		}
	}
	return nil
}

// parseReason maps an internal/keys parse error to a fixed phrase that names
// the member group at fault and nothing the caller sent.
func parseReason(err error) string {
	switch {
	case errors.Is(err, keys.ErrAlgMismatch):
		return "alg does not match the key type"
	case errors.Is(err, keys.ErrUnsupportedAlg):
		return "unsupported key type or curve"
	case errors.Is(err, keys.ErrInvalidKey):
		return "not a valid public key (members x and y must be a point on the curve; no duplicate members)"
	default:
		return "not a valid public key"
	}
}

func checkKID(kid string) error {
	if len(kid) > maxKIDBytes {
		return fmt.Errorf("must be at most %d bytes", maxKIDBytes)
	}
	for i := 0; i < len(kid); i++ {
		if c := kid[i]; c <= 0x20 || c >= 0x7f {
			return errors.New("must be printable ASCII without spaces")
		}
	}
	return nil
}

func checkActor(actor string) error {
	if actor == "" {
		return invalid("actor", "must not be empty")
	}
	return checkText("actor", actor, maxActorBytes, false)
}

// thumbprintPrefixOf is the log-safe form of a thumbprint.
func thumbprintPrefixOf(jkt string) string {
	if len(jkt) > thumbprintPrefix {
		return jkt[:thumbprintPrefix]
	}
	return jkt
}
