package oauthbroker

import "log/slog"

const redacted = "[REDACTED]"

// Secret holds a provider client secret. Every formatting path (String,
// GoString, slog LogValue, JSON and text marshalling) prints a placeholder;
// only Reveal returns the value, and only the code that sends it to the
// provider's token endpoint should call that.
type Secret struct{ p *string }

// NewSecret wraps v.
func NewSecret(v string) Secret { return Secret{p: &v} }

// Reveal returns the secret value.
func (s Secret) Reveal() string {
	if s.p == nil {
		return ""
	}
	return *s.p
}

// IsZero reports whether no secret is held.
func (s Secret) IsZero() bool { return s.p == nil || *s.p == "" }

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
