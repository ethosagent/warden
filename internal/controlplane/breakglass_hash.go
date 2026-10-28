package controlplane

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/ethosagent/warden/internal/config"
)

// Break-glass password hashing: argon2id in the PHC string format. Hashes are
// produced offline by `warden control-plane hash-password` and only ever
// verified here; no password and no hash is logged or echoed in an error.
const (
	// Default (and produced) argon2id cost: 64 MiB, 3 passes, 2 lanes.
	phcDefaultMemory  uint32 = 64 * 1024
	phcDefaultTime    uint32 = 3
	phcDefaultThreads uint8  = 2
	phcSaltLen               = 16
	phcKeyLen                = 32

	// Accepted bounds when parsing a configured hash (a hostile or typo'd hash
	// must not make a login attempt allocate gigabytes).
	phcMinMemory  = 19456
	phcMaxMemory  = 262144
	phcMinTime    = 2
	phcMaxTime    = 10
	phcMinThreads = 1
	phcMaxThreads = 4
	phcMaxLen     = 512

	// MinBreakGlassPasswordRunes and MaxBreakGlassPasswordBytes bound a password
	// accepted for hashing.
	MinBreakGlassPasswordRunes = 16
	MaxBreakGlassPasswordBytes = 1024
)

// ErrPasswordTooShort and ErrPasswordTooLong are returned by HashPassword.
var (
	ErrPasswordTooShort = errors.New("password must be at least 16 characters")
	ErrPasswordTooLong  = errors.New("password must be at most 1024 bytes")
)

// PHC is a parsed argon2id hash.
type PHC struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	Salt    []byte
	Key     []byte
}

var phcB64 = base64.RawStdEncoding

// HashPassword returns the argon2id PHC string of password, with a 16-byte salt
// read from random.
func HashPassword(password string, random io.Reader) (string, error) {
	if len(password) > MaxBreakGlassPasswordBytes {
		return "", ErrPasswordTooLong
	}
	if utf8.RuneCountInString(password) < MinBreakGlassPasswordRunes {
		return "", ErrPasswordTooShort
	}
	salt := make([]byte, phcSaltLen)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", errors.New("phc: cannot read random salt")
	}
	p := PHC{Memory: phcDefaultMemory, Time: phcDefaultTime, Threads: phcDefaultThreads, Salt: salt}
	p.Key = argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, phcKeyLen)
	return p.String(), nil
}

// String renders the PHC form.
func (p PHC) String() string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, phcB64.EncodeToString(p.Salt), phcB64.EncodeToString(p.Key))
}

// ParsePHC accepts only argon2id v=19 within the bounds above. Every error is a
// fixed message that never echoes s.
func ParsePHC(s string) (PHC, error) {
	if len(s) > phcMaxLen {
		return PHC{}, errors.New("phc: too long")
	}
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" {
		return PHC{}, errors.New("phc: malformed")
	}
	if parts[1] != "argon2id" {
		return PHC{}, errors.New("phc: unsupported algorithm")
	}
	if parts[2] != "v=19" {
		return PHC{}, errors.New("phc: unsupported version")
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return PHC{}, errors.New("phc: malformed parameters")
	}
	m, okM := phcUint(params[0], "m=")
	t, okT := phcUint(params[1], "t=")
	pl, okP := phcUint(params[2], "p=")
	if !okM || !okT || !okP {
		return PHC{}, errors.New("phc: malformed parameters")
	}
	if m < phcMinMemory || m > phcMaxMemory {
		return PHC{}, errors.New("phc: memory out of range")
	}
	if t < phcMinTime || t > phcMaxTime {
		return PHC{}, errors.New("phc: time out of range")
	}
	if pl < phcMinThreads || pl > phcMaxThreads {
		return PHC{}, errors.New("phc: parallelism out of range")
	}
	salt, err := phcB64.DecodeString(parts[4])
	if err != nil {
		return PHC{}, errors.New("phc: malformed salt")
	}
	key, err := phcB64.DecodeString(parts[5])
	if err != nil {
		return PHC{}, errors.New("phc: malformed key")
	}
	if len(salt) < phcSaltLen {
		return PHC{}, errors.New("phc: salt too short")
	}
	if len(key) < phcKeyLen {
		return PHC{}, errors.New("phc: key too short")
	}
	return PHC{Memory: uint32(m), Time: uint32(t), Threads: uint8(pl), Salt: salt, Key: key}, nil
}

// phcUint parses prefix followed by a plain decimal (no sign, no spaces).
func phcUint(s, prefix string) (uint64, bool) {
	v, ok := strings.CutPrefix(s, prefix)
	if !ok || v == "" || len(v) > 9 {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 32)
	return n, err == nil
}

// Verify reports whether password matches, comparing in constant time.
func (p PHC) Verify(password string) bool {
	if len(p.Key) == 0 || len(p.Key) > phcMaxLen || len(password) > MaxBreakGlassPasswordBytes {
		return false
	}
	got := argon2.IDKey([]byte(password), p.Salt, p.Time, p.Memory, p.Threads, uint32(len(p.Key)))
	return subtle.ConstantTimeCompare(got, p.Key) == 1
}

var dummyPHC = sync.OnceValue(func() PHC {
	salt := []byte("warden-dummy-slt")
	p := PHC{Memory: phcDefaultMemory, Time: phcDefaultTime, Threads: phcDefaultThreads, Salt: salt}
	p.Key = argon2.IDKey([]byte("warden-dummy-password"), salt, p.Time, p.Memory, p.Threads, phcKeyLen)
	return p
})

// DummyPHC returns a fixed valid hash with the default parameters, so a login
// attempt with an unknown username spends the same time as a real verify.
func DummyPHC() PHC { return dummyPHC() }

// LoadBreakGlassHash reads the configured hash on every call (a mounted secret
// can rotate without a restart). Errors name the config key, never the value.
func LoadBreakGlassHash(cfg config.ConsoleBreakGlass) (PHC, error) {
	var raw, key string
	switch {
	case cfg.PasswordHashEnv != "" && cfg.PasswordHashFile == "":
		key = "console.breakGlass.passwordHashEnv"
		raw = os.Getenv(cfg.PasswordHashEnv)
		if strings.TrimSpace(raw) == "" {
			return PHC{}, errors.New(key + " is empty")
		}
	case cfg.PasswordHashFile != "" && cfg.PasswordHashEnv == "":
		key = "console.breakGlass.passwordHashFile"
		f, err := os.Open(cfg.PasswordHashFile)
		if err != nil {
			return PHC{}, errors.New(key + ": unreadable")
		}
		defer func() { _ = f.Close() }()
		b, err := io.ReadAll(io.LimitReader(f, phcMaxLen+2))
		if err != nil {
			return PHC{}, errors.New(key + ": unreadable")
		}
		raw = string(b)
		if strings.TrimSpace(raw) == "" {
			return PHC{}, errors.New(key + " is empty")
		}
	default:
		return PHC{}, errors.New("console.breakGlass: set exactly one of passwordHashEnv and passwordHashFile")
	}
	p, err := ParsePHC(strings.TrimRight(raw, " \t\r\n"))
	if err != nil {
		return PHC{}, fmt.Errorf("%s: %s", key, err.Error())
	}
	return p, nil
}
