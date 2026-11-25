package apikeys

import (
	"bytes"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

// testRand is a deterministic entropy source for tests.
func testRand(seed byte) io.Reader {
	var key [32]byte
	key[0] = seed
	return mrand.NewChaCha8(key)
}

func TestParse(t *testing.T) {
	rd := testRand(1)
	g, err := Generate(rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := g.Plaintext
	secret := valid[sepOffset+1:]
	id := valid[len(Prefix):sepOffset]

	bad := map[string]string{
		"empty":            "",
		"worker token":     "wwt_" + strings.Repeat("a", 52),
		"uppercase prefix": "WAK_" + valid[len(Prefix):],
		"72 chars":         valid[:Length-1],
		"74 chars":         valid + "a",
		"dash in secret":   valid[:sepOffset+1] + "-" + secret[1:],
		"equals in secret": valid[:sepOffset+1] + "=" + secret[1:],
		"digit 1":          valid[:sepOffset+1] + "1" + secret[1:],
		"digit 0":          valid[:sepOffset+1] + "0" + secret[1:],
		"uppercase secret": valid[:sepOffset+1] + "A" + secret[1:],
		"no separator":     valid[:sepOffset] + "a" + secret,
		"uppercase id":     Prefix + strings.ToUpper(id) + "_" + secret,
		"non-hex id":       Prefix + "g" + id[1:] + "_" + secret,
		"space":            valid[:Length-1] + " ",
		"non-canonical":    valid[:Length-1] + "b",
		"extra separator":  Prefix + id + "__" + secret[1:],
	}
	for name, in := range bad {
		if _, err := Parse(in); err != ErrMalformed {
			t.Errorf("%s: Parse = %v, want ErrMalformed", name, err)
		}
	}

	for range 200 {
		g, err := Generate(rd, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(g.Plaintext) != Length || Length != 73 {
			t.Fatalf("length = %d, want 73", len(g.Plaintext))
		}
		got, err := Parse(g.Plaintext)
		if err != nil || got != g.ID {
			t.Fatalf("round trip: id %q err %v, want %q", got, err, g.ID)
		}
		if _, h, _ := parse(g.Plaintext); h != g.hash {
			t.Fatal("Parse hash differs from the Generate hash")
		}
		if !regexp.MustCompile(`^` + Pattern + `$`).MatchString(g.Plaintext) {
			t.Fatalf("Pattern does not match a generated key")
		}
	}
}

func TestLooksLikeKey(t *testing.T) {
	g, _ := Generate(testRand(2), nil)
	for in, want := range map[string]bool{
		g.Plaintext:       true,
		"wak_":            true, // prefix only: a truncated key still routes to the key path
		"wak_garbage":     true,
		"wwt_" + "a":      false,
		"WAK_" + "a":      false,
		"":                false,
		"Bearer wak_abcd": false,
	} {
		if got := LooksLikeKey(in); got != want {
			t.Errorf("LooksLikeKey(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestGenerateRetriesOnCollision(t *testing.T) {
	calls := 0
	g, err := Generate(testRand(3), func(string) bool { calls++; return calls <= 3 })
	if err != nil || calls != 4 {
		t.Fatalf("Generate: err %v after %d probes, want success on the 4th", err, calls)
	}
	if _, err := Generate(testRand(3), func(string) bool { return true }); err == nil {
		t.Fatal("Generate with every id taken returned no error")
	}
	_ = g
}

func TestGeneratedNeverPrintsPlaintext(t *testing.T) {
	g, _ := Generate(testRand(4), nil)
	secret := g.Plaintext[sepOffset+1:]
	for _, s := range []string{fmt.Sprint(g), fmt.Sprintf("%v %+v %#v", g, g, g)} {
		if strings.Contains(s, secret) || strings.Contains(s, g.Plaintext) {
			t.Fatalf("formatted Generated leaks the key: %s", s)
		}
	}
}

func TestGenerateRandomSourceFailure(t *testing.T) {
	if _, err := Generate(bytes.NewReader([]byte{1, 2, 3}), nil); err == nil {
		t.Fatal("Generate with a short entropy source returned no error")
	}
}

func TestStorageHashMatchesParse(t *testing.T) {
	g, _ := Generate(testRand(5), nil)
	if _, h, err := parse(g.Plaintext); err != nil || h != g.StorageHash() {
		t.Fatalf("StorageHash differs from the hash Parse derives: %v", err)
	}
}

// FuzzParse: Parse never panics, and an input it accepts is exactly a key
// shape (length, prefix, alphabet) whose id and hash are stable.
func FuzzParse(f *testing.F) {
	g, _ := Generate(testRand(6), nil)
	for _, seed := range []string{"", Prefix, g.Plaintext, g.Plaintext[:Length-1], g.Plaintext + "a",
		"WAK_" + g.Plaintext[len(Prefix):], Prefix + "0000000000000000_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		id, h, err := parse(in)
		if err != nil {
			if err != ErrMalformed {
				t.Fatalf("parse error = %v, want ErrMalformed", err)
			}
			return
		}
		if len(in) != Length || !LooksLikeKey(in) || in[len(Prefix):sepOffset] != id {
			t.Fatalf("accepted a non-key %q", in)
		}
		id2, err := Parse(in)
		if err != nil || id2 != id {
			t.Fatalf("Parse disagrees with parse: %q %v", id2, err)
		}
		if _, h2, _ := parse(in); h2 != h {
			t.Fatal("hash not stable")
		}
	})
}
