package apikeys

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	g, err := Generate(nil)
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
		g, err := Generate(nil)
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
	g, _ := Generate(nil)
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
	g, err := Generate(func(string) bool { calls++; return calls <= 3 })
	if err != nil || calls != 4 {
		t.Fatalf("Generate: err %v after %d probes, want success on the 4th", err, calls)
	}
	if _, err := Generate(func(string) bool { return true }); err == nil {
		t.Fatal("Generate with every id taken returned no error")
	}
	_ = g
}

func TestGeneratedNeverPrintsPlaintext(t *testing.T) {
	g, _ := Generate(nil)
	secret := g.Plaintext[sepOffset+1:]
	for _, s := range []string{fmt.Sprint(g), fmt.Sprintf("%v %+v %#v", g, g, g)} {
		if strings.Contains(s, secret) || strings.Contains(s, g.Plaintext) {
			t.Fatalf("formatted Generated leaks the key: %s", s)
		}
	}
}
