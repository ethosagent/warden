package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
)

const echoTestValue = "AKIARTCANARY00000000"

// encodingsOf returns every form the guard must recognise for v, built here with
// the stdlib independently of the production needle builder.
func encodingsOf(v string) map[string]string {
	return map[string]string{
		"raw":            v,
		"b64std":         base64.StdEncoding.EncodeToString([]byte(v)),
		"b64std_nopad":   base64.RawStdEncoding.EncodeToString([]byte(v)),
		"b64url":         base64.URLEncoding.EncodeToString([]byte(v)),
		"b64url_nopad":   base64.RawURLEncoding.EncodeToString([]byte(v)),
		"url_upper":      url.QueryEscape(v),
		"url_lower":      lowerPercent(url.QueryEscape(v)),
		"url_path":       url.PathEscape(v),
		"hex_lower":      hex.EncodeToString([]byte(v)),
		"hex_upper":      strings.ToUpper(hex.EncodeToString([]byte(v))),
		"json_escaped":   testJSON(v, true),
		"json_noescapeH": testJSON(v, false),
	}
}

func lowerPercent(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = byte(strings.ToLower(string(b[i+1]))[0])
			b[i+2] = byte(strings.ToLower(string(b[i+2]))[0])
		}
	}
	return string(b)
}

func TestEchoSet_FindsEveryEncoding(t *testing.T) {
	// A value with characters every escaper rewrites.
	for _, v := range []string{echoTestValue, "p@ss/w0rd+x=y z&<q>\"é\\"} {
		set := newEchoSet([]string{v})
		for name, enc := range encodingsOf(v) {
			if enc == v && name != "raw" {
				continue // this encoding is the identity for this value
			}
			if _, ok := set.find([]byte("xx" + enc + "yy")); !ok {
				t.Errorf("value %q: encoding %s (%q) not found", v, name, enc)
			}
		}
		if _, ok := set.find([]byte("nothing to see here")); ok {
			t.Errorf("value %q: false positive", v)
		}
	}
}

// A value embedded inside a larger base64 string (e.g. Basic auth "user:value")
// lands on any of three 6-bit alignments; each must still be found.
func TestEchoSet_FindsBase64AtEveryAlignment(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	for _, prefix := range []string{"u:", "us:", "usr:", "user:", "userx:"} {
		for _, suffix := range []string{"", "!", "!!", "!!!"} {
			raw := []byte(prefix + echoTestValue + suffix)
			for name, enc := range map[string]string{
				"std": base64.StdEncoding.EncodeToString(raw),
				"url": base64.URLEncoding.EncodeToString(raw),
			} {
				if _, ok := set.find([]byte("Basic " + enc)); !ok {
					t.Errorf("prefix %q suffix %q %s: not found in %q", prefix, suffix, name, enc)
				}
			}
		}
	}
}

func TestEchoSet_ReportsWhichSecret(t *testing.T) {
	set := newEchoSet([]string{"first-secret-value", "second-secret-value"})
	idx, ok := set.find([]byte("..second-secret-value.."))
	if !ok || idx != 1 {
		t.Fatalf("find = (%d, %v), want (1, true)", idx, ok)
	}
}

func TestEchoSet_EmptyValueIgnored(t *testing.T) {
	set := newEchoSet([]string{""})
	if _, ok := set.find([]byte("anything")); ok {
		t.Fatal("an empty value must never match")
	}
}

// oneByteReader hands out one byte per Read, the worst case for a value split
// across chunks.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func TestEchoReader_PassesCleanStreamUnchanged(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	src := strings.Repeat("clean data ", 500)
	r := newEchoReader(io.NopCloser(oneByteReader{strings.NewReader(src)}), set, nil)
	got, err := io.ReadAll(r)
	if err != nil || string(got) != src {
		t.Fatalf("clean stream altered: err=%v len=%d want %d", err, len(got), len(src))
	}
}

func TestEchoReader_BlocksValueSplitAcrossChunks(t *testing.T) {
	for name, enc := range encodingsOf(echoTestValue) {
		set := newEchoSet([]string{echoTestValue})
		src := strings.Repeat("a", 100) + enc + strings.Repeat("b", 100)
		hits := 0
		r := newEchoReader(io.NopCloser(oneByteReader{strings.NewReader(src)}), set, func(int) { hits++ })
		got, err := io.ReadAll(r)
		if !errors.Is(err, errEchoBlocked) {
			t.Fatalf("%s: err = %v, want errEchoBlocked", name, err)
		}
		if hits != 1 {
			t.Fatalf("%s: onHit called %d times, want 1", name, hits)
		}
		if bytes.Contains(got, []byte(enc)) {
			t.Fatalf("%s: the encoded value was released to the consumer", name)
		}
		if len(got) >= len(src) {
			t.Fatalf("%s: stream was not cut", name)
		}
	}
}

// The chunk that contains the (whole) value is never released, even when it
// arrives in one Read.
func TestEchoReader_WithholdsHitChunk(t *testing.T) {
	set := newEchoSet([]string{echoTestValue})
	r := newEchoReader(io.NopCloser(strings.NewReader("prefix "+echoTestValue+" suffix")), set, nil)
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if n != 0 || !errors.Is(err, errEchoBlocked) {
		t.Fatalf("Read = (%d, %v), want (0, errEchoBlocked)", n, err)
	}
}

func testJSON(v string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(v)
	return strings.TrimSuffix(strings.Trim(strings.TrimSpace(b.String()), `"`), "")
}
