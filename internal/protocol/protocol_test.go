package protocol

import "testing"

func TestDetect(t *testing.T) {
	cases := map[string]Protocol{
		"GET / HTTP/1.1\r\n":          HTTP,
		"POST /v1/chat HTTP/1.1\r\n":  HTTP,
		"CONNECT host:443 HTTP/1.1\r": HTTP,
		"\x16\x03\x01raw-tls-bytes":   Unknown,
		"":                            Unknown,
		"random garbage":              Unknown,
		"PRI * HTTP/2.0\r\n\r\n":      HTTP2,
	}
	for input, want := range cases {
		if got := Detect([]byte(input)); got != want {
			t.Errorf("Detect(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestProtocolString(t *testing.T) {
	if HTTP.String() != "http" {
		t.Errorf("HTTP.String() = %q", HTTP.String())
	}
	if Unknown.String() != "unknown" {
		t.Errorf("Unknown.String() = %q", Unknown.String())
	}
	if HTTP2.String() != "http2" {
		t.Errorf("HTTP2.String() = %q", HTTP2.String())
	}
}

func TestHTTPHandler(t *testing.T) {
	var h Handler = NewHTTPHandler()
	if h.Protocol() != HTTP {
		t.Errorf("handler protocol = %v, want HTTP", h.Protocol())
	}
}
