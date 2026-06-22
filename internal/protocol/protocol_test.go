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

func TestMCPString(t *testing.T) {
	if MCP.String() != "mcp" {
		t.Errorf("MCP.String() = %q, want %q", MCP.String(), "mcp")
	}
}

func TestIsMCP(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        string
		want        bool
	}{
		{
			name:        "valid tools/call",
			contentType: "application/json",
			body:        `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_search","arguments":{"query":"hello"}}}`,
			want:        true,
		},
		{
			name:        "valid tools/list",
			contentType: "application/json",
			body:        `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			want:        true,
		},
		{
			name:        "valid resources/read",
			contentType: "application/json",
			body:        `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///tmp/x"}}`,
			want:        true,
		},
		{
			name:        "valid initialize",
			contentType: "application/json",
			body:        `{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}`,
			want:        true,
		},
		{
			name:        "wrong content type",
			contentType: "text/html",
			body:        `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			want:        false,
		},
		{
			name:        "not json-rpc 2.0",
			contentType: "application/json",
			body:        `{"jsonrpc":"1.0","id":1,"method":"tools/call"}`,
			want:        false,
		},
		{
			name:        "non-MCP method",
			contentType: "application/json",
			body:        `{"jsonrpc":"2.0","id":1,"method":"some/other"}`,
			want:        false,
		},
		{
			name:        "empty body",
			contentType: "application/json",
			body:        "",
			want:        false,
		},
		{
			name:        "invalid json",
			contentType: "application/json",
			body:        `{not json`,
			want:        false,
		},
		{
			name:        "content type with charset",
			contentType: "application/json; charset=utf-8",
			body:        `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			want:        true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsMCP(tc.contentType, []byte(tc.body))
			if got != tc.want {
				t.Errorf("IsMCP(%q, %q) = %v, want %v", tc.contentType, tc.body, got, tc.want)
			}
		})
	}
}
