package compose

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
)

// AgentCurlArgs renders req as the argv for one `curl` run inside an agent
// container: the shim that makes an *http.Client ride the agent's own proxy
// env (HTTPS_PROXY=http://worker-N:8080) and trust the worker's MITM CA. The
// body, when present, is fed on stdin (`--data-binary @-`). h2 asks curl to
// negotiate HTTP/2 on the tunnel (the h2 scenarios' lever).
func AgentCurlArgs(req *http.Request, body []byte, h2 bool) ([]string, error) {
	if req.URL == nil {
		return nil, fmt.Errorf("compose: agent request %s has no URL", req.Method)
	}
	args := []string{
		"curl", "-s", "-i", "--max-time", AgentCurlMaxTime,
		"--cacert", AgentCABundle,
	}
	if h2 {
		args = append(args, "--http2")
	}
	args = append(args, "-X", req.Method)
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range req.Header[k] {
			args = append(args, "-H", k+": "+v)
		}
	}
	if len(body) > 0 {
		args = append(args, "--data-binary", "@-")
	}
	args = append(args, req.URL.String())
	return args, nil
}

// ParseCurlResponse parses `curl -s -i` output — status line, headers, body —
// into the *http.Response the harness agent client expects. The framing
// headers are stripped: curl has already decoded chunked bodies, so keeping
// "Transfer-Encoding" would make a reader de-chunk plain bytes.
func ParseCurlResponse(out []byte, req *http.Request) (*http.Response, error) {
	rest := out
	for {
		head, body, ok := splitHeaderBlock(rest)
		if !ok {
			return nil, fmt.Errorf("compose: curl produced no response header block (%d bytes: %.80q)", len(out), out)
		}
		resp, interim, err := parseResponseHead(head, body, req)
		if err != nil {
			return nil, err
		}
		if !interim {
			return resp, nil
		}
		rest = body // a 1xx interim response: parse the next block as the real one
	}
}

// splitHeaderBlock splits off one header block — INCLUDING its terminating
// blank line, which ReadMIMEHeader needs as the end-of-headers marker — and
// what follows it (the decoded body).
func splitHeaderBlock(out []byte) (head, body []byte, ok bool) {
	if i := bytes.Index(out, []byte("\r\n\r\n")); i >= 0 {
		return out[:i+4], out[i+4:], true
	}
	if i := bytes.Index(out, []byte("\n\n")); i >= 0 {
		return out[:i+2], out[i+2:], true
	}
	return nil, nil, false
}

// parseResponseHead parses one header block and attaches body. interim reports
// a 1xx response the caller must skip in favour of the next block.
func parseResponseHead(head, body []byte, req *http.Request) (*http.Response, bool, error) {
	s := string(head)
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return nil, false, fmt.Errorf("compose: curl response %q has no complete status line", s)
	}
	statusLine := strings.TrimRight(s[:nl], "\r")
	rest := s[nl+1:] // the header lines plus the terminating blank line
	parts := strings.SplitN(statusLine, " ", 2)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return nil, false, fmt.Errorf("compose: curl status line %q is not an HTTP status", statusLine)
	}
	codeStr := strings.TrimSpace(parts[1])
	if i := strings.IndexByte(codeStr, ' '); i >= 0 {
		codeStr = codeStr[:i]
	}
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return nil, false, fmt.Errorf("compose: curl status line %q: %v", statusLine, err)
	}
	proto := parts[0]
	if proto == "HTTP/2" { // curl's spelling; net/http's is HTTP/2.0
		proto = "HTTP/2.0"
	}
	major, minor := protoVersion(proto)

	mime, err := textproto.NewReader(bufio.NewReader(strings.NewReader(rest))).ReadMIMEHeader()
	if err != nil {
		return nil, false, fmt.Errorf("compose: parse curl response headers: %v", err)
	}
	hdr := http.Header(mime)
	// The body is the DECODED stream (curl's), so the framing headers would
	// only lie to a subsequent reader — drop them and mark the length unknown.
	hdr.Del("Transfer-Encoding")
	hdr.Del("Content-Length")

	resp := &http.Response{
		Status:        strings.TrimSpace(parts[1]),
		StatusCode:    code,
		Proto:         proto,
		ProtoMajor:    major,
		ProtoMinor:    minor,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: -1,
		Request:       req,
	}
	return resp, code >= 100 && code < 200, nil
}

// protoVersion splits a normalized "HTTP/x.y" into its major and minor.
func protoVersion(proto string) (major, minor int) {
	digits := strings.TrimPrefix(proto, "HTTP/")
	dot := strings.IndexByte(digits, '.')
	if dot < 0 {
		n, _ := strconv.Atoi(digits)
		return n, 0
	}
	major, _ = strconv.Atoi(digits[:dot])
	minor, _ = strconv.Atoi(digits[dot+1:])
	return major, minor
}

// ParseConnectStatus parses curl's %{http_connect} footer — the status of the
// proxy's reply to the CONNECT itself. "000" (no tunnel attempted) is an
// error, never a status.
func ParseConnectStatus(out string) (int, error) {
	code, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("compose: CONNECT probe produced no proxy status (curl wrote %q)", out)
	}
	return code, nil
}
