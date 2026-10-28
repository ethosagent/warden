package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"
)

// TestConnSinkErrorsAreConnectionClose: every terminal h1 error the proxy
// writes ends the session, so it must say Connection: close. Without it a
// keep-alive client can send its next request on the conn the proxy is closing
// and see EOF instead of a response.
func TestConnSinkErrorsAreConnectionClose(t *testing.T) {
	for name, write := range map[string]func(io.Writer){
		"errorResponse": func(w io.Writer) { connSink{w: w}.errorResponse(http.StatusForbidden, "Forbidden") },
		"errorJSON":     func(w io.Writer) { connSink{w: w}.errorJSON(http.StatusForbidden, `{"error":"x"}`) },
	} {
		var buf bytes.Buffer
		write(&buf)
		resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", name, resp.StatusCode)
		}
		if !resp.Close {
			t.Errorf("%s: response is not Connection: close", name)
		}
	}
}
