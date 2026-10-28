package proxy

import (
	"bufio"
	"bytes"
	"net/http"
	"testing"
)

// TestWriteErrorResponseAnnouncesClose pins #602: the h1 error responses end the
// keep-alive session, so they must carry Connection: close or a client reuses
// the dying conn and fails its next request with EOF.
func TestWriteErrorResponseAnnouncesClose(t *testing.T) {
	var buf bytes.Buffer
	writeErrorResponse(&buf, http.StatusForbidden, "Forbidden")
	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	// ReadResponse folds "Connection: close" into resp.Close.
	if !resp.Close {
		t.Error("error response lacks Connection: close")
	}
}
