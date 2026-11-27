package dashboard

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The 409 for a capability guard names the capability when the guard sets
// one (userlimits/v1), and the require-mode guard's body, which sets none, is
// byte-for-byte what it was before the field existed.
func TestWorkersLackCapabilityBody(t *testing.T) {
	for _, tc := range []struct {
		err  *WorkersLackCapabilityError
		want string
	}{
		{&WorkersLackCapabilityError{Workers: []string{"old"}}, `{"error":"workers_lack_capability","workers":["old"]}`},
		{&WorkersLackCapabilityError{Workers: []string{"a", "b"}, Capability: "userlimits/v1"}, `{"error":"workers_lack_capability","capability":"userlimits/v1","workers":["a","b"]}`},
	} {
		rec := httptest.NewRecorder()
		writeWriterError(rec, tc.err)
		if rec.Code != 409 || strings.TrimSpace(rec.Body.String()) != tc.want {
			t.Errorf("body = %d %s, want 409 %s", rec.Code, rec.Body.String(), tc.want)
		}
	}
}
