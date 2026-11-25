package identityclient

import "net/http"

// healthMux registers the forwarder's one route, GET /healthz (HEAD included),
// on a ServeMux: other paths get 404 and other methods 405 with Allow.
func healthMux(h http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", h)
	return mux
}
