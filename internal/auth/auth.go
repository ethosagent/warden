package auth

import "net/http"

// RequestTransformer modifies an outbound HTTP request for authentication.
type RequestTransformer interface {
	Transform(req *http.Request) error
}
