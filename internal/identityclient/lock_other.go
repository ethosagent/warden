//go:build !unix

package identityclient

import "errors"

// lockFile is not implemented off unix: the cache needs an exclusive lock to
// stay safe under concurrent refreshes, so the client refuses to run.
func lockFile(string) (func(), error) {
	return nil, errors.New("identityclient: the token cache lock is supported on unix platforms only")
}
