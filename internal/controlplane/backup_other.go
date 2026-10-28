//go:build !unix

package controlplane

import "math"

// diskFree has no portable implementation here: the free-space check passes.
func diskFree(string) (uint64, error) { return math.MaxUint64, nil }
