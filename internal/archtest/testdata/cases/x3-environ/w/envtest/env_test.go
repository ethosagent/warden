package envtest

import (
	"os"
	"testing"
)

func TestEnv(t *testing.T) { _ = os.Environ() }
