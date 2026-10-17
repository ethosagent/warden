package envtest

import "os"

func Env() []string { return os.Environ() }
