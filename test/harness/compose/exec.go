//go:build e2e

package compose

import (
	"context"
	"os/exec"
)

// The one place this package touches os/exec, behind the e2e tag (like
// test/e2e's own plumbing): docker.go calls these two names only.

func execCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

type execExitError = exec.ExitError
