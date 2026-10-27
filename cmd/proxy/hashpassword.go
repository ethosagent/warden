package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ethosagent/warden/internal/controlplane"
)

// maxPasswordLine bounds the one line read with --stdin (1 KiB).
const maxPasswordLine = 1024

// newHashPasswordCmd builds `warden control-plane hash-password`: it turns a
// password into the argon2id PHC string that console.breakGlass reads from an
// env var or file. There is no password flag (argv is visible to other
// processes); the password comes from a terminal prompt or one line on stdin.
// Only the PHC string reaches stdout; prompts go to stderr. It stays thin (rule
// C1): hashing and the password rules live in internal/controlplane.
func newHashPasswordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hash-password",
		Short: "Print the argon2id hash of a break-glass password.",
		Long: "Read a password (at least 16 characters) and print its argon2id PHC hash, " +
			"for console.breakGlass.passwordHashEnv or passwordHashFile. Without --stdin " +
			"the password is read from the terminal with echo off and asked twice; with " +
			"--stdin exactly one line is read. The password is never taken from a flag.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fromStdin, _ := cmd.Flags().GetBool("stdin")
			var pw string
			var err error
			if fromStdin {
				pw, err = readPasswordLine(cmd.InOrStdin())
			} else {
				pw, err = promptPassword(cmd)
			}
			if err != nil {
				return usageErr(err)
			}
			phc, err := controlplane.HashPassword(pw, rand.Reader)
			if err != nil {
				return usageErr(err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), phc)
			return err
		},
	}
	cmd.Flags().Bool("stdin", false, "read the password as one line from stdin instead of prompting")
	quiet(cmd)
	return cmd
}

// readPasswordLine reads one line (at most maxPasswordLine bytes before the
// newline) and strips the trailing CR/LF.
func readPasswordLine(in io.Reader) (string, error) {
	buf, err := io.ReadAll(io.LimitReader(in, maxPasswordLine+2))
	if err != nil {
		return "", errors.New("cannot read the password from stdin")
	}
	line, _, _ := bytes.Cut(buf, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(line) > maxPasswordLine {
		return "", controlplane.ErrPasswordTooLong
	}
	return string(line), nil
}

// promptPassword asks twice on the terminal with echo off.
func promptPassword(cmd *cobra.Command) (string, error) {
	f, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", errors.New("stdin is not a terminal; use --stdin")
	}
	ask := func(prompt string) (string, error) {
		_, _ = fmt.Fprint(cmd.ErrOrStderr(), prompt)
		b, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", errors.New("cannot read the password from the terminal")
		}
		return string(b), nil
	}
	first, err := ask("Password: ")
	if err != nil {
		return "", err
	}
	second, err := ask("Confirm password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passwords do not match")
	}
	return first, nil
}
