package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// newPolicyCmd builds the `warden policy` parent command.
func newPolicyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "policy",
		Short: "Policy inspection and suggestion tools.",
	}
}

// parseDuration parses human-friendly durations like "7d", "30d", "24h".
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid day duration: %s", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
