package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/mcp/stdio"
	"github.com/ethosagent/warden/internal/scan"
)

// newMCPCmd builds the `warden mcp -- <server-cmd> [args...]` wedge: a stdio
// transport that fronts any MCP server. The MCP client spawns this command as if
// it were the server; warden reads the client's newline-delimited JSON-RPC from
// its own stdin, runs each message through the gateway, forwards allowed
// messages to the real server subprocess, and pumps the server's responses back
// through the gateway to warden's stdout. stdout is the data channel and stays
// clean JSON-RPC; the banner and all findings go to stderr.
func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp [flags] -- <server-cmd> [args...]",
		Short: "Front an MCP server over stdio, running all traffic through the gateway.",
		Long: "warden mcp wedges between an MCP client and an MCP server over stdio. " +
			"The client launches `warden mcp -- <server-cmd>` in place of the server; " +
			"warden pumps newline-delimited JSON-RPC through the gateway in both " +
			"directions. With the built-in default it watches everything and blocks " +
			"nothing (monitor); --mode enforce blocks denied tool calls before they " +
			"reach the server. stdout carries only forwarded JSON-RPC; findings and " +
			"the startup banner go to stderr.",
		// We parse args manually around the `--` separator.
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: false,
		RunE:               runMCP,
	}

	cmd.Flags().String("mode", "", "override the MCP mode: monitor|enforce (default: config or built-in monitor)")
	cmd.Flags().String("verify-sha256", "", "verify the server binary's SHA-256 (hex) before launch")
	// --config is inherited from the root persistent flag.

	return cmd
}

// runMCP wires the gateway + server subprocess and runs the stdio pump.
func runMCP(cmd *cobra.Command, args []string) error {
	dash := cmd.ArgsLenAtDash()
	if dash < 0 || dash >= len(args) {
		return fmt.Errorf("missing server command: usage: warden mcp [flags] -- <server-cmd> [args...]")
	}
	serverCmd := args[dash]
	serverArgs := args[dash+1:]

	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}
	modeOverride, err := cmd.Flags().GetString("mode")
	if err != nil {
		return err
	}
	verifySHA, err := cmd.Flags().GetString("verify-sha256")
	if err != nil {
		return err
	}

	mcpCfg, err := loadMCPConfig(cmd, configPath)
	if err != nil {
		return err
	}
	if m := strings.ToLower(strings.TrimSpace(modeOverride)); m != "" {
		mcpCfg.Mode = m
	}

	// Logger to STDERR — stdout is the JSON-RPC data channel and must stay clean.
	logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelInfo}))

	scanner := scan.NewScanner(scan.WithPhonePII(mcpCfg.Scan.PII.Phone), scan.WithEvidence(mcpCfg.Scan.Evidence))
	gw := gateway.New(mcpCfg, scanner, logger)

	// Verify the server binary before launch, if requested. Resolve the command
	// to an absolute path so the hash check targets the actual executable.
	resolved, lookErr := exec.LookPath(serverCmd)
	if lookErr != nil {
		return fmt.Errorf("resolve server command %q: %w", serverCmd, lookErr)
	}
	if verifySHA != "" {
		if verr := stdio.VerifyBinary(resolved, verifySHA); verr != nil {
			return verr
		}
		logger.Info("server binary integrity verified", "path", resolved)
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("warden mcp wedge starting",
		"mode", mcpCfg.Mode,
		"server", resolved,
		"verify", verifySHA != "",
	)

	srv := exec.CommandContext(ctx, resolved, serverArgs...) //nolint:gosec // operator-provided server command
	srv.Stderr = cmd.ErrOrStderr()                           // server diagnostics share warden's stderr
	serverStdin, err := srv.StdinPipe()
	if err != nil {
		return fmt.Errorf("server stdin pipe: %w", err)
	}
	serverStdout, err := srv.StdoutPipe()
	if err != nil {
		return fmt.Errorf("server stdout pipe: %w", err)
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("start server %q: %w", resolved, err)
	}

	pump := &stdio.Pump{GW: gw, SessionKey: "stdio", Log: logger}
	pumpErr := pump.Run(ctx, cmd.InOrStdin(), serverStdin, serverStdout, cmd.OutOrStdout())

	// Wait for the server to exit and surface its exit error. The pump returns
	// when both directions close; the server may already be done.
	waitErr := srv.Wait()

	if pumpErr != nil {
		return fmt.Errorf("mcp pump: %w", pumpErr)
	}
	if waitErr != nil && ctx.Err() == nil {
		return fmt.Errorf("mcp server exited: %w", waitErr)
	}
	return nil
}

// loadMCPConfig returns the MCP policy for the wedge. When configPath points to
// a readable config, its mcp block is used. When the config is absent or
// unreadable (e.g. the default example path on a fresh checkout) the wedge falls
// back to a built-in safe default: enabled, monitor mode, scanning + schema pin
// on — "watch everything, block nothing" so it fronts ANY server out of the box.
func loadMCPConfig(cmd *cobra.Command, configPath string) (config.MCPConfig, error) {
	provider, err := config.NewLocalYAMLProvider(configPath)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warden mcp: no usable config at %q (%v); using built-in monitor default\n", configPath, err)
		return defaultMCPConfig(), nil
	}
	pol, err := provider.GetPolicy()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warden mcp: config at %q is invalid (%v); using built-in monitor default\n", configPath, err)
		return defaultMCPConfig(), nil
	}
	if !pol.MCP.Enabled {
		// A config exists but its mcp block is disabled; the wedge still needs an
		// active gateway, so enable the built-in default while honoring the
		// config's scan/schema knobs where present.
		return defaultMCPConfig(), nil
	}
	return pol.MCP, nil
}

// defaultMCPConfig is the wedge's built-in safe default policy.
func defaultMCPConfig() config.MCPConfig {
	return config.MCPConfig{
		Enabled:              true,
		Mode:                 "monitor",
		MaxResponseScanBytes: 1 << 20,
		Schema:               config.MCPSchemaConfig{Pin: true},
		Scan: config.MCPScanConfig{
			ToolArgs:      true,
			ToolResults:   true,
			ProfileSchema: true,
		},
		Chain: config.MCPChainConfig{Enabled: true, WindowSize: 50},
	}
}
