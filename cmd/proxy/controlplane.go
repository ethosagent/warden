package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/observability"
)

// newControlPlaneCmd builds the `control-plane` subcommand. The control plane
// serves allow/deny policy to data-plane workers and aggregates their analytics
// for a fleet dashboard. It is the same binary as the worker but a distinct
// role and process, so it can later be deployed on a separate host with no code
// change. It deliberately serves policy ONLY — secrets never cross this boundary.
func newControlPlaneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control-plane",
		Short: "Serve allow/deny policy to workers and aggregate fleet analytics.",
		Long: "Run Warden as a control plane: it serves allow/deny policy to " +
			"data-plane workers (which pull and hot-reload it) and ingests their " +
			"analytics into a fleet dashboard. Policy only — secrets never cross " +
			"this boundary. Provide --ca-cert/--ca-key to serve HTTPS with a cert " +
			"minted from that CA (workers trust it via controlPlane.caCert).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			listenAddr, _ := cmd.Flags().GetString("listen")
			tokenEnv, _ := cmd.Flags().GetString("token-env")
			caCert, _ := cmd.Flags().GetString("ca-cert")
			caKey, _ := cmd.Flags().GetString("ca-key")
			tlsHost, _ := cmd.Flags().GetString("tls-host")
			maxEvents, _ := cmd.Flags().GetInt("central-max-events")
			return runControlPlane(cmd, configPath, listenAddr, tokenEnv, caCert, caKey, tlsHost, maxEvents)
		},
	}
	cmd.Flags().String("listen", "0.0.0.0:7070", "control-plane HTTP(S) listen address")
	cmd.Flags().String("token-env", "", "env var holding the bearer token workers must present")
	cmd.Flags().String("ca-cert", "", "CA cert to mint the server TLS cert from (enables HTTPS)")
	cmd.Flags().String("ca-key", "", "CA key to mint the server TLS cert from")
	cmd.Flags().String("tls-host", "localhost,127.0.0.1", "comma-separated SANs for the minted server cert")
	cmd.Flags().Int("central-max-events", 0, "central analytics store retention cap (0 = default)")
	return cmd
}

func runControlPlane(cmd *cobra.Command, configPath, listenAddr, tokenEnv, caCert, caKey, tlsHost string, maxEvents int) error {
	// Validate the policy file up front so the control plane fails loudly on a
	// bad config rather than only when a worker first polls.
	prov, err := config.NewLocalYAMLProvider(configPath)
	if err != nil {
		return fmt.Errorf("control-plane: %w", err)
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		return err
	}
	logger, _ := observability.NewLogger(cmd.OutOrStdout(), pol.LogLevel, pol.LogFormat)

	var token string
	if tokenEnv != "" {
		token = os.Getenv(tokenEnv)
		if token == "" {
			logger.Warn("control-plane: token-env set but empty; serving WITHOUT auth", "env", tokenEnv)
		}
	} else {
		logger.Warn("control-plane: no token configured; serving WITHOUT auth (set --token-env for production)")
	}

	srv := controlplane.New(controlplane.Config{
		PolicyPath: configPath,
		Token:      token,
		MaxEvents:  maxEvents,
		Logger:     logger,
	})

	httpSrv := &http.Server{
		Addr:    listenAddr,
		Handler: srv.Handler(),
		// ReadHeaderTimeout bounds request-header reads; WriteTimeout is left 0 so
		// long-poll responses (held up to ~60s) are never cut off mid-flight.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// TLS: mint a server cert from the provided CA so workers trust it via their
	// configured controlPlane.caCert. Both flags required together.
	haveCA := caCert != "" && caKey != ""
	if (caCert != "") != (caKey != "") {
		return fmt.Errorf("control-plane: both --ca-cert and --ca-key must be set together")
	}
	if haveCA {
		tlsCfg, tErr := controlplane.MintServerTLS(caCert, caKey, strings.Split(tlsHost, ","))
		if tErr != nil {
			return tErr
		}
		httpSrv.TLSConfig = tlsCfg
	} else {
		logger.Warn("control-plane: serving plain HTTP; workers require HTTPS for the policy pull (provide --ca-cert/--ca-key)")
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodic re-read so external edits to the policy file propagate to workers.
	srv.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		scheme := "http"
		if haveCA {
			scheme = "https"
		}
		logger.Info("control plane listening",
			"addr", listenAddr,
			"policy", scheme+"://"+listenAddr+"/policy",
			"dashboard", scheme+"://"+listenAddr+"/dashboard/")
		if haveCA {
			errCh <- httpSrv.ListenAndServeTLS("", "")
		} else {
			errCh <- httpSrv.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
