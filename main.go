package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	rootCmd := &cobra.Command{
		Use:     "nexus-vpn",
		Short:   "Tech Duinn mesh VPN - WireGuard-based peer-to-peer networking",
		Long:    "Nexus VPN provides WireGuard mesh networking with STUN NAT traversal, TCP relay fallback, MQTT-based discovery, and MagicDNS for the Tech Duinn swarm.",
		Version: fmt.Sprintf("%s (built %s)", version, buildTime),
	}

	rootCmd.AddCommand(
		newUpCmd(),
		newDownCmd(),
		newStatusCmd(),
		newPeersCmd(),
		newDashboardCmd(),
		newGenKeysCmd(),
		newDNSCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newUpCmd() *cobra.Command {
	var configFile, nodeName string

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Start the mesh VPN",
		Long:  "Bring up WireGuard interface, register with MQTT, start STUN discovery, DNS, relay, and dashboard.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(configFile, nodeName)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle shutdown signals
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				slog.Info("shutting down...")
				cancel()
			}()

			return Run(ctx, cfg)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "/etc/nexus-vpn/config.yaml", "Config file path")
	cmd.Flags().StringVarP(&nodeName, "node", "n", "", "Node name (overrides config and NEXUS_NODE env)")

	return cmd
}

func newDownCmd() *cobra.Command {
	var nodeName string

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop the mesh VPN",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Teardown(nodeName)
		},
	}

	cmd.Flags().StringVarP(&nodeName, "node", "n", "", "Node name")
	return cmd
}

func newStatusCmd() *cobra.Command {
	var configFile, nodeName string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show mesh VPN status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(configFile, nodeName)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			return ShowStatus(cfg)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "/etc/nexus-vpn/config.yaml", "Config file path")
	cmd.Flags().StringVarP(&nodeName, "node", "n", "", "Node name")
	return cmd
}

func newPeersCmd() *cobra.Command {
	var configFile, nodeName string

	cmd := &cobra.Command{
		Use:   "peers",
		Short: "List connected peers",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(configFile, nodeName)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			return ListPeers(cfg)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "/etc/nexus-vpn/config.yaml", "Config file path")
	cmd.Flags().StringVarP(&nodeName, "node", "n", "", "Node name")
	return cmd
}

func newDashboardCmd() *cobra.Command {
	var configFile, nodeName string

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start standalone dashboard server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(configFile, nodeName)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			return RunDashboard(ctx, cfg)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "/etc/nexus-vpn/config.yaml", "Config file path")
	cmd.Flags().StringVarP(&nodeName, "node", "n", "", "Node name")
	return cmd
}

func newGenKeysCmd() *cobra.Command {
	var outDir string

	cmd := &cobra.Command{
		Use:   "gen-keys",
		Short: "Generate WireGuard keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			return GenerateKeys(outDir)
		},
	}

	cmd.Flags().StringVarP(&outDir, "out", "o", ".", "Output directory for key files")
	return cmd
}

func newDNSCmd() *cobra.Command {
	var configFile, nodeName string

	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Start standalone DNS server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(configFile, nodeName)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			return RunDNS(ctx, cfg)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "/etc/nexus-vpn/config.yaml", "Config file path")
	cmd.Flags().StringVarP(&nodeName, "node", "n", "", "Node name")
	return cmd
}
