package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/cicdecoy/cli/pkg/k8s"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	var (
		wide  bool
		watch bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Platform and decoy status overview",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if watch {
				return runStatusWatch(ctx, wide)
			}
			return runStatusOverview(ctx, wide)
		},
	}

	cmd.Flags().BoolVar(&wide, "wide", false, "show extended columns")
	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "continuous refresh")

	// Subcommands
	cmd.AddCommand(newStatusDecoysCmd())
	cmd.AddCommand(newStatusHealthCmd())

	return cmd
}

func newStatusDecoysCmd() *cobra.Command {
	var (
		tier    string
		zone    string
		svcType string
		wide    bool
	)

	cmd := &cobra.Command{
		Use:   "decoys",
		Short: "List all decoys with status",
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}

			decoys, err := kc.ListDecoys(tier, zone, svcType)
			if err != nil {
				return err
			}

			if jsonOutput {
				return printer.JSON(decoys)
			}

			printer.Ln()
			if wide {
				printer.Table(
					[]string{"NAME", "TIER", "TYPE", "ZONE", "STATUS", "IP", "SESSIONS", "ALERTS", "UPTIME", "LAST ROTATION"},
					decoyRowsWide(decoys),
				)
			} else {
				printer.Table(
					[]string{"NAME", "TIER", "TYPE", "STATUS", "SESSIONS", "ALERTS"},
					decoyRows(decoys),
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&tier, "tier", "", "filter by tier (1,2,3)")
	cmd.Flags().StringVar(&zone, "zone", "", "filter by zone")
	cmd.Flags().StringVar(&svcType, "type", "", "filter by service type")
	cmd.Flags().BoolVar(&wide, "wide", false, "extended columns")

	return cmd
}

func newStatusHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Platform component health",
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}

			health, err := kc.PlatformHealth()
			if err != nil {
				return err
			}

			if jsonOutput {
				return printer.JSON(health)
			}

			printer.Ln()
			printer.Header("CI/CDecoy Platform Health")
			printer.Ln()

			components := []struct {
				name string
				h    k8s.ComponentStatus
			}{
				{"k3s Cluster", health.Cluster},
				{"NATS JetStream", health.NATS},
				{"TimescaleDB", health.Storage},
				{"CTI Pipeline", health.CTIPipeline},
				{"Inference Gateway", health.Inference},
			}

			for _, c := range components {
				icon := printer.StatusIcon(c.h.Status)
				latency := ""
				if c.h.Latency != "" {
					latency = fmt.Sprintf("  (%s)", c.h.Latency)
				}
				printer.Ln("  %s %-22s %s%s", icon, c.name, c.h.Status, latency)
				for k, v := range c.h.Details {
					printer.Dim("    %s: %s", k, v)
				}
			}
			printer.Ln()
			return nil
		},
	}
}

// ── Status Overview ───────────────────────────────────

func runStatusOverview(ctx context.Context, wide bool) error {
	kc, err := getKubeClient()
	if err != nil {
		return err
	}

	health, err := kc.PlatformHealth()
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}

	decoys, err := kc.ListDecoys("", "", "")
	if err != nil {
		return fmt.Errorf("listing decoys: %w", err)
	}

	if jsonOutput {
		return printer.JSON(map[string]interface{}{
			"health": health,
			"decoys": decoys,
		})
	}

	printer.Ln()
	printer.Header("CI/CDecoy Platform Status")
	printer.Ln()

	// Health summary
	for _, c := range []struct {
		name string
		h    k8s.ComponentStatus
	}{
		{"k3s Cluster", health.Cluster},
		{"NATS JetStream", health.NATS},
		{"TimescaleDB", health.Storage},
		{"CTI Pipeline", health.CTIPipeline},
		{"Inference", health.Inference},
	} {
		printer.Ln("  %s %-20s %s", printer.StatusIcon(c.h.Status), c.name, c.h.Status)
	}

	// Fleet summary
	tierCounts := map[int]int{}
	statusCounts := map[string]int{}
	var totalSessions, totalAlerts int64

	for _, d := range decoys {
		tierCounts[d.Tier]++
		statusCounts[d.Status]++
		totalSessions += d.Sessions
		totalAlerts += d.Alerts
	}

	printer.Ln()
	printer.Ln("  Decoy Fleet:")
	printer.Ln("    Total: %d  (T1: %d  T2: %d  T3: %d)",
		len(decoys), tierCounts[1], tierCounts[2], tierCounts[3])
	printer.Ln("    Active: %d  Degraded: %d  Retired: %d",
		statusCounts["Active"], statusCounts["Degraded"], statusCounts["Retired"])
	printer.Ln("    Sessions (24h): %d  Alerts (24h): %d", totalSessions, totalAlerts)
	printer.Ln()

	return nil
}

func runStatusWatch(ctx context.Context, wide bool) error {
	for {
		// Clear screen
		fmt.Print("\033[H\033[2J")
		if err := runStatusOverview(ctx, wide); err != nil {
			printer.Error("refresh failed: %v", err)
		}
		printer.Dim("  Refreshing every 5s — Ctrl+C to stop")
		time.Sleep(5 * time.Second)
	}
}

// ── Row Helpers ──────────────────────────────────────

func decoyRows(decoys []k8s.DecoyStatusRow) [][]string {
	var rows [][]string
	for _, d := range decoys {
		rows = append(rows, []string{
			d.Name,
			fmt.Sprintf("T%d", d.Tier),
			d.Service,
			d.Status,
			fmt.Sprintf("%d", d.Sessions),
			fmt.Sprintf("%d", d.Alerts),
		})
	}
	return rows
}

func decoyRowsWide(decoys []k8s.DecoyStatusRow) [][]string {
	var rows [][]string
	for _, d := range decoys {
		rows = append(rows, []string{
			d.Name,
			fmt.Sprintf("T%d", d.Tier),
			d.Service,
			d.Zone,
			d.Status,
			d.PodIP,
			fmt.Sprintf("%d", d.Sessions),
			fmt.Sprintf("%d", d.Alerts),
			d.Uptime,
			d.LastRotation,
		})
	}
	return rows
}
