package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cicdecoy/cli/pkg/k8s"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ── Validate ──────────────────────────────────────────

func newValidateCmd() *cobra.Command {
	var (
		dir          string
		strict       bool
		fidelityTest bool
	)

	cmd := &cobra.Command{
		Use:   "validate [manifest...]",
		Short: "Lint and validate decoy manifests",
		Example: `  cicdecoy validate config/dev-decoy.yaml
  cicdecoy validate -d manifests/ --strict
  cicdecoy validate config/ --fidelity-test`,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if dir != "" {
				dirPaths, err := collectManifests(dir)
				if err != nil {
					return err
				}
				paths = append(paths, dirPaths...)
			}
			if len(paths) == 0 {
				return fmt.Errorf("specify manifest path(s) or -d directory")
			}

			docs, err := loadManifests(paths)
			if err != nil {
				return err
			}

			allValid := true
			for _, doc := range docs {
				name := doc.GetName()
				kind := doc.GetKind()
				errors := doc.Validate()
				warnings := doc.FidelityWarnings()

				if strict && len(warnings) > 0 {
					errors = append(errors, warnings...)
					warnings = nil
				}

				if len(errors) > 0 {
					allValid = false
					printer.Ln("  %s %s/%s", printer.Red("✗"), kind, name)
					for _, e := range errors {
						printer.Ln("    %s %s", printer.Red("error:"), e)
					}
				} else {
					printer.Ln("  %s %s/%s", printer.Green("✓"), kind, name)
				}

				for _, w := range warnings {
					printer.Ln("    %s %s", printer.Yellow("warn:"), w)
				}
			}

			printer.Ln()
			if allValid {
				printer.Success("All %d manifest(s) valid", len(docs))
			} else {
				return fmt.Errorf("validation failed")
			}

			if fidelityTest {
				printer.Ln()
				printer.Warn("Fidelity testing is reserved for a future release (planned v0.2.0). See docs/ROADMAP.md for details.")
				return nil
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&dir, "directory", "d", "", "validate all manifests in directory")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail on warnings")
	cmd.Flags().BoolVar(&fidelityTest, "fidelity-test", false, "run fidelity tests against staging (reserved — not yet implemented)")

	return cmd
}

// ── Logs ──────────────────────────────────────────────

func newLogsCmd() *cobra.Command {
	var (
		follow    bool
		since     string
		eventType string
		raw       bool
	)

	cmd := &cobra.Command{
		Use:   "logs <decoy-name>",
		Short: "Stream decoy interaction logs",
		Args:  cobra.ExactArgs(1),
		Example: `  cicdecoy logs ssh-dmz-01 -f
  cicdecoy logs ssh-dmz-01 --type command.exec --since 1h`,
		RunE: func(cmd *cobra.Command, args []string) error {
			decoyName := args[0]

			if follow {
				nc, err := getNATSClient()
				if err != nil {
					return err
				}

				subject := fmt.Sprintf("cicdecoy.enriched.events.%s.>", decoyName)
				if eventType != "" {
					subject = fmt.Sprintf("cicdecoy.enriched.events.%s.%s", decoyName, eventType)
				}

				printer.Ln("  Streaming: %s", subject)
				printer.Ln()

				return nc.Subscribe(subject, func(subj string, data []byte) {
					if raw {
						fmt.Println(string(data))
						return
					}

					var event map[string]interface{}
					if err := json.Unmarshal(data, &event); err != nil {
						printer.Ln("  %s skipping malformed event: %v", printer.Yellow("warn:"), err)
						return
					}

					ts := time.Now().Format("15:04:05")
					evType, _ := event["event_type"].(string)
					srcIP, _ := event["source_ip"].(string)
					sev, _ := event["severity"].(string)

					detail := ""
					if rd, ok := event["raw_data"].(map[string]interface{}); ok {
						if c, ok := rd["command"].(string); ok {
							detail = c
						}
					}

					printer.Ln("  %s %-16s %-15s %-8s %s",
						printer.Dim2(ts), evType, srcIP, sev, detail)
				})
			}

			// Non-follow: query DB for recent events
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			events, err := dbc.RecentEvents(context.Background(), decoyName, eventType, since, 100)
			if err != nil {
				return err
			}

			if jsonOutput {
				return printer.JSON(events)
			}

			for _, e := range events {
				printer.Ln("  %s %-16s %-15s %-8s %s",
					printer.Dim2(e.Timestamp), e.EventType, e.SourceIP, e.Severity, e.Command)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow log output")
	cmd.Flags().StringVar(&since, "since", "1h", "time filter")
	cmd.Flags().StringVar(&eventType, "type", "", "event type filter")
	cmd.Flags().BoolVar(&raw, "raw", false, "show raw NATS messages")

	return cmd
}

// ── Fleet ─────────────────────────────────────────────

func newFleetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Manage decoy fleets",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all DecoyFleet resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}
			fleets, err := kc.ListFleets()
			if err != nil {
				return err
			}
			if jsonOutput {
				return printer.JSON(fleets)
			}
			printer.Ln()
			printer.Table(
				[]string{"NAME", "TEMPLATE", "READY", "TOTAL", "ZONES", "AGE"},
				fleetRows(fleets),
			)
			return nil
		},
	})

	scaleCmd := &cobra.Command{
		Use:   "scale <name> <count>",
		Short: "Scale fleet replica count",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}
			printer.Info("Scaling %s to %s...", args[0], args[1])
			return kc.ScaleFleet(args[0], args[1])
		},
	}

	rotateCmd := &cobra.Command{
		Use:   "rotate <name>",
		Short: "Trigger fleet-wide rotation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}
			printer.Info("Rotating fleet %s...", args[0])
			return kc.RotateFleet(args[0])
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status <name>",
		Short: "Detailed fleet member status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}
			detail, err := kc.FleetDetail(args[0])
			if err != nil {
				return err
			}
			if jsonOutput {
				return printer.JSON(detail)
			}
			printer.Ln()
			printer.Header("Fleet: %s", args[0])
			// Render member table
			return printer.JSON(detail) // TODO: rich table
		},
	}

	cmd.AddCommand(scaleCmd, rotateCmd, statusCmd)
	return cmd
}

// ── Profile ───────────────────────────────────────────

func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage decoy profiles",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available decoy profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}
			profiles, err := kc.ListProfiles()
			if err != nil {
				return err
			}
			if jsonOutput {
				return printer.JSON(profiles)
			}
			printer.Ln()
			printer.Table(
				[]string{"NAME", "OS", "DISTRO", "PACKAGES", "USERS"},
				profileRows(profiles),
			)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show <name>",
		Short: "Display profile details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := getKubeClient()
			if err != nil {
				return err
			}
			profile, err := kc.GetProfile(args[0])
			if err != nil {
				return err
			}
			return printer.JSON(profile)
		},
	})

	return cmd
}

// ── Config ────────────────────────────────────────────

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "CLI configuration",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "view",
		Short: "Show current CLI configuration",
		Run: func(cmd *cobra.Command, args []string) {
			printer.Ln()
			printer.Header("CLI Configuration")
			printer.Ln()
			for _, k := range []string{"kubeconfig", "namespace", "nats.url", "db.dsn"} {
				v := viper.GetString(k)
				if v == "" {
					v = "(auto-discover)"
				}
				printer.Ln("  %-20s %s", k, v)
			}
			printer.Ln()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			viper.Set(args[0], args[1])
			if err := viper.WriteConfig(); err != nil {
				// Config file may not exist yet
				return viper.SafeWriteConfig()
			}
			printer.Success("Set %s = %s", args[0], args[1])
			return nil
		},
	})

	return cmd
}

// ── Row Helpers ───────────────────────────────────────

func fleetRows(fleets []k8s.FleetRow) [][]string {
	var rows [][]string
	for _, f := range fleets {
		rows = append(rows, []string{
			f.Name, f.Template, f.Ready, fmt.Sprintf("%d", f.Total), f.Zones, f.Age,
		})
	}
	return rows
}

func profileRows(profiles []k8s.ProfileRow) [][]string {
	var rows [][]string
	for _, p := range profiles {
		rows = append(rows, []string{
			p.Name, p.OS, p.Distro, fmt.Sprintf("%d", p.Packages), fmt.Sprintf("%d", p.Users),
		})
	}
	return rows
}

