package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newSessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sessions",
		Aliases: []string{"sess"},
		Short:   "List, watch, and replay attacker sessions",
	}

	cmd.AddCommand(newSessionsListCmd())
	cmd.AddCommand(newSessionsWatchCmd())
	cmd.AddCommand(newSessionsReplayCmd())
	cmd.AddCommand(newSessionsExportCmd())

	return cmd
}

// ── List ──────────────────────────────────────────────

func newSessionsListCmd() *cobra.Command {
	var (
		liveOnly bool
		severity string
		decoy    string
		since    string
		limit    int
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active and recent sessions",
		Example: `  cicdecoy sessions list --live
  cicdecoy sessions list --severity high --since 1h
  cicdecoy sessions list --decoy ssh-dmz-01 --limit 20`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			sessions, err := dbc.ListSessions(context.Background(), db.SessionQuery{
				LiveOnly: liveOnly,
				Severity: severity,
				Decoy:    decoy,
				Since:    since,
				Limit:    limit,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				return printer.JSON(sessions)
			}

			printer.Ln()
			printer.Table(
				[]string{"", "SESSION", "DECOY", "SOURCE", "USER", "CMDS", "SEVERITY", "PHASE", "TOOLS", "STARTED"},
				sessionRows(sessions),
			)

			return nil
		},
	}

	cmd.Flags().BoolVar(&liveOnly, "live", false, "show only live sessions")
	cmd.Flags().StringVar(&severity, "severity", "", "filter by severity")
	cmd.Flags().StringVar(&decoy, "decoy", "", "filter by decoy name")
	cmd.Flags().StringVar(&since, "since", "24h", "time filter")
	cmd.Flags().IntVar(&limit, "limit", 50, "max results")

	return cmd
}

// ── Watch ─────────────────────────────────────────────

func newSessionsWatchCmd() *cobra.Command {
	var (
		decoy       string
		minSeverity string
	)

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Real-time session activity stream",
		RunE: func(cmd *cobra.Command, args []string) error {
			nc, err := getNATSClient()
			if err != nil {
				return err
			}

			printer.Ln()
			printer.Header("Watching live sessions...")
			printer.Ln()

			subject := "cicdecoy.enriched.events.>"
			if decoy != "" {
				subject = fmt.Sprintf("cicdecoy.enriched.events.%s.>", decoy)
			}

			return nc.Subscribe(subject, func(subj string, data []byte) {
				var event map[string]interface{}
				if err := json.Unmarshal(data, &event); err != nil {
					return
				}

				sev, _ := event["severity"].(string)
				if minSeverity != "" && severityRank(sev) < severityRank(minSeverity) {
					return
				}

				ts := time.Now().Format("15:04:05")
				evType, _ := event["event_type"].(string)
				srcIP, _ := event["source_ip"].(string)
				decoyName, _ := event["decoy_name"].(string)

				switch evType {
				case "auth.success", "auth.attempt":
					user, _ := event["username"].(string)
					printer.Ln("  %s %s %s ← %s as %s",
						printer.Dim2(ts), printer.StatusIcon("auth"), decoyName, srcIP, user)

				case "command.exec":
					raw, _ := event["raw_data"].(map[string]interface{})
					command, _ := raw["command"].(string)
					mitre := ""
					if techs, ok := event["mitre_techniques"].([]interface{}); ok && len(techs) > 0 {
						if t, ok := techs[0].(map[string]interface{}); ok {
							mitre, _ = t["technique_id"].(string)
						}
					}
					line := fmt.Sprintf("  %s %s %s $ %s",
						printer.Dim2(ts), printer.SeverityIcon(sev), decoyName, command)
					if mitre != "" {
						line += fmt.Sprintf("  [%s]", mitre)
					}
					printer.Ln(line)

				case "session.end":
					printer.Ln("  %s %s %s session ended (%s)",
						printer.Dim2(ts), printer.StatusIcon("offline"), decoyName, srcIP)
				}
			})
		},
	}

	cmd.Flags().StringVar(&decoy, "decoy", "", "filter by decoy name")
	cmd.Flags().StringVar(&minSeverity, "severity", "", "minimum severity")

	return cmd
}

// ── Replay ────────────────────────────────────────────

func newSessionsReplayCmd() *cobra.Command {
	var (
		speed     float64
		raw       bool
		annotated bool
	)

	cmd := &cobra.Command{
		Use:   "replay <session-id>",
		Short: "Replay a session in the terminal",
		Args:  cobra.ExactArgs(1),
		Example: `  cicdecoy sessions replay abc12345 --annotated
  cicdecoy sessions replay abc12345 --speed 2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			sessionID := args[0]
			events, err := dbc.GetSessionEvents(context.Background(), sessionID)
			if err != nil {
				return err
			}

			if raw {
				return printer.JSON(events)
			}

			printer.Ln()
			printer.Header("Replaying session %s  (speed: %.1fx, %d events)", sessionID[:8], speed, len(events))
			printer.Ln()

			var prevTime time.Time

			for _, ev := range events {
				evTime, _ := time.Parse(time.RFC3339Nano, ev.Timestamp)

				// Simulate timing
				if !prevTime.IsZero() {
					delay := evTime.Sub(prevTime)
					scaled := time.Duration(float64(delay) / speed)
					if scaled > 0 && scaled < 30*time.Second {
						time.Sleep(scaled)
					}
				}
				prevTime = evTime

				ts := evTime.Format("15:04:05")

				switch ev.EventType {
				case "connection.new", "session.start":
					printer.Ln("  %s → Session started from %s",
						printer.Dim2(ts), ev.SourceIP)

				case "auth.success":
					printer.Ln("  %s ◉ AUTH SUCCESS: %s",
						printer.Dim2(ts), ev.Username)

				case "command.exec":
					printer.Ln("  %s $ %s",
						printer.Dim2(ts), printer.Green(ev.Command))
					if annotated && ev.MITRETechnique != "" {
						printer.Ln("  %s   ╰─ ATT&CK: %s %s",
							printer.Dim2("        "), printer.Blue(ev.MITRETechnique), ev.MITREName)
					}

				case "command.response":
					if ev.Response != "" {
						for _, line := range strings.Split(ev.Response, "\n") {
							printer.Ln("  %s %s", printer.Dim2(ts), line)
						}
					}

				case "alert":
					printer.Ln("  %s ⚠ ALERT: %s — %s",
						printer.Dim2(ts), printer.Red(ev.Severity), ev.Command)

				case "session.end":
					printer.Ln("  %s ← Session ended",
						printer.Dim2(ts))
				}
			}

			printer.Ln()
			printer.Dim("  Replay complete")
			printer.Ln()

			return nil
		},
	}

	cmd.Flags().Float64Var(&speed, "speed", 1.0, "playback speed (0.5, 1, 2, 5)")
	cmd.Flags().BoolVar(&raw, "raw", false, "show raw event data")
	cmd.Flags().BoolVar(&annotated, "annotated", true, "show MITRE annotations inline")

	return cmd
}

// ── Export ─────────────────────────────────────────────

func newSessionsExportCmd() *cobra.Command {
	var (
		format string
		output string
	)

	cmd := &cobra.Command{
		Use:   "export <session-id>",
		Short: "Export session data",
		Args:  cobra.ExactArgs(1),
		Example: `  cicdecoy sessions export abc12345 --format json -o session.json
  cicdecoy sessions export abc12345 --format stix -o session.stix.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			events, err := dbc.GetSessionEvents(context.Background(), args[0])
			if err != nil {
				return err
			}

			var data []byte
			switch format {
			case "json":
				data, err = json.MarshalIndent(events, "", "  ")
			case "csv":
				data, err = eventsToCSV(events)
			case "stix":
				data, err = eventsToSTIX(events, args[0])
			default:
				return fmt.Errorf("unsupported format: %s (use json|csv|stix)", format)
			}

			if err != nil {
				return err
			}

			if output != "" {
				return os.WriteFile(output, data, 0644)
			}

			fmt.Println(string(data))
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "json", "output format (json|csv|stix)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")

	return cmd
}

// ── Helpers ───────────────────────────────────────────

type SessionRow struct {
	SessionID string   `json:"sessionId"`
	DecoyName string   `json:"decoyName"`
	SourceIP  string   `json:"sourceIP"`
	Country   string   `json:"country"`
	Username  string   `json:"username"`
	StartTime string   `json:"startTime"`
	Commands  int      `json:"commandCount"`
	Severity  string   `json:"maxSeverity"`
	Phase     string   `json:"attackPhase"`
	Tools     []string `json:"toolsDetected"`
	Live      bool     `json:"live"`
}

type SessionEvent struct {
	Timestamp      string `json:"timestamp"`
	EventType      string `json:"eventType"`
	SourceIP       string `json:"sourceIP,omitempty"`
	Username       string `json:"username,omitempty"`
	Command        string `json:"command,omitempty"`
	Response       string `json:"response,omitempty"`
	Severity       string `json:"severity,omitempty"`
	MITRETechnique string `json:"mitreTechnique,omitempty"`
	MITREName      string `json:"mitreName,omitempty"`
}

func sessionRows(sessions []SessionRow) [][]string {
	var rows [][]string
	for _, s := range sessions {
		live := " "
		if s.Live {
			live = "●"
		}
		id := s.SessionID
		if len(id) > 8 {
			id = id[:8]
		}
		tools := strings.Join(s.Tools, ", ")
		if tools == "" {
			tools = "—"
		}
		rows = append(rows, []string{
			live, id, s.DecoyName, s.SourceIP, s.Username,
			fmt.Sprintf("%d", s.Commands), s.Severity, s.Phase, tools, s.StartTime,
		})
	}
	return rows
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func eventsToCSV(events []SessionEvent) ([]byte, error) {
	var b strings.Builder
	b.WriteString("timestamp,event_type,source_ip,username,command,severity,mitre_technique\n")
	for _, e := range events {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%q,%s,%s\n",
			e.Timestamp, e.EventType, e.SourceIP, e.Username,
			e.Command, e.Severity, e.MITRETechnique))
	}
	return []byte(b.String()), nil
}

func eventsToSTIX(events []SessionEvent, sessionID string) ([]byte, error) {
	// Generate STIX 2.1 bundle from session events
	bundle := map[string]interface{}{
		"type":        "bundle",
		"id":          fmt.Sprintf("bundle--%s", sessionID),
		"spec_version": "2.1",
		"objects":     stixObjectsFromEvents(events, sessionID),
	}
	return json.MarshalIndent(bundle, "", "  ")
}

func stixObjectsFromEvents(events []SessionEvent, sessionID string) []map[string]interface{} {
	var objects []map[string]interface{}

	// Create observed-data object for each event with MITRE technique
	for i, e := range events {
		if e.MITRETechnique == "" {
			continue
		}
		objects = append(objects, map[string]interface{}{
			"type":          "observed-data",
			"id":            fmt.Sprintf("observed-data--%s-%d", sessionID[:8], i),
			"created":       e.Timestamp,
			"modified":      e.Timestamp,
			"first_observed": e.Timestamp,
			"last_observed":  e.Timestamp,
			"number_observed": 1,
			"object_refs":   []string{},
		})

		// Attack pattern for the technique
		objects = append(objects, map[string]interface{}{
			"type": "attack-pattern",
			"id":   fmt.Sprintf("attack-pattern--%s", e.MITRETechnique),
			"name": e.MITREName,
			"external_references": []map[string]string{
				{
					"source_name": "mitre-attack",
					"external_id": e.MITRETechnique,
				},
			},
		})
	}

	return objects
}
