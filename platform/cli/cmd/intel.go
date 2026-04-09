package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func newIntelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intel",
		Short: "Query and export threat intelligence",
	}

	cmd.AddCommand(newIntelIOCsCmd())
	cmd.AddCommand(newIntelActorsCmd())
	cmd.AddCommand(newIntelMITRECmd())
	cmd.AddCommand(newIntelExportCmd())
	cmd.AddCommand(newIntelReportCmd())
	cmd.AddCommand(newIntelHoneytokensCmd())

	return cmd
}

// ── IOCs ──────────────────────────────────────────────

func newIntelIOCsCmd() *cobra.Command {
	var (
		iocType  string
		severity string
		since    string
		format   string
		output   string
	)

	cmd := &cobra.Command{
		Use:   "iocs",
		Short: "List active indicators of compromise",
		Example: `  cicdecoy intel iocs --type ip --severity high
  cicdecoy intel iocs --format stix -o iocs.stix.json
  cicdecoy intel iocs --since 7d --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			iocs, err := dbc.ListIOCs(context.Background(), iocType, severity, since)
			if err != nil {
				return err
			}

			switch format {
			case "json":
				data, _ := json.MarshalIndent(iocs, "", "  ")
				if output != "" {
					return os.WriteFile(output, data, 0644)
				}
				fmt.Println(string(data))

			case "stix":
				data, err := iocsToSTIX(iocs)
				if err != nil {
					return err
				}
				if output != "" {
					return os.WriteFile(output, data, 0644)
				}
				fmt.Println(string(data))

			case "csv":
				data := iocsToCSV(iocs)
				if output != "" {
					return os.WriteFile(output, []byte(data), 0644)
				}
				fmt.Print(data)

			default: // table
				if jsonOutput {
					return printer.JSON(iocs)
				}
				printer.Ln()
				printer.Table(
					[]string{"TYPE", "VALUE", "SEVERITY", "CONF", "SIGHTINGS", "FIRST SEEN", "LAST SEEN", "TECHNIQUES"},
					iocRows(iocs),
				)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&iocType, "type", "", "filter: ip|domain|hash|url")
	cmd.Flags().StringVar(&severity, "severity", "", "minimum severity")
	cmd.Flags().StringVar(&since, "since", "7d", "time filter")
	cmd.Flags().StringVar(&format, "format", "table", "output format (table|json|csv|stix)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "export to file")

	return cmd
}

// ── Actors ────────────────────────────────────────────

func newIntelActorsCmd() *cobra.Command {
	var (
		since       string
		minSessions int
	)

	cmd := &cobra.Command{
		Use:   "actors",
		Short: "List observed threat actors / source IP clusters",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			actors, err := dbc.ListActors(context.Background(), since, minSessions)
			if err != nil {
				return err
			}

			if jsonOutput {
				return printer.JSON(actors)
			}

			printer.Ln()
			printer.Table(
				[]string{"SOURCE IP", "COUNTRY", "SESSIONS", "COMMANDS", "MAX SEVERITY", "TECHNIQUES", "FIRST SEEN", "LAST SEEN"},
				actorRows(actors),
			)

			return nil
		},
	}

	cmd.Flags().StringVar(&since, "since", "7d", "time filter")
	cmd.Flags().IntVar(&minSessions, "min-sessions", 1, "minimum session count")

	return cmd
}

// ── MITRE ─────────────────────────────────────────────

func newIntelMITRECmd() *cobra.Command {
	var (
		since  string
		format string
	)

	cmd := &cobra.Command{
		Use:   "mitre",
		Short: "MITRE ATT&CK technique summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			techniques, err := dbc.MITRESummary(context.Background(), since)
			if err != nil {
				return err
			}

			if jsonOutput || format == "json" {
				return printer.JSON(techniques)
			}

			printer.Ln()
			printer.Header("MITRE ATT&CK Technique Summary (%s)", since)
			printer.Ln()

			if len(techniques) == 0 {
				printer.Dim("  No techniques observed")
				return nil
			}

			maxCount := techniques[0].Count
			for _, t := range techniques {
				barLen := (t.Count * 40) / maxCount
				bar := strings.Repeat("█", barLen) + strings.Repeat("░", 40-barLen)
				printer.Ln("  %-10s %-32s %s %3d", t.TechniqueID, t.Name, bar, t.Count)
			}
			printer.Ln()

			return nil
		},
	}

	cmd.Flags().StringVar(&since, "since", "7d", "time filter")
	cmd.Flags().StringVar(&format, "format", "table", "output format (table|json|heatmap)")

	return cmd
}

// ── Export ─────────────────────────────────────────────

func newIntelExportCmd() *cobra.Command {
	var (
		format string
		since  string
		until  string
		output string
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Bulk export intelligence",
		Example: `  cicdecoy intel export --format stix --since 7d -o weekly.stix.json
  cicdecoy intel export --format csv --since 30d -o monthly.csv`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			data, err := dbc.ExportIntel(context.Background(), format, since, until)
			if err != nil {
				return err
			}

			if output != "" {
				printer.Success("Exported to %s", output)
				return os.WriteFile(output, data, 0644)
			}

			fmt.Println(string(data))
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "stix", "stix|taxii|csv|json")
	cmd.Flags().StringVar(&since, "since", "7d", "time range start")
	cmd.Flags().StringVar(&until, "until", "now", "time range end")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")

	return cmd
}

// ── Report ────────────────────────────────────────────

func newIntelReportCmd() *cobra.Command {
	var (
		period string
		format string
		output string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate human-readable intelligence report",
		Example: `  cicdecoy intel report --period weekly --format md -o report.md
  cicdecoy intel report --period daily`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			report, err := dbc.GenerateReport(context.Background(), period, format)
			if err != nil {
				return err
			}

			if output != "" {
				printer.Success("Report written to %s", output)
				return os.WriteFile(output, report, 0644)
			}

			fmt.Println(string(report))
			return nil
		},
	}

	cmd.Flags().StringVar(&period, "period", "weekly", "daily|weekly|monthly")
	cmd.Flags().StringVar(&format, "format", "md", "md|html|pdf")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")

	return cmd
}

// ── Honeytokens ───────────────────────────────────────

func newIntelHoneytokensCmd() *cobra.Command {
	var (
		triggered bool
		since     string
	)

	cmd := &cobra.Command{
		Use:   "honeytokens",
		Short: "List honeytoken trigger history",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbc, err := getDBClient()
			if err != nil {
				return err
			}

			tokens, err := dbc.ListHoneytokens(context.Background(), triggered, since)
			if err != nil {
				return err
			}

			if jsonOutput {
				return printer.JSON(tokens)
			}

			printer.Ln()
			printer.Table(
				[]string{"TOKEN", "TYPE", "DECOY", "TRIGGERED", "LAST TRIGGER", "SOURCE IP"},
				honeytokenRows(tokens),
			)

			return nil
		},
	}

	cmd.Flags().BoolVar(&triggered, "triggered", false, "show only triggered tokens")
	cmd.Flags().StringVar(&since, "since", "30d", "time filter")

	return cmd
}

// ── Row Helpers ───────────────────────────────────────

type IOCRow struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Severity   string   `json:"severity"`
	Confidence int      `json:"confidence"`
	Sightings  int      `json:"sightings"`
	FirstSeen  string   `json:"firstSeen"`
	LastSeen   string   `json:"lastSeen"`
	Techniques []string `json:"techniques"`
}

type ActorRow struct {
	SourceIP   string   `json:"sourceIP"`
	Country    string   `json:"country"`
	Sessions   int      `json:"sessions"`
	Commands   int      `json:"commands"`
	Severity   string   `json:"maxSeverity"`
	Techniques []string `json:"techniques"`
	FirstSeen  string   `json:"firstSeen"`
	LastSeen   string   `json:"lastSeen"`
}

type MITRETechRow struct {
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Count       int    `json:"count"`
}

type HoneytokenRow struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Decoy       string `json:"decoy"`
	Triggered   int    `json:"triggered"`
	LastTrigger string `json:"lastTrigger"`
	SourceIP    string `json:"sourceIP"`
}

func iocRows(iocs []IOCRow) [][]string {
	var rows [][]string
	for _, i := range iocs {
		techs := strings.Join(i.Techniques, ", ")
		if len(techs) > 30 {
			techs = techs[:30] + "..."
		}
		rows = append(rows, []string{
			i.Type, i.Value, i.Severity, fmt.Sprintf("%d%%", i.Confidence),
			fmt.Sprintf("%d", i.Sightings), i.FirstSeen, i.LastSeen, techs,
		})
	}
	return rows
}

func actorRows(actors []ActorRow) [][]string {
	var rows [][]string
	for _, a := range actors {
		techs := strings.Join(a.Techniques, ", ")
		if len(techs) > 25 {
			techs = techs[:25] + "..."
		}
		rows = append(rows, []string{
			a.SourceIP, a.Country, fmt.Sprintf("%d", a.Sessions),
			fmt.Sprintf("%d", a.Commands), a.Severity, techs, a.FirstSeen, a.LastSeen,
		})
	}
	return rows
}

func honeytokenRows(tokens []HoneytokenRow) [][]string {
	var rows [][]string
	for _, t := range tokens {
		rows = append(rows, []string{
			t.Name, t.Type, t.Decoy, fmt.Sprintf("%d", t.Triggered), t.LastTrigger, t.SourceIP,
		})
	}
	return rows
}

func iocsToCSV(iocs []IOCRow) string {
	var b strings.Builder
	b.WriteString("type,value,severity,confidence,sightings,first_seen,last_seen,techniques\n")
	for _, i := range iocs {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%d,%d,%s,%s,%q\n",
			i.Type, i.Value, i.Severity, i.Confidence, i.Sightings,
			i.FirstSeen, i.LastSeen, strings.Join(i.Techniques, ";")))
	}
	return b.String()
}

func iocsToSTIX(iocs []IOCRow) ([]byte, error) {
	var objects []map[string]interface{}
	for _, ioc := range iocs {
		stixType := "indicator"
		pattern := ""
		switch ioc.Type {
		case "ip":
			pattern = fmt.Sprintf("[ipv4-addr:value = '%s']", ioc.Value)
		case "domain":
			pattern = fmt.Sprintf("[domain-name:value = '%s']", ioc.Value)
		case "hash":
			pattern = fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", ioc.Value)
		case "url":
			pattern = fmt.Sprintf("[url:value = '%s']", ioc.Value)
		}
		objects = append(objects, map[string]interface{}{
			"type":         stixType,
			"id":           fmt.Sprintf("indicator--%s-%s", ioc.Type, ioc.Value),
			"created":      ioc.FirstSeen,
			"modified":     ioc.LastSeen,
			"pattern":      pattern,
			"pattern_type": "stix",
			"valid_from":   ioc.FirstSeen,
			"confidence":   ioc.Confidence,
			"labels":       []string{ioc.Severity},
		})
	}

	bundle := map[string]interface{}{
		"type":         "bundle",
		"id":           "bundle--cicdecoy-iocs",
		"spec_version": "2.1",
		"objects":      objects,
	}
	return json.MarshalIndent(bundle, "", "  ")
}
