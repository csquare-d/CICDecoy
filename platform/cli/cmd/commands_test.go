package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── severityRank tests ──────────────────────────────────

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"info", 0},
		{"unknown", 0},
		{"", 0},
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			got := severityRank(tc.severity)
			if got != tc.want {
				t.Errorf("severityRank(%q) = %d, want %d", tc.severity, got, tc.want)
			}
		})
	}
}

func TestSeverityRank_Ordering(t *testing.T) {
	// Verify relative ordering
	if severityRank("critical") <= severityRank("high") {
		t.Error("critical should rank higher than high")
	}
	if severityRank("high") <= severityRank("medium") {
		t.Error("high should rank higher than medium")
	}
	if severityRank("medium") <= severityRank("low") {
		t.Error("medium should rank higher than low")
	}
	if severityRank("low") <= severityRank("info") {
		t.Error("low should rank higher than info")
	}
}

// ── sessionRows tests ───────────────────────────────────

func TestSessionRows(t *testing.T) {
	tests := []struct {
		name     string
		sessions []SessionRow
		wantLen  int
		check    func(t *testing.T, rows [][]string)
	}{
		{
			name:     "empty sessions",
			sessions: nil,
			wantLen:  0,
			check:    func(t *testing.T, rows [][]string) {},
		},
		{
			name: "live session shows bullet",
			sessions: []SessionRow{
				{
					SessionID: "abcdef1234567890",
					DecoyName: "ssh-01",
					SourceIP:  "10.0.0.1",
					Username:  "root",
					Commands:  5,
					Severity:  "high",
					Phase:     "discovery",
					Tools:     []string{"nmap"},
					Live:      true,
					StartTime: "2025-03-26T14:00:00Z",
				},
			},
			wantLen: 1,
			check: func(t *testing.T, rows [][]string) {
				if rows[0][0] != "●" {
					t.Errorf("live indicator = %q, want bullet", rows[0][0])
				}
			},
		},
		{
			name: "non-live session shows space",
			sessions: []SessionRow{
				{
					SessionID: "abcdef1234567890",
					DecoyName: "ssh-01",
					Live:      false,
				},
			},
			wantLen: 1,
			check: func(t *testing.T, rows [][]string) {
				if rows[0][0] != " " {
					t.Errorf("non-live indicator = %q, want space", rows[0][0])
				}
			},
		},
		{
			name: "session ID truncated to 8 chars",
			sessions: []SessionRow{
				{SessionID: "abcdef1234567890"},
			},
			wantLen: 1,
			check: func(t *testing.T, rows [][]string) {
				if rows[0][1] != "abcdef12" {
					t.Errorf("session ID = %q, want truncated to 8", rows[0][1])
				}
			},
		},
		{
			name: "short session ID preserved",
			sessions: []SessionRow{
				{SessionID: "abc"},
			},
			wantLen: 1,
			check: func(t *testing.T, rows [][]string) {
				if rows[0][1] != "abc" {
					t.Errorf("session ID = %q, want abc", rows[0][1])
				}
			},
		},
		{
			name: "empty tools shows dash",
			sessions: []SessionRow{
				{SessionID: "abcdef1234567890", Tools: nil},
			},
			wantLen: 1,
			check: func(t *testing.T, rows [][]string) {
				// tools column is index 8
				if rows[0][8] != "\u2014" { // em dash
					t.Errorf("empty tools = %q, want em dash", rows[0][8])
				}
			},
		},
		{
			name: "multiple tools joined with comma",
			sessions: []SessionRow{
				{
					SessionID: "abcdef1234567890",
					Tools:     []string{"nmap", "curl", "wget"},
				},
			},
			wantLen: 1,
			check: func(t *testing.T, rows [][]string) {
				if rows[0][8] != "nmap, curl, wget" {
					t.Errorf("tools = %q", rows[0][8])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := sessionRows(tc.sessions)
			if len(rows) != tc.wantLen {
				t.Fatalf("rows count = %d, want %d", len(rows), tc.wantLen)
			}
			tc.check(t, rows)
		})
	}
}

// ── eventsToCSV tests ───────────────────────────────────

func TestEventsToCSV(t *testing.T) {
	tests := []struct {
		name   string
		events []SessionEvent
		check  func(t *testing.T, csv string)
	}{
		{
			name:   "empty events returns header only",
			events: nil,
			check: func(t *testing.T, csv string) {
				if !strings.HasPrefix(csv, "timestamp,event_type,") {
					t.Error("should start with CSV header")
				}
				lines := strings.Split(strings.TrimSpace(csv), "\n")
				if len(lines) != 1 {
					t.Errorf("expected 1 line (header only), got %d", len(lines))
				}
			},
		},
		{
			name: "single event",
			events: []SessionEvent{
				{
					Timestamp:      "2025-03-26T14:03:22Z",
					EventType:      "command.exec",
					SourceIP:       "10.0.0.1",
					Username:       "root",
					Command:        "ls -la",
					Severity:       "medium",
					MITRETechnique: "T1083",
				},
			},
			check: func(t *testing.T, csv string) {
				lines := strings.Split(strings.TrimSpace(csv), "\n")
				if len(lines) != 2 {
					t.Fatalf("expected 2 lines, got %d", len(lines))
				}
				if !strings.Contains(lines[1], "command.exec") {
					t.Error("data line should contain event type")
				}
				if !strings.Contains(lines[1], "10.0.0.1") {
					t.Error("data line should contain source IP")
				}
				if !strings.Contains(lines[1], "T1083") {
					t.Error("data line should contain MITRE technique")
				}
			},
		},
		{
			name: "command with special characters is quoted",
			events: []SessionEvent{
				{
					Command: `cat /etc/passwd | grep "root"`,
				},
			},
			check: func(t *testing.T, csv string) {
				lines := strings.Split(strings.TrimSpace(csv), "\n")
				if len(lines) != 2 {
					t.Fatalf("expected 2 lines, got %d", len(lines))
				}
				// Go %q quoting wraps the command
				if !strings.Contains(lines[1], `"cat /etc/passwd`) {
					t.Errorf("command should be quoted: %s", lines[1])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := eventsToCSV(tc.events)
			if err != nil {
				t.Fatalf("eventsToCSV error = %v", err)
			}
			tc.check(t, string(data))
		})
	}
}

// ── eventsToSTIX tests ──────────────────────────────────

func TestEventsToSTIX(t *testing.T) {
	t.Run("empty events produce valid bundle", func(t *testing.T) {
		data, err := eventsToSTIX(nil, "session-123")
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		var bundle map[string]interface{}
		if err := json.Unmarshal(data, &bundle); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if bundle["type"] != "bundle" {
			t.Errorf("type = %v", bundle["type"])
		}
		if bundle["spec_version"] != "2.1" {
			t.Errorf("spec_version = %v", bundle["spec_version"])
		}
	})

	t.Run("events without MITRE techniques are skipped", func(t *testing.T) {
		events := []SessionEvent{
			{EventType: "connection.new", Timestamp: "2025-03-26T14:00:00Z"},
			{EventType: "auth.success", Timestamp: "2025-03-26T14:00:01Z"},
		}
		data, err := eventsToSTIX(events, "session-123")
		if err != nil {
			t.Fatal(err)
		}
		var bundle map[string]interface{}
		json.Unmarshal(data, &bundle)
		objects := bundle["objects"].([]interface{})
		if len(objects) != 0 {
			t.Errorf("expected 0 objects for events without MITRE, got %d", len(objects))
		}
	})

	t.Run("events with MITRE create observed-data and attack-pattern", func(t *testing.T) {
		events := []SessionEvent{
			{
				EventType:      "command.exec",
				Timestamp:      "2025-03-26T14:03:22Z",
				MITRETechnique: "T1059.004",
				MITREName:      "Unix Shell",
			},
		}
		data, err := eventsToSTIX(events, "session-12345678")
		if err != nil {
			t.Fatal(err)
		}
		var bundle map[string]interface{}
		json.Unmarshal(data, &bundle)
		objects := bundle["objects"].([]interface{})
		if len(objects) != 2 {
			t.Fatalf("expected 2 objects (observed-data + attack-pattern), got %d", len(objects))
		}

		// First object: observed-data
		od := objects[0].(map[string]interface{})
		if od["type"] != "observed-data" {
			t.Errorf("first object type = %v", od["type"])
		}

		// Second object: attack-pattern
		ap := objects[1].(map[string]interface{})
		if ap["type"] != "attack-pattern" {
			t.Errorf("second object type = %v", ap["type"])
		}
		if ap["name"] != "Unix Shell" {
			t.Errorf("attack-pattern name = %v", ap["name"])
		}
		refs := ap["external_references"].([]interface{})
		if len(refs) != 1 {
			t.Fatalf("expected 1 external reference, got %d", len(refs))
		}
		ref := refs[0].(map[string]interface{})
		if ref["external_id"] != "T1059.004" {
			t.Errorf("external_id = %v", ref["external_id"])
		}
	})

	t.Run("bundle ID contains session ID", func(t *testing.T) {
		data, _ := eventsToSTIX(nil, "my-session-id")
		var bundle map[string]interface{}
		json.Unmarshal(data, &bundle)
		if !strings.Contains(bundle["id"].(string), "my-session-id") {
			t.Errorf("bundle id should contain session ID: %v", bundle["id"])
		}
	})
}

// ── iocRows tests ───────────────────────────────────────

func TestIocRows(t *testing.T) {
	t.Run("empty IOCs", func(t *testing.T) {
		rows := iocRows(nil)
		if len(rows) != 0 {
			t.Errorf("expected 0 rows, got %d", len(rows))
		}
	})

	t.Run("formats correctly", func(t *testing.T) {
		iocs := []IOCRow{
			{
				Type:       "ip",
				Value:      "198.51.100.42",
				Severity:   "high",
				Confidence: 85,
				Sightings:  12,
				FirstSeen:  "2025-03-20",
				LastSeen:   "2025-03-26",
				Techniques: []string{"T1059", "T1083"},
			},
		}
		rows := iocRows(iocs)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		row := rows[0]
		if row[0] != "ip" {
			t.Errorf("type = %q", row[0])
		}
		if row[1] != "198.51.100.42" {
			t.Errorf("value = %q", row[1])
		}
		if row[3] != "85%" {
			t.Errorf("confidence = %q, want 85%%", row[3])
		}
		if row[4] != "12" {
			t.Errorf("sightings = %q", row[4])
		}
	})

	t.Run("long techniques list is truncated", func(t *testing.T) {
		iocs := []IOCRow{
			{
				Techniques: []string{"T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1083"},
			},
		}
		rows := iocRows(iocs)
		techs := rows[0][7]
		if len(techs) > 33 { // 30 + "..."
			t.Errorf("techniques column should be truncated, got len=%d: %s", len(techs), techs)
		}
	})
}

// ── iocsToCSV tests ─────────────────────────────────────

func TestIocsToCSV(t *testing.T) {
	t.Run("empty produces header only", func(t *testing.T) {
		csv := iocsToCSV(nil)
		if !strings.HasPrefix(csv, "type,value,severity") {
			t.Error("should start with CSV header")
		}
		lines := strings.Split(strings.TrimSpace(csv), "\n")
		if len(lines) != 1 {
			t.Errorf("expected 1 line, got %d", len(lines))
		}
	})

	t.Run("IOC data is included", func(t *testing.T) {
		iocs := []IOCRow{
			{
				Type:       "ip",
				Value:      "10.0.0.1",
				Severity:   "high",
				Confidence: 90,
				Sightings:  5,
				FirstSeen:  "2025-01-01",
				LastSeen:   "2025-03-26",
				Techniques: []string{"T1059"},
			},
		}
		csv := iocsToCSV(iocs)
		lines := strings.Split(strings.TrimSpace(csv), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 lines, got %d", len(lines))
		}
		if !strings.Contains(lines[1], "10.0.0.1") {
			t.Error("data line should contain IP")
		}
	})
}

// ── iocsToSTIX tests ────────────────────────────────────

func TestIocsToSTIX(t *testing.T) {
	tests := []struct {
		name  string
		iocs  []IOCRow
		check func(t *testing.T, bundle map[string]interface{})
	}{
		{
			name: "empty IOCs produce valid bundle",
			iocs: nil,
			check: func(t *testing.T, bundle map[string]interface{}) {
				if bundle["type"] != "bundle" {
					t.Errorf("type = %v", bundle["type"])
				}
				if bundle["spec_version"] != "2.1" {
					t.Errorf("spec_version = %v", bundle["spec_version"])
				}
			},
		},
		{
			name: "IP IOC produces correct STIX pattern",
			iocs: []IOCRow{
				{Type: "ip", Value: "10.0.0.1", Confidence: 80, FirstSeen: "2025-01-01", LastSeen: "2025-03-26", Severity: "high"},
			},
			check: func(t *testing.T, bundle map[string]interface{}) {
				objects := bundle["objects"].([]interface{})
				if len(objects) != 1 {
					t.Fatalf("expected 1 object, got %d", len(objects))
				}
				ind := objects[0].(map[string]interface{})
				if ind["type"] != "indicator" {
					t.Errorf("type = %v", ind["type"])
				}
				pattern := ind["pattern"].(string)
				if !strings.Contains(pattern, "ipv4-addr:value") {
					t.Errorf("pattern = %q, want ipv4-addr pattern", pattern)
				}
				if !strings.Contains(pattern, "10.0.0.1") {
					t.Errorf("pattern should contain IP: %q", pattern)
				}
			},
		},
		{
			name: "domain IOC produces correct STIX pattern",
			iocs: []IOCRow{
				{Type: "domain", Value: "evil.example.com", Confidence: 70, FirstSeen: "2025-01-01", LastSeen: "2025-03-26"},
			},
			check: func(t *testing.T, bundle map[string]interface{}) {
				objects := bundle["objects"].([]interface{})
				ind := objects[0].(map[string]interface{})
				pattern := ind["pattern"].(string)
				if !strings.Contains(pattern, "domain-name:value") {
					t.Errorf("pattern = %q, want domain-name pattern", pattern)
				}
			},
		},
		{
			name: "hash IOC produces correct STIX pattern",
			iocs: []IOCRow{
				{Type: "hash", Value: "abc123def456", Confidence: 90, FirstSeen: "2025-01-01", LastSeen: "2025-03-26"},
			},
			check: func(t *testing.T, bundle map[string]interface{}) {
				objects := bundle["objects"].([]interface{})
				ind := objects[0].(map[string]interface{})
				pattern := ind["pattern"].(string)
				if !strings.Contains(pattern, "file:hashes") {
					t.Errorf("pattern = %q, want file:hashes pattern", pattern)
				}
			},
		},
		{
			name: "URL IOC produces correct STIX pattern",
			iocs: []IOCRow{
				{Type: "url", Value: "http://evil.example.com/malware", Confidence: 60, FirstSeen: "2025-01-01", LastSeen: "2025-03-26"},
			},
			check: func(t *testing.T, bundle map[string]interface{}) {
				objects := bundle["objects"].([]interface{})
				ind := objects[0].(map[string]interface{})
				pattern := ind["pattern"].(string)
				if !strings.Contains(pattern, "url:value") {
					t.Errorf("pattern = %q, want url:value pattern", pattern)
				}
			},
		},
		{
			name: "confidence is preserved",
			iocs: []IOCRow{
				{Type: "ip", Value: "10.0.0.1", Confidence: 95, FirstSeen: "2025-01-01", LastSeen: "2025-03-26"},
			},
			check: func(t *testing.T, bundle map[string]interface{}) {
				objects := bundle["objects"].([]interface{})
				ind := objects[0].(map[string]interface{})
				conf := ind["confidence"].(float64)
				if conf != 95 {
					t.Errorf("confidence = %v, want 95", conf)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := iocsToSTIX(tc.iocs)
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			var bundle map[string]interface{}
			if err := json.Unmarshal(data, &bundle); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			tc.check(t, bundle)
		})
	}
}

// ── actorRows tests ─────────────────────────────────────

func TestActorRows(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		rows := actorRows(nil)
		if len(rows) != 0 {
			t.Errorf("expected 0 rows, got %d", len(rows))
		}
	})

	t.Run("formats correctly", func(t *testing.T) {
		actors := []ActorRow{
			{
				SourceIP:   "10.0.0.1",
				Country:    "CN",
				Sessions:   5,
				Commands:   42,
				Severity:   "critical",
				Techniques: []string{"T1059"},
				FirstSeen:  "2025-01-01",
				LastSeen:   "2025-03-26",
			},
		}
		rows := actorRows(actors)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		if rows[0][0] != "10.0.0.1" {
			t.Errorf("source IP = %q", rows[0][0])
		}
		if rows[0][1] != "CN" {
			t.Errorf("country = %q", rows[0][1])
		}
		if rows[0][2] != "5" {
			t.Errorf("sessions = %q", rows[0][2])
		}
	})

	t.Run("long techniques truncated", func(t *testing.T) {
		actors := []ActorRow{
			{Techniques: []string{"T1059.001", "T1059.002", "T1059.003", "T1083.001"}},
		}
		rows := actorRows(actors)
		techs := rows[0][5]
		if len(techs) > 28 { // 25 + "..."
			t.Errorf("techniques should be truncated, got len=%d: %s", len(techs), techs)
		}
	})
}

// ── honeytokenRows tests ────────────────────────────────

func TestHoneytokenRows(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		rows := honeytokenRows(nil)
		if len(rows) != 0 {
			t.Errorf("expected 0 rows, got %d", len(rows))
		}
	})

	t.Run("formats correctly", func(t *testing.T) {
		tokens := []HoneytokenRow{
			{
				Name:        "fake-aws-key",
				Type:        "aws_access_key",
				Decoy:       "ssh-01",
				Triggered:   3,
				LastTrigger: "2025-03-26 14:00",
				SourceIP:    "10.0.0.5",
			},
		}
		rows := honeytokenRows(tokens)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		if rows[0][0] != "fake-aws-key" {
			t.Errorf("name = %q", rows[0][0])
		}
		if rows[0][3] != "3" {
			t.Errorf("triggered = %q", rows[0][3])
		}
	})
}

// ── decoyRows tests ─────────────────────────────────────

func TestDecoyRows(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		rows := decoyRows(nil)
		if len(rows) != 0 {
			t.Errorf("expected 0 rows, got %d", len(rows))
		}
	})

	t.Run("formats tier with T prefix", func(t *testing.T) {
		decoys := []DecoyStatusRow{
			{Name: "ssh-01", Tier: 2, Service: "ssh", Status: "active", Sessions: 10, Alerts: 3},
		}
		rows := decoyRows(decoys)
		if rows[0][1] != "T2" {
			t.Errorf("tier = %q, want T2", rows[0][1])
		}
	})
}

func TestDecoyRowsWide(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		rows := decoyRowsWide(nil)
		if len(rows) != 0 {
			t.Errorf("expected 0 rows, got %d", len(rows))
		}
	})

	t.Run("includes extra columns", func(t *testing.T) {
		decoys := []DecoyStatusRow{
			{
				Name:         "ssh-01",
				Tier:         1,
				Service:      "ssh",
				Zone:         "dmz",
				Status:       "active",
				PodIP:        "10.42.0.5",
				Sessions:     10,
				Alerts:       3,
				Uptime:       "24h",
				LastRotation: "2025-03-25",
			},
		}
		rows := decoyRowsWide(decoys)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		// Wide rows should have 10 columns
		if len(rows[0]) != 10 {
			t.Errorf("expected 10 columns, got %d", len(rows[0]))
		}
		if rows[0][3] != "dmz" {
			t.Errorf("zone = %q", rows[0][3])
		}
		if rows[0][5] != "10.42.0.5" {
			t.Errorf("pod IP = %q", rows[0][5])
		}
	})
}

// ── fleetRows / profileRows tests ───────────────────────

func TestFleetRows(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if len(fleetRows(nil)) != 0 {
			t.Error("expected 0 rows")
		}
	})

	t.Run("formats correctly", func(t *testing.T) {
		fleets := []FleetRow{
			{Name: "fleet-1", Template: "ssh-tmpl", Ready: "3/3", Total: 3, Zones: "dmz,internal", Age: "2d"},
		}
		rows := fleetRows(fleets)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		if rows[0][0] != "fleet-1" {
			t.Errorf("name = %q", rows[0][0])
		}
		if rows[0][3] != "3" {
			t.Errorf("total = %q", rows[0][3])
		}
	})
}

func TestProfileRows(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if len(profileRows(nil)) != 0 {
			t.Error("expected 0 rows")
		}
	})

	t.Run("formats correctly", func(t *testing.T) {
		profiles := []ProfileRow{
			{Name: "ubuntu-22", OS: "linux", Distro: "ubuntu", Packages: 150, Users: 5},
		}
		rows := profileRows(profiles)
		if rows[0][0] != "ubuntu-22" {
			t.Errorf("name = %q", rows[0][0])
		}
		if rows[0][3] != "150" {
			t.Errorf("packages = %q", rows[0][3])
		}
	})
}

// ── Command structure tests ─────────────────────────────

func TestRootCommand_Structure(t *testing.T) {
	// Verify root command exists and has expected properties
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}
	if rootCmd.Use != "cicdecoy" {
		t.Errorf("Use = %q, want cicdecoy", rootCmd.Use)
	}
	if !rootCmd.SilenceUsage {
		t.Error("SilenceUsage should be true")
	}
	if !rootCmd.SilenceErrors {
		t.Error("SilenceErrors should be true")
	}
}

func TestRootCommand_HasSubcommands(t *testing.T) {
	subcommands := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		subcommands[cmd.Name()] = true
	}

	expected := []string{"deploy", "destroy", "status", "fleet", "sessions", "intel", "validate", "logs", "rotate", "profile", "config"}
	for _, name := range expected {
		if !subcommands[name] {
			t.Errorf("missing subcommand: %s", name)
		}
	}
}

func TestRootCommand_GlobalFlags(t *testing.T) {
	flags := rootCmd.PersistentFlags()

	flagTests := []struct {
		name     string
		flagType string
	}{
		{"config", "string"},
		{"kubeconfig", "string"},
		{"context", "string"},
		{"namespace", "string"},
		{"verbose", "bool"},
		{"json", "bool"},
		{"no-color", "bool"},
	}

	for _, tc := range flagTests {
		t.Run(tc.name, func(t *testing.T) {
			f := flags.Lookup(tc.name)
			if f == nil {
				t.Fatalf("flag %q not found", tc.name)
			}
			if f.Value.Type() != tc.flagType {
				t.Errorf("flag %q type = %q, want %q", tc.name, f.Value.Type(), tc.flagType)
			}
		})
	}
}

func TestDeployCommand_Flags(t *testing.T) {
	cmd := newDeployCmd()

	flagTests := []struct {
		name      string
		shorthand string
		flagType  string
	}{
		{"file", "f", "stringArray"},
		{"directory", "d", "string"},
		{"dry-run", "", "bool"},
		{"wait", "", "bool"},
		{"timeout", "", "string"},
	}

	for _, tc := range flagTests {
		t.Run(tc.name, func(t *testing.T) {
			f := cmd.Flags().Lookup(tc.name)
			if f == nil {
				t.Fatalf("flag %q not found", tc.name)
			}
			if f.Value.Type() != tc.flagType {
				t.Errorf("type = %q, want %q", f.Value.Type(), tc.flagType)
			}
			if tc.shorthand != "" && f.Shorthand != tc.shorthand {
				t.Errorf("shorthand = %q, want %q", f.Shorthand, tc.shorthand)
			}
		})
	}

	// Verify timeout default
	f := cmd.Flags().Lookup("timeout")
	if f.DefValue != "120s" {
		t.Errorf("timeout default = %q, want 120s", f.DefValue)
	}
}

func TestDestroyCommand_Flags(t *testing.T) {
	cmd := newDestroyCmd()

	for _, name := range []string{"all", "cascade", "force"} {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("flag %q not found", name)
		}
	}
}

func TestSessionsCommand_Subcommands(t *testing.T) {
	cmd := newSessionsCmd()

	subcommands := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subcommands[sub.Name()] = true
	}

	expected := []string{"list", "watch", "replay", "export"}
	for _, name := range expected {
		if !subcommands[name] {
			t.Errorf("missing subcommand: sessions %s", name)
		}
	}

	// Verify alias
	if len(cmd.Aliases) == 0 || cmd.Aliases[0] != "sess" {
		t.Errorf("aliases = %v, want [sess]", cmd.Aliases)
	}
}

func TestIntelCommand_Subcommands(t *testing.T) {
	cmd := newIntelCmd()

	subcommands := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subcommands[sub.Name()] = true
	}

	expected := []string{"iocs", "actors", "mitre", "export", "report", "honeytokens"}
	for _, name := range expected {
		if !subcommands[name] {
			t.Errorf("missing subcommand: intel %s", name)
		}
	}
}

func TestRotateCommand_Flags(t *testing.T) {
	cmd := newRotateCmd()

	f := cmd.Flags().Lookup("all")
	if f == nil {
		t.Fatal("flag 'all' not found")
	}
	f = cmd.Flags().Lookup("strategy")
	if f == nil {
		t.Fatal("flag 'strategy' not found")
	}
}

func TestValidateCommand_Flags(t *testing.T) {
	cmd := newValidateCmd()

	for _, name := range []string{"directory", "strict", "fidelity-test"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %q not found", name)
		}
	}
}

func TestStatusCommand_Subcommands(t *testing.T) {
	cmd := newStatusCmd()

	subcommands := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subcommands[sub.Name()] = true
	}

	if !subcommands["decoys"] {
		t.Error("missing subcommand: status decoys")
	}
	if !subcommands["health"] {
		t.Error("missing subcommand: status health")
	}
}

func TestFleetCommand_Subcommands(t *testing.T) {
	cmd := newFleetCmd()

	subcommands := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subcommands[sub.Name()] = true
	}

	expected := []string{"list", "scale", "rotate", "status"}
	for _, name := range expected {
		if !subcommands[name] {
			t.Errorf("missing subcommand: fleet %s", name)
		}
	}
}

func TestCollectManifests_NonexistentDir(t *testing.T) {
	_, err := collectManifests("/nonexistent/dir/path")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}
