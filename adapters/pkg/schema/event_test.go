package schema

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	event := NewEvent("cowrie", "bastion-dmz-01", 3)

	if event.EventID == "" {
		t.Error("EventID should not be empty")
	}
	if event.Version != "1.0" {
		t.Errorf("Version = %q, want %q", event.Version, "1.0")
	}
	if event.Source.Decoy != "bastion-dmz-01" {
		t.Errorf("Source.Decoy = %q, want %q", event.Source.Decoy, "bastion-dmz-01")
	}
	if event.Source.Tier != 3 {
		t.Errorf("Source.Tier = %d, want %d", event.Source.Tier, 3)
	}
	if event.Severity != "info" {
		t.Errorf("Severity = %q, want %q", event.Severity, "info")
	}
	if event.Data == nil {
		t.Error("Data should be initialized, not nil")
	}
	if event.Adapter.Name != "cowrie" {
		t.Errorf("Adapter.Name = %q, want %q", event.Adapter.Name, "cowrie")
	}
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
	// Timestamp should be recent (within last 5 seconds)
	if time.Since(event.Timestamp) > 5*time.Second {
		t.Errorf("Timestamp too old: %v", event.Timestamp)
	}
}

func TestNewEvent_UniqueIDs(t *testing.T) {
	e1 := NewEvent("cowrie", "decoy-1", 1)
	e2 := NewEvent("cowrie", "decoy-1", 1)

	if e1.EventID == e2.EventID {
		t.Error("two events should have different EventIDs")
	}
}

func TestNATSSubject(t *testing.T) {
	tests := []struct {
		name      string
		decoy     string
		eventType string
		expected  string
	}{
		{
			name:      "auth_attempt",
			decoy:     "bastion-dmz-01",
			eventType: "auth.attempt",
			expected:  "cicdecoy.decoy.events.bastion-dmz-01.auth.attempt",
		},
		{
			name:      "command_exec",
			decoy:     "smb-fileshare-02",
			eventType: "command.exec",
			expected:  "cicdecoy.decoy.events.smb-fileshare-02.command.exec",
		},
		{
			name:      "connection",
			decoy:     "ssh-bastion",
			eventType: "connection",
			expected:  "cicdecoy.decoy.events.ssh-bastion.connection",
		},
		{
			name:      "file_access",
			decoy:     "ftp-server-01",
			eventType: "file.access",
			expected:  "cicdecoy.decoy.events.ftp-server-01.file.access",
		},
		{
			name:      "session_closed",
			decoy:     "honeypot-01",
			eventType: "session.closed",
			expected:  "cicdecoy.decoy.events.honeypot-01.session.closed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := NewEvent("test", tt.decoy, 1)
			event.EventType = tt.eventType
			got := event.NATSSubject()
			if got != tt.expected {
				t.Errorf("NATSSubject() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestJSON(t *testing.T) {
	event := NewEvent("cowrie", "test-decoy", 2)
	event.EventType = "auth.attempt"
	event.SourceIP = "10.0.0.1"
	event.SourcePort = 22
	event.SessionID = "cowrie-abc123"
	event.Severity = "medium"
	event.Data = map[string]any{
		"username": "root",
		"password": "toor",
		"accepted": true,
	}

	data, err := event.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}

	// Spot-check key fields
	if parsed["event_type"] != "auth.attempt" {
		t.Errorf("event_type = %v, want %q", parsed["event_type"], "auth.attempt")
	}
	if parsed["source_ip"] != "10.0.0.1" {
		t.Errorf("source_ip = %v, want %q", parsed["source_ip"], "10.0.0.1")
	}
	if parsed["session_id"] != "cowrie-abc123" {
		t.Errorf("session_id = %v, want %q", parsed["session_id"], "cowrie-abc123")
	}
	if parsed["severity"] != "medium" {
		t.Errorf("severity = %v, want %q", parsed["severity"], "medium")
	}
	if parsed["version"] != "1.0" {
		t.Errorf("version = %v, want %q", parsed["version"], "1.0")
	}

	// Check nested source
	src, ok := parsed["source"].(map[string]any)
	if !ok {
		t.Fatal("source is not a map")
	}
	if src["decoy"] != "test-decoy" {
		t.Errorf("source.decoy = %v, want %q", src["decoy"], "test-decoy")
	}
	if src["tier"] != float64(2) {
		t.Errorf("source.tier = %v, want %v", src["tier"], 2)
	}

	// Check nested data
	d, ok := parsed["data"].(map[string]any)
	if !ok {
		t.Fatal("data is not a map")
	}
	if d["username"] != "root" {
		t.Errorf("data.username = %v, want %q", d["username"], "root")
	}
}

func TestJSON_RoundTrip(t *testing.T) {
	original := NewEvent("dionaea", "smb-server", 5)
	original.EventType = "file.access"
	original.SourceIP = "192.168.1.100"
	original.SourcePort = 54321
	original.SessionID = "dionaea-42"
	original.Severity = "high"
	original.Data = map[string]any{
		"access_type": "download",
		"url":         "http://evil.com/malware.exe",
	}
	original.Adapter.OriginalEventID = "dionaea-conn-42"
	original.Adapter.IngestLatencyMs = 150

	data, err := original.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	var restored Event
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if restored.EventID != original.EventID {
		t.Errorf("EventID = %q, want %q", restored.EventID, original.EventID)
	}
	if restored.EventType != original.EventType {
		t.Errorf("EventType = %q, want %q", restored.EventType, original.EventType)
	}
	if restored.SourceIP != original.SourceIP {
		t.Errorf("SourceIP = %q, want %q", restored.SourceIP, original.SourceIP)
	}
	if restored.SourcePort != original.SourcePort {
		t.Errorf("SourcePort = %d, want %d", restored.SourcePort, original.SourcePort)
	}
	if restored.Source.Decoy != original.Source.Decoy {
		t.Errorf("Source.Decoy = %q, want %q", restored.Source.Decoy, original.Source.Decoy)
	}
	if restored.Source.Tier != original.Source.Tier {
		t.Errorf("Source.Tier = %d, want %d", restored.Source.Tier, original.Source.Tier)
	}
	if restored.Adapter.OriginalEventID != original.Adapter.OriginalEventID {
		t.Errorf("Adapter.OriginalEventID = %q, want %q", restored.Adapter.OriginalEventID, original.Adapter.OriginalEventID)
	}
}

func TestJSON_OmitsEmptyOptionalFields(t *testing.T) {
	event := NewEvent("test", "decoy", 1)
	event.EventType = "connection"

	data, err := event.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	s := string(data)
	// source_ip and source_port should be omitted when empty/zero (omitempty)
	if strings.Contains(s, `"source_ip"`) {
		t.Error("expected source_ip to be omitted when empty")
	}
	if strings.Contains(s, `"source_port"`) {
		t.Error("expected source_port to be omitted when zero")
	}
}

func TestNATSSubject_EmptyFields(t *testing.T) {
	event := Event{}
	got := event.NATSSubject()
	expected := "cicdecoy.decoy.events.unknown.unknown"
	if got != expected {
		t.Errorf("NATSSubject() with empty event = %q, want %q", got, expected)
	}
}
