package dionaea

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/cicdecoy/adapters/pkg/adapter"
)

func newTestAdapter() *DionaeaAdapter {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return New(DefaultConfig(), adapter.Config{
		DecoyName:     "test-smb-01",
		DecoyTier:     2,
		SessionPrefix: "dionaea",
	}, logger)
}

// ── translate tests ──────────────────────────────────────

func TestTranslate_Connection(t *testing.T) {
	a := newTestAdapter()

	raw := `{"type":"connection","timestamp":"2024-03-10 08:15:30","connection":42,"local_host":"192.168.1.50","local_port":445,"remote_host":"10.0.0.99","remote_port":55123,"protocol":"smbd","transport":"tcp"}`

	event, err := a.translate([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatal("expected event, got nil")
	}

	if event.EventType != "connection" {
		t.Errorf("EventType = %q, want %q", event.EventType, "connection")
	}
	if event.Severity != "info" {
		t.Errorf("Severity = %q, want %q", event.Severity, "info")
	}
	if event.SourceIP != "10.0.0.99" {
		t.Errorf("SourceIP = %q, want %q", event.SourceIP, "10.0.0.99")
	}
	if event.SourcePort != 55123 {
		t.Errorf("SourcePort = %d, want %d", event.SourcePort, 55123)
	}
	if event.SessionID != "dionaea-42" {
		t.Errorf("SessionID = %q, want %q", event.SessionID, "dionaea-42")
	}
	if event.Source.Decoy != "test-smb-01" {
		t.Errorf("Source.Decoy = %q, want %q", event.Source.Decoy, "test-smb-01")
	}
	if event.Source.Tier != 2 {
		t.Errorf("Source.Tier = %d, want %d", event.Source.Tier, 2)
	}
	if event.Adapter.OriginalEventID != "dionaea-conn-42" {
		t.Errorf("Adapter.OriginalEventID = %q, want %q", event.Adapter.OriginalEventID, "dionaea-conn-42")
	}
	if event.Data["protocol"] != "smb" {
		t.Errorf("Data[protocol] = %v, want %q", event.Data["protocol"], "smb")
	}
	if event.Data["transport"] != "tcp" {
		t.Errorf("Data[transport] = %v, want %q", event.Data["transport"], "tcp")
	}
	if event.Timestamp.Year() != 2024 {
		t.Errorf("Timestamp year = %d, want 2024", event.Timestamp.Year())
	}
}

func TestTranslate_EventTypes(t *testing.T) {
	a := newTestAdapter()

	tests := []struct {
		name         string
		input        dionaeaEvent
		wantType     string
		wantSeverity string
		wantNil      bool
		checkData    map[string]any
	}{
		{
			name: "connection",
			input: dionaeaEvent{
				Type:       "connection",
				ConnID:     1,
				RemoteIP:   "10.0.0.1",
				RemotePort: 12345,
				LocalIP:    "192.168.1.1",
				LocalPort:  445,
				Protocol:   "smbd",
				Transport:  "tcp",
			},
			wantType:     "connection",
			wantSeverity: "info",
			checkData: map[string]any{
				"protocol":  "smb",
				"transport": "tcp",
			},
		},
		{
			name: "download",
			input: dionaeaEvent{
				Type:     "download",
				ConnID:   2,
				RemoteIP: "10.0.0.2",
				Protocol: "httpd",
				URL:      "http://evil.com/malware.exe",
				MD5:      "d41d8cd98f00b204e9800998ecf8427e",
				SHA512:   "cf83e1357eefb8bd",
			},
			wantType:     "file.access",
			wantSeverity: "high",
			checkData: map[string]any{
				"access_type": "download",
				"url":         "http://evil.com/malware.exe",
				"md5":         "d41d8cd98f00b204e9800998ecf8427e",
				"sha512":      "cf83e1357eefb8bd",
				"protocol":    "http",
			},
		},
		{
			name: "login",
			input: dionaeaEvent{
				Type:       "login",
				ConnID:     3,
				RemoteIP:   "10.0.0.3",
				RemotePort: 54321,
				Protocol:   "mysqld",
				Username:   "root",
				Password:   "password123",
			},
			wantType:     "auth.attempt",
			wantSeverity: "medium",
			checkData: map[string]any{
				"username": "root",
				"password": "password123",
				"method":   "password",
				"protocol": "mysql",
				"accepted": false,
			},
		},
		{
			name: "unknown_type_returns_nil",
			input: dionaeaEvent{
				Type:   "dcerpc_request",
				ConnID: 4,
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}

			event, err := a.translate(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantNil {
				if event != nil {
					t.Fatalf("expected nil event, got %+v", event)
				}
				return
			}

			if event == nil {
				t.Fatal("expected event, got nil")
			}
			if event.EventType != tt.wantType {
				t.Errorf("EventType = %q, want %q", event.EventType, tt.wantType)
			}
			if event.Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", event.Severity, tt.wantSeverity)
			}
			if event.Adapter.Name != "dionaea" {
				t.Errorf("Adapter.Name = %q, want %q", event.Adapter.Name, "dionaea")
			}

			for k, want := range tt.checkData {
				got, ok := event.Data[k]
				if !ok {
					t.Errorf("Data[%q] missing", k)
					continue
				}
				if got != want {
					t.Errorf("Data[%q] = %v (%T), want %v (%T)", k, got, got, want, want)
				}
			}
		})
	}
}

// ── Edge cases ───────────────────────────────────────────

func TestTranslate_MalformedJSON(t *testing.T) {
	a := newTestAdapter()

	inputs := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"not_json", "not json at all"},
		{"truncated", `{"type":"connection","connec`},
	}

	for _, tt := range inputs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.translate([]byte(tt.input))
			if err == nil {
				t.Error("expected error for malformed input")
			}
		})
	}
}

func TestTranslate_MissingFields(t *testing.T) {
	a := newTestAdapter()

	// Minimal: only type field
	raw := `{"type":"connection","connection":0}`
	event, err := a.translate([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.SourceIP != "" {
		t.Errorf("SourceIP = %q, want empty", event.SourceIP)
	}
	if event.SessionID != "dionaea-0" {
		t.Errorf("SessionID = %q, want %q", event.SessionID, "dionaea-0")
	}
}

func TestTranslate_TimestampParsing(t *testing.T) {
	a := newTestAdapter()

	tests := []struct {
		name      string
		timestamp string
		wantYear  int
	}{
		{"valid", "2024-06-15 10:30:00", 2024},
		{"invalid", "not-a-timestamp", 0},
		{"empty", "", 0},
		{"wrong_format", "2024-06-15T10:30:00Z", 0}, // Dionaea uses space-separated
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _ := json.Marshal(dionaeaEvent{
				Type:      "connection",
				Timestamp: tt.timestamp,
				ConnID:    1,
			})
			event, err := a.translate(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantYear > 0 && event.Timestamp.Year() != tt.wantYear {
				t.Errorf("Timestamp.Year = %d, want %d", event.Timestamp.Year(), tt.wantYear)
			}
		})
	}
}

// ── Protocol mapping tests ───────────────────────────────

func TestMapDionaeaProtocol(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"smbd", "smb"},
		{"httpd", "http"},
		{"ftpd", "ftp"},
		{"mysqld", "mysql"},
		{"mssqld", "mssql"},
		{"SipSession", "sip"},
		{"pptp", "pptp"},
		{"upnp", "upnp"},
		{"unknown_proto", "unknown_proto"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapDionaeaProtocol(tt.input)
			if got != tt.expected {
				t.Errorf("mapDionaeaProtocol(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ── Constructor and config tests ─────────────────────────

func TestNew_DefaultSessionPrefix(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	a := New(DefaultConfig(), adapter.Config{
		DecoyName: "test",
		DecoyTier: 1,
	}, logger)

	if a.common.SessionPrefix != "dionaea" {
		t.Errorf("SessionPrefix = %q, want %q", a.common.SessionPrefix, "dionaea")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LogPath != "/var/lib/dionaea/dionaea.json" {
		t.Errorf("LogPath = %q, want %q", cfg.LogPath, "/var/lib/dionaea/dionaea.json")
	}
}

func TestName(t *testing.T) {
	a := newTestAdapter()
	if a.Name() != "dionaea" {
		t.Errorf("Name() = %q, want %q", a.Name(), "dionaea")
	}
}

func TestHealthCheck_NonexistentFile(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	a := New(Config{LogPath: "/nonexistent/dionaea.json"}, adapter.Config{
		DecoyName: "test",
		DecoyTier: 1,
	}, logger)

	err := a.HealthCheck(context.Background())
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected not-exist error, got: %v", err)
	}
}

// ── NATS subject tests ──────────────────────────────────

func TestTranslate_NATSSubject(t *testing.T) {
	a := newTestAdapter()

	tests := []struct {
		name        string
		eventType   string
		wantSubject string
	}{
		{"connection", "connection", "cicdecoy.decoy.events.test-smb-01.connection"},
		{"file_access", "download", "cicdecoy.decoy.events.test-smb-01.file.access"},
		{"auth_attempt", "login", "cicdecoy.decoy.events.test-smb-01.auth.attempt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _ := json.Marshal(dionaeaEvent{
				Type:   tt.eventType,
				ConnID: 1,
			})
			event, err := a.translate(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatalf("expected event, got nil")
			}
			got := event.NATSSubject()
			if got != tt.wantSubject {
				t.Errorf("NATSSubject() = %q, want %q", got, tt.wantSubject)
			}
		})
	}
}
