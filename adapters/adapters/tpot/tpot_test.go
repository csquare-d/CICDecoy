package tpot

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cicdecoy/adapters/pkg/adapter"
	"github.com/cicdecoy/adapters/pkg/schema"
)

func newTestAdapter() *TPotAdapter {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	a := New(DefaultConfig(), adapter.Config{
		DecoyName:     "test-tpot-01",
		DecoyTier:     4,
		SessionPrefix: "tpot",
	}, logger)
	return a
}

// ── translate tests ──────────────────────────────────────

func TestTranslate_CowrieLoginSuccess(t *testing.T) {
	a := newTestAdapter()

	hit := esHit{
		Source: map[string]any{
			"type":       "cowrie",
			"@timestamp": "2024-03-15T12:30:45.123Z",
			"src_ip":     "10.0.0.50",
			"src_port":   float64(33221),
			"eventid":    "cowrie.login.success",
			"username":   "root",
			"password":   "toor",
		},
		Index: "logstash-2024.03.15",
	}

	event, err := a.translate(hit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatal("expected event, got nil")
	}

	if event.EventType != "auth.attempt" {
		t.Errorf("EventType = %q, want %q", event.EventType, "auth.attempt")
	}
	if event.Severity != "medium" {
		t.Errorf("Severity = %q, want %q", event.Severity, "medium")
	}
	if event.SourceIP != "10.0.0.50" {
		t.Errorf("SourceIP = %q, want %q", event.SourceIP, "10.0.0.50")
	}
	if event.SourcePort != 33221 {
		t.Errorf("SourcePort = %d, want %d", event.SourcePort, 33221)
	}
	if event.Source.Decoy != "test-tpot-01" {
		t.Errorf("Source.Decoy = %q, want %q", event.Source.Decoy, "test-tpot-01")
	}
	if event.Source.Tier != 4 {
		t.Errorf("Source.Tier = %d, want %d", event.Source.Tier, 4)
	}
	if event.Data["accepted"] != true {
		t.Errorf("Data[accepted] = %v, want true", event.Data["accepted"])
	}
	if event.Data["username"] != "root" {
		t.Errorf("Data[username] = %v, want %q", event.Data["username"], "root")
	}
	if event.Data["protocol"] != "ssh" {
		t.Errorf("Data[protocol] = %v, want %q", event.Data["protocol"], "ssh")
	}
}

func TestTranslate_HoneypotTypes(t *testing.T) {
	a := newTestAdapter()

	tests := []struct {
		name         string
		hit          esHit
		wantType     string
		wantSeverity string
		wantNil      bool
		checkData    map[string]any
	}{
		{
			name: "cowrie_login_failed",
			hit: esHit{
				Source: map[string]any{
					"type":       "cowrie",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.1",
					"eventid":    "cowrie.login.failed",
					"username":   "admin",
					"password":   "admin",
				},
			},
			wantType:     "auth.attempt",
			wantSeverity: "medium",
			checkData: map[string]any{
				"accepted": false,
				"username": "admin",
			},
		},
		{
			name: "cowrie_command_input",
			hit: esHit{
				Source: map[string]any{
					"type":       "cowrie",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.2",
					"eventid":    "cowrie.command.input",
					"input":      "whoami",
					"username":   "root",
				},
			},
			wantType:     "command.exec",
			wantSeverity: "medium",
			checkData: map[string]any{
				"command": "whoami",
			},
		},
		{
			name: "cowrie_file_download",
			hit: esHit{
				Source: map[string]any{
					"type":       "cowrie",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.3",
					"eventid":    "cowrie.session.file_download",
					"url":        "http://evil.com/payload",
					"shasum":     "abc123",
				},
			},
			wantType:     "file.access",
			wantSeverity: "high",
			checkData: map[string]any{
				"access_type": "download",
				"url":         "http://evil.com/payload",
				"sha256":      "abc123",
			},
		},
		{
			name: "cowrie_unknown_eventid",
			hit: esHit{
				Source: map[string]any{
					"type":       "cowrie",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.4",
					"eventid":    "cowrie.session.connect",
				},
			},
			wantType:     "connection",
			wantSeverity: "info",
		},
		{
			name: "dionaea_accept",
			hit: esHit{
				Source: map[string]any{
					"type":            "dionaea",
					"@timestamp":      "2024-01-01T00:00:00Z",
					"src_ip":          "10.0.0.5",
					"connection_type": "accept",
					"dst_port":        float64(445),
					"connection_protocol": "smbd",
				},
			},
			wantType:     "connection",
			wantSeverity: "info",
			checkData: map[string]any{
				"protocol": "smbd",
			},
		},
		{
			name: "dionaea_other",
			hit: esHit{
				Source: map[string]any{
					"type":                "dionaea",
					"@timestamp":          "2024-01-01T00:00:00Z",
					"src_ip":              "10.0.0.6",
					"connection_type":     "reject",
					"connection_protocol": "httpd",
				},
			},
			wantType:     "connection",
			wantSeverity: "info",
			checkData: map[string]any{
				"connection_type": "reject",
			},
		},
		{
			name: "conpot",
			hit: esHit{
				Source: map[string]any{
					"type":       "conpot",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.7",
					"data_type":  "modbus",
					"request":    "read_holding_registers",
				},
			},
			wantType:     "connection",
			wantSeverity: "medium",
			checkData: map[string]any{
				"protocol":   "modbus",
				"ics_device": "conpot",
			},
		},
		{
			name: "honeytrap_generic",
			hit: esHit{
				Source: map[string]any{
					"type":       "honeytrap",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.8",
					"dst_port":   float64(8080),
				},
			},
			wantType:     "connection",
			wantSeverity: "info",
			checkData: map[string]any{
				"honeypot_type": "honeytrap",
			},
		},
		{
			name: "glutton_generic",
			hit: esHit{
				Source: map[string]any{
					"type":       "glutton",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.9",
					"dst_port":   float64(23),
				},
			},
			wantType:     "connection",
			wantSeverity: "info",
			checkData: map[string]any{
				"honeypot_type": "glutton",
			},
		},
		{
			name: "unknown_honeypot_generic",
			hit: esHit{
				Source: map[string]any{
					"type":       "some-new-honeypot",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.10",
					"dst_port":   float64(80),
				},
			},
			wantType:     "connection",
			wantSeverity: "info",
			checkData: map[string]any{
				"honeypot_type": "some-new-honeypot",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := a.translate(tt.hit)
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
			if event.Adapter.Name != "tpot" {
				t.Errorf("Adapter.Name = %q, want %q", event.Adapter.Name, "tpot")
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

func TestTranslate_EmptySource(t *testing.T) {
	a := newTestAdapter()

	hit := esHit{
		Source: map[string]any{},
	}
	event, err := a.translate(hit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty type -> falls through to translateGeneric with empty string
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.EventType != "connection" {
		t.Errorf("EventType = %q, want %q", event.EventType, "connection")
	}
}

func TestTranslate_MissingTimestamp(t *testing.T) {
	a := newTestAdapter()

	hit := esHit{
		Source: map[string]any{
			"type":   "cowrie",
			"src_ip": "10.0.0.1",
		},
	}
	event, err := a.translate(hit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	// Timestamp should be the default from NewEvent (approximately now)
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestTranslate_InvalidTimestamp(t *testing.T) {
	a := newTestAdapter()

	hit := esHit{
		Source: map[string]any{
			"type":       "cowrie",
			"@timestamp": "not-a-timestamp",
			"src_ip":     "10.0.0.1",
		},
	}
	event, err := a.translate(hit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	// Should still have a valid timestamp from NewEvent default
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero even with invalid input")
	}
}

func TestTranslate_SessionIDFormat(t *testing.T) {
	a := newTestAdapter()

	hit := esHit{
		Source: map[string]any{
			"type":       "cowrie",
			"@timestamp": "2024-06-15T10:30:45.000Z",
			"src_ip":     "192.168.1.100",
			"eventid":    "cowrie.session.connect",
		},
	}
	event, err := a.translate(hit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatal("expected event, got nil")
	}

	// Session ID should follow the pattern: prefix-type-ip-timestamp
	expected := "tpot-cowrie-192.168.1.100-20240615-103045"
	if event.SessionID != expected {
		t.Errorf("SessionID = %q, want %q", event.SessionID, expected)
	}
}

func TestTranslate_NilSource(t *testing.T) {
	a := newTestAdapter()

	hit := esHit{
		Source: nil,
	}
	// This should panic or handle gracefully -- test that it doesn't crash
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("translate panicked with nil source: %v", r)
		}
	}()
	// nil map access will panic -- this tests the current behavior
	// In production code, you'd want to add a nil check
	_, _ = a.translate(hit)
}

// ── Helper function tests ────────────────────────────────

func TestGetString(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]any
		key      string
		expected string
	}{
		{"present", map[string]any{"key": "value"}, "key", "value"},
		{"missing", map[string]any{"other": "value"}, "key", ""},
		{"wrong_type", map[string]any{"key": 42}, "key", ""},
		{"nil_value", map[string]any{"key": nil}, "key", ""},
		{"empty_string", map[string]any{"key": ""}, "key", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getString(tt.m, tt.key)
			if got != tt.expected {
				t.Errorf("getString(%v, %q) = %q, want %q", tt.m, tt.key, got, tt.expected)
			}
		})
	}
}

func TestGetInt(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]any
		key      string
		expected int
	}{
		{"float64", map[string]any{"key": float64(42)}, "key", 42},
		{"missing", map[string]any{"other": float64(1)}, "key", 0},
		{"wrong_type_string", map[string]any{"key": "42"}, "key", 0},
		{"nil_value", map[string]any{"key": nil}, "key", 0},
		{"zero", map[string]any{"key": float64(0)}, "key", 0},
		{"negative", map[string]any{"key": float64(-1)}, "key", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getInt(tt.m, tt.key)
			if got != tt.expected {
				t.Errorf("getInt(%v, %q) = %d, want %d", tt.m, tt.key, got, tt.expected)
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

	if a.common.SessionPrefix != "tpot" {
		t.Errorf("SessionPrefix = %q, want %q", a.common.SessionPrefix, "tpot")
	}
}

func TestNew_CustomSessionPrefix(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	a := New(DefaultConfig(), adapter.Config{
		DecoyName:     "test",
		DecoyTier:     1,
		SessionPrefix: "custom-tpot",
	}, logger)

	if a.common.SessionPrefix != "custom-tpot" {
		t.Errorf("SessionPrefix = %q, want %q", a.common.SessionPrefix, "custom-tpot")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ElasticsearchURL != "http://localhost:64298" {
		t.Errorf("ElasticsearchURL = %q, want %q", cfg.ElasticsearchURL, "http://localhost:64298")
	}
	if cfg.IndexPattern != "logstash-*" {
		t.Errorf("IndexPattern = %q, want %q", cfg.IndexPattern, "logstash-*")
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want %v", cfg.PollInterval, 5*time.Second)
	}
	if cfg.HoneypotFilter != nil {
		t.Errorf("HoneypotFilter = %v, want nil", cfg.HoneypotFilter)
	}
}

func TestName(t *testing.T) {
	a := newTestAdapter()
	if a.Name() != "tpot" {
		t.Errorf("Name() = %q, want %q", a.Name(), "tpot")
	}
}

func TestHealthCheck(t *testing.T) {
	a := newTestAdapter()
	// Current implementation always returns nil
	if err := a.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck() = %v, want nil", err)
	}
}

// ── NATS subject tests ──────────────────────────────────

func TestTranslate_NATSSubject(t *testing.T) {
	a := newTestAdapter()

	tests := []struct {
		name        string
		hit         esHit
		wantSubject string
	}{
		{
			name: "cowrie_auth",
			hit: esHit{
				Source: map[string]any{
					"type":       "cowrie",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.1",
					"eventid":    "cowrie.login.success",
				},
			},
			wantSubject: "cicdecoy.decoy.events.test-tpot-01.auth.attempt",
		},
		{
			name: "dionaea_connection",
			hit: esHit{
				Source: map[string]any{
					"type":            "dionaea",
					"@timestamp":      "2024-01-01T00:00:00Z",
					"src_ip":          "10.0.0.2",
					"connection_type": "accept",
				},
			},
			wantSubject: "cicdecoy.decoy.events.test-tpot-01.connection",
		},
		{
			name: "conpot_connection",
			hit: esHit{
				Source: map[string]any{
					"type":       "conpot",
					"@timestamp": "2024-01-01T00:00:00Z",
					"src_ip":     "10.0.0.3",
				},
			},
			wantSubject: "cicdecoy.decoy.events.test-tpot-01.connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := a.translate(tt.hit)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected event, got nil")
			}
			got := event.NATSSubject()
			if got != tt.wantSubject {
				t.Errorf("NATSSubject() = %q, want %q", got, tt.wantSubject)
			}
		})
	}
}

// ── Verify all events satisfy the schema contract ────────

func TestTranslate_SchemaContract(t *testing.T) {
	a := newTestAdapter()

	hits := []esHit{
		{Source: map[string]any{"type": "cowrie", "@timestamp": "2024-01-01T00:00:00Z", "src_ip": "1.2.3.4", "eventid": "cowrie.login.success"}},
		{Source: map[string]any{"type": "dionaea", "@timestamp": "2024-01-01T00:00:00Z", "src_ip": "1.2.3.5", "connection_type": "accept"}},
		{Source: map[string]any{"type": "conpot", "@timestamp": "2024-01-01T00:00:00Z", "src_ip": "1.2.3.6"}},
		{Source: map[string]any{"type": "honeytrap", "@timestamp": "2024-01-01T00:00:00Z", "src_ip": "1.2.3.7"}},
	}

	validEventTypes := map[string]bool{
		"connection":            true,
		"auth.attempt":          true,
		"auth.success":          true,
		"auth.failure":          true,
		"command.exec":          true,
		"file.access":           true,
		"alert":                 true,
		"honeytoken.triggered":  true,
		"session.closed":        true,
	}

	validSeverities := map[string]bool{
		"info": true, "low": true, "medium": true, "high": true, "critical": true,
	}

	for i, hit := range hits {
		t.Run(getString(hit.Source, "type"), func(t *testing.T) {
			event, err := a.translate(hit)
			if err != nil {
				t.Fatalf("hit %d: unexpected error: %v", i, err)
			}
			if event == nil {
				t.Fatalf("hit %d: expected event", i)
			}

			// Every event must have these fields
			if event.EventID == "" {
				t.Error("EventID is empty")
			}
			if event.Version != "1.0" {
				t.Errorf("Version = %q, want %q", event.Version, "1.0")
			}
			if event.Timestamp.IsZero() {
				t.Error("Timestamp is zero")
			}
			if event.Source.Decoy == "" {
				t.Error("Source.Decoy is empty")
			}
			if event.SessionID == "" {
				t.Error("SessionID is empty")
			}
			if !validEventTypes[event.EventType] {
				t.Errorf("EventType %q is not a valid CI/CDecoy event type", event.EventType)
			}
			if !validSeverities[event.Severity] {
				t.Errorf("Severity %q is not a valid severity", event.Severity)
			}
			if event.Data == nil {
				t.Error("Data is nil")
			}

			// Must serialize to valid JSON
			_, err = event.JSON()
			if err != nil {
				t.Errorf("JSON() failed: %v", err)
			}
		})
	}
}

// ── translateCowrie directly ────────────────────────────

func TestTranslateCowrie_AllEventIDs(t *testing.T) {
	a := newTestAdapter()
	base := schema.NewEvent("tpot", "test-tpot-01", 4)

	tests := []struct {
		name     string
		eventID  string
		wantType string
	}{
		{"login_success", "cowrie.login.success", "auth.attempt"},
		{"login_failed", "cowrie.login.failed", "auth.attempt"},
		{"command_input", "cowrie.command.input", "command.exec"},
		{"file_download", "cowrie.session.file_download", "file.access"},
		{"session_connect", "cowrie.session.connect", "connection"},
		{"client_version", "cowrie.client.version", "connection"},
		{"unknown", "cowrie.some.other.event", "connection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := map[string]any{
				"eventid": tt.eventID,
			}
			event, err := a.translateCowrie(base, src)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected event, got nil")
			}
			if event.EventType != tt.wantType {
				t.Errorf("EventType = %q, want %q", event.EventType, tt.wantType)
			}
		})
	}
}
