// Package cowrie implements the CI/CDecoy adapter for Cowrie SSH/Telnet honeypot.
//
// Cowrie outputs structured JSON events to a log file or various backends.
// This adapter tails the JSON log and translates each event into the
// CI/CDecoy common schema for publishing to NATS.
//
// Cowrie event types we handle:
//   cowrie.session.connect     → connection
//   cowrie.login.success       → auth.attempt (accepted: true)
//   cowrie.login.failed        → auth.attempt (accepted: false)
//   cowrie.command.input       → command.exec
//   cowrie.command.failed      → command.exec (with failed flag)
//   cowrie.session.file_download → file.access
//   cowrie.session.file_upload   → file.access
//   cowrie.session.closed      → session.closed
//   cowrie.client.version      → connection (SSH client info)
//   cowrie.client.kex          → connection (key exchange details)
//
// Cowrie docs: https://docs.cowrie.org/en/latest/
package cowrie

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cicdecoy/adapters/pkg/adapter"
	"github.com/cicdecoy/adapters/pkg/schema"
)

// CowrieAdapter reads Cowrie's JSON log and emits CI/CDecoy events.
type CowrieAdapter struct {
	cfg    Config
	common adapter.Config
	logger *slog.Logger
}

type Config struct {
	// Path to Cowrie's JSON log file.
	// Default: /var/log/cowrie/cowrie.json (standard Cowrie location)
	LogPath string `yaml:"log_path" env:"COWRIE_LOG_PATH"`
}

func DefaultConfig() Config {
	return Config{
		LogPath: "/var/log/cowrie/cowrie.json",
	}
}

func New(cfg Config, common adapter.Config, logger *slog.Logger) *CowrieAdapter {
	if common.SessionPrefix == "" {
		common.SessionPrefix = "cowrie"
	}
	return &CowrieAdapter{
		cfg:    cfg,
		common: common,
		logger: logger,
	}
}

func (a *CowrieAdapter) Name() string { return "cowrie" }

func (a *CowrieAdapter) HealthCheck(ctx context.Context) error {
	_, err := os.Stat(a.cfg.LogPath)
	return err
}

// Start tails the Cowrie JSON log and emits normalized events.
func (a *CowrieAdapter) Start(ctx context.Context, events chan<- schema.Event) error {
	a.logger.Info("cowrie adapter starting",
		"log_path", a.cfg.LogPath,
		"decoy_name", a.common.DecoyName,
	)

	f, err := os.Open(a.cfg.LogPath)
	if err != nil {
		return fmt.Errorf("open cowrie log: %w", err)
	}
	defer f.Close()

	// Seek to end — only process new events.
	// On first deploy you might want to process the full file;
	// add a --backfill flag for that.
	f.Seek(0, os.SEEK_END)

	scanner := bufio.NewScanner(f)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}

				event, err := a.translate([]byte(line))
				if err != nil {
					a.logger.Warn("failed to translate cowrie event",
						"error", err,
						"line", truncate(line, 200),
					)
					continue
				}
				if event != nil {
					events <- *event
				}
			} else {
				// No new lines — back off briefly then retry.
				// In production, replace with fsnotify or inotify.
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// ── Cowrie JSON structures ────────────────────────────

// cowrieEvent is the raw JSON structure Cowrie writes.
type cowrieEvent struct {
	EventID   string `json:"eventid"`    // e.g. "cowrie.login.success"
	Timestamp string `json:"timestamp"`  // "2024-01-18T14:03:22.847123Z"
	Session   string `json:"session"`    // Cowrie's session hex ID
	Src_IP    string `json:"src_ip"`
	Src_Port  int    `json:"src_port"`
	Dst_IP    string `json:"dst_ip"`
	Dst_Port  int    `json:"dst_port"`
	Sensor    string `json:"sensor"`
	Message   string `json:"message"`

	// Auth fields
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Command fields
	Input   string `json:"input,omitempty"`
	Success bool   `json:"success,omitempty"`

	// File transfer fields
	URL      string `json:"url,omitempty"`
	DestFile string `json:"destfile,omitempty"`
	Shasum   string `json:"shasum,omitempty"`
	Outfile  string `json:"outfile,omitempty"`

	// Client info
	Version  string `json:"version,omitempty"`  // SSH client version string
	HasshHex string `json:"hassh,omitempty"`    // HASSH fingerprint
	KexAlgs  string `json:"kexAlgs,omitempty"`  // Key exchange algorithms
}

// ── Translation logic ─────────────────────────────────

// translate converts a raw Cowrie JSON line into a CI/CDecoy event.
// Returns nil for event types we don't care about (e.g. internal cowrie logs).
func (a *CowrieAdapter) translate(raw []byte) (*schema.Event, error) {
	var ce cowrieEvent
	if err := json.Unmarshal(raw, &ce); err != nil {
		return nil, fmt.Errorf("unmarshal cowrie event: %w", err)
	}

	// Build the base event from our common schema
	event := schema.NewEvent("cowrie", a.common.DecoyName, a.common.DecoyTier)

	// Use Cowrie's timestamp if available
	if ts, err := time.Parse("2006-01-02T15:04:05.999999Z", ce.Timestamp); err == nil {
		event.Timestamp = ts
	}

	// Map Cowrie session ID → CI/CDecoy session ID with prefix
	event.SessionID = a.common.SessionPrefix + "-" + ce.Session

	// Network context
	event.SourceIP = ce.Src_IP
	event.SourcePort = ce.Src_Port

	// Preserve Cowrie's original event ID for debugging
	event.Adapter.OriginalEventID = ce.EventID

	// ── Map Cowrie event types to CI/CDecoy event types ──
	switch ce.EventID {

	case "cowrie.session.connect":
		event.EventType = "connection"
		event.Severity = "info"
		event.Data = map[string]any{
			"dst_ip":   ce.Dst_IP,
			"dst_port": ce.Dst_Port,
			"protocol": "ssh",
			"sensor":   ce.Sensor,
		}

	case "cowrie.client.version":
		event.EventType = "connection"
		event.Severity = "info"
		event.Data = map[string]any{
			"ssh_client_version": ce.Version,
			"hassh":              ce.HasshHex,
		}

	case "cowrie.login.success":
		event.EventType = "auth.attempt"
		event.Severity = "medium"
		event.Data = map[string]any{
			"client_ip":      ce.Src_IP,
			"client_port":    ce.Src_Port,
			"username":       ce.Username,
			"password":       ce.Password,
			"method":         "password",
			"accepted":       true,
			"reason":         "honeypot_accept",
		}

	case "cowrie.login.failed":
		event.EventType = "auth.attempt"
		event.Severity = "info"
		event.Data = map[string]any{
			"client_ip":   ce.Src_IP,
			"client_port": ce.Src_Port,
			"username":    ce.Username,
			"password":    ce.Password,
			"method":      "password",
			"accepted":    false,
		}

	case "cowrie.command.input":
		event.EventType = "command.exec"
		event.Severity = classifyCommandSeverity(ce.Input)
		event.Data = map[string]any{
			"command":  ce.Input,
			"username": ce.Username,
		}

	case "cowrie.command.failed":
		event.EventType = "command.exec"
		event.Severity = "info"
		event.Data = map[string]any{
			"command":  ce.Input,
			"username": ce.Username,
			"failed":   true,
		}

	case "cowrie.session.file_download":
		event.EventType = "file.access"
		event.Severity = "high"
		event.Data = map[string]any{
			"access_type": "download",
			"url":         ce.URL,
			"dest_file":   ce.DestFile,
			"sha256":      ce.Shasum,
		}

	case "cowrie.session.file_upload":
		event.EventType = "file.access"
		event.Severity = "high"
		event.Data = map[string]any{
			"access_type": "upload",
			"outfile":     ce.Outfile,
			"sha256":      ce.Shasum,
		}

	case "cowrie.session.closed":
		event.EventType = "session.closed"
		event.Severity = "info"
		event.Data = map[string]any{
			"message": ce.Message,
		}

	default:
		// Event types we don't translate (yet):
		// cowrie.direct-tcpip.request, cowrie.log.closed, etc.
		return nil, nil
	}

	return &event, nil
}

// classifyCommandSeverity does a rough baseline severity classification
// based on the command content. This is NOT the ATT&CK mapping — that
// happens in the enrichment service downstream. This is just so the
// event arrives with a reasonable severity before enrichment runs.
func classifyCommandSeverity(cmd string) string {
	lower := strings.ToLower(cmd)

	// High: clear signs of post-exploitation
	highIndicators := []string{
		"/etc/shadow", "/etc/passwd", ".ssh/", "authorized_keys",
		"wget ", "curl ", "chmod +x", "nc -", "ncat ",
		"/dev/tcp/", "base64", "python -c", "perl -e",
		"iptables", "history -c", "rm -rf",
	}
	for _, indicator := range highIndicators {
		if strings.Contains(lower, indicator) {
			return "high"
		}
	}

	// Medium: reconnaissance
	mediumIndicators := []string{
		"whoami", "id", "uname", "ifconfig", "ip addr",
		"cat /proc", "ps aux", "netstat", "ss -", "ls -la",
		"find /", "env", "printenv",
	}
	for _, indicator := range mediumIndicators {
		if strings.Contains(lower, indicator) {
			return "medium"
		}
	}

	return "info"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
