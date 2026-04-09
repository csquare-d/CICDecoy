// Package dionaea implements the CI/CDecoy adapter for the Dionaea honeypot.
//
// Dionaea captures malware by emulating vulnerable services (SMB, HTTP,
// FTP, MSSQL, MySQL, SIP, etc.). Its primary value is malware collection,
// but the connection and credential data is useful CTI too.
//
// Dionaea can log to JSON via its log_json module or to SQLite.
// This adapter reads from the JSON log (simpler, streamable).
//
// Dionaea JSON event types we handle:
//   connection    → connection
//   download      → file.access
//   login         → auth.attempt
//   sip_command   → command.exec (SIP-specific)
//
// Dionaea docs: https://dionaea.readthedocs.io/
package dionaea

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/cicdecoy/adapters/pkg/adapter"
	"github.com/cicdecoy/adapters/pkg/schema"
)

type DionaeaAdapter struct {
	cfg    Config
	common adapter.Config
	logger *slog.Logger
}

type Config struct {
	LogPath string `yaml:"log_path" env:"DIONAEA_LOG_PATH"`
}

func DefaultConfig() Config {
	return Config{
		LogPath: "/var/lib/dionaea/dionaea.json",
	}
}

func New(cfg Config, common adapter.Config, logger *slog.Logger) *DionaeaAdapter {
	if common.SessionPrefix == "" {
		common.SessionPrefix = "dionaea"
	}
	return &DionaeaAdapter{
		cfg:    cfg,
		common: common,
		logger: logger,
	}
}

func (a *DionaeaAdapter) Name() string { return "dionaea" }

func (a *DionaeaAdapter) HealthCheck(ctx context.Context) error {
	_, err := os.Stat(a.cfg.LogPath)
	return err
}

func (a *DionaeaAdapter) Start(ctx context.Context, events chan<- schema.Event) error {
	a.logger.Info("dionaea adapter starting",
		"log_path", a.cfg.LogPath,
		"decoy_name", a.common.DecoyName,
	)

	f, err := os.Open(a.cfg.LogPath)
	if err != nil {
		return fmt.Errorf("open dionaea log: %w", err)
	}
	defer f.Close()

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
					a.logger.Warn("failed to translate dionaea event",
						"error", err,
					)
					continue
				}
				if event != nil {
					events <- *event
				}
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// ── Dionaea JSON structures ───────────────────────────

type dionaeaEvent struct {
	Type      string `json:"type"`       // "connection", "download", etc.
	Timestamp string `json:"timestamp"`
	ConnID    int64  `json:"connection"`  // Dionaea uses numeric connection IDs

	// Connection fields
	LocalIP    string `json:"local_host"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
	Protocol   string `json:"protocol"`   // "smbd", "httpd", "ftpd", etc.
	Transport  string `json:"transport"`  // "tcp", "udp"

	// Download fields
	URL     string `json:"url,omitempty"`
	MD5     string `json:"md5hash,omitempty"`
	SHA512  string `json:"sha512hash,omitempty"`

	// Auth fields
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func (a *DionaeaAdapter) translate(raw []byte) (*schema.Event, error) {
	var de dionaeaEvent
	if err := json.Unmarshal(raw, &de); err != nil {
		return nil, fmt.Errorf("unmarshal dionaea event: %w", err)
	}

	event := schema.NewEvent("dionaea", a.common.DecoyName, a.common.DecoyTier)

	if ts, err := time.Parse("2006-01-02 15:04:05", de.Timestamp); err == nil {
		event.Timestamp = ts
	}

	// Dionaea uses numeric connection IDs — prefix to avoid collisions
	event.SessionID = fmt.Sprintf("%s-%d", a.common.SessionPrefix, de.ConnID)
	event.SourceIP = de.RemoteIP
	event.SourcePort = de.RemotePort
	event.Adapter.OriginalEventID = fmt.Sprintf("dionaea-conn-%d", de.ConnID)

	// Map Dionaea's protocol identifiers to readable names
	protocol := mapDionaeaProtocol(de.Protocol)

	switch de.Type {

	case "connection":
		event.EventType = "connection"
		event.Severity = "info"
		event.Data = map[string]any{
			"dst_ip":    de.LocalIP,
			"dst_port":  de.LocalPort,
			"protocol":  protocol,
			"transport": de.Transport,
		}

	case "download":
		event.EventType = "file.access"
		event.Severity = "high"
		event.Data = map[string]any{
			"access_type": "download",
			"url":         de.URL,
			"md5":         de.MD5,
			"sha512":      de.SHA512,
			"protocol":    protocol,
		}

	case "login":
		event.EventType = "auth.attempt"
		event.Severity = "medium"
		event.Data = map[string]any{
			"client_ip":   de.RemoteIP,
			"client_port": de.RemotePort,
			"username":    de.Username,
			"password":    de.Password,
			"method":      "password",
			"protocol":    protocol,
			"accepted":    false, // Dionaea typically logs all attempts
		}

	default:
		return nil, nil
	}

	return &event, nil
}

// mapDionaeaProtocol translates Dionaea's internal protocol names
// to human-readable protocol names.
func mapDionaeaProtocol(p string) string {
	switch p {
	case "smbd":
		return "smb"
	case "httpd":
		return "http"
	case "ftpd":
		return "ftp"
	case "mysqld":
		return "mysql"
	case "mssqld":
		return "mssql"
	case "SipSession":
		return "sip"
	case "pptp":
		return "pptp"
	case "upnp":
		return "upnp"
	default:
		return p
	}
}
