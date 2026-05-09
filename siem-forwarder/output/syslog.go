package output

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// SyslogConfig holds configuration for the syslog output.
type SyslogConfig struct {
	Endpoint string // "host:port"
	Protocol string // "tcp" or "udp"
	Facility string // "local0" through "local7"
}

type SyslogSink struct {
	cfg    SyslogConfig
	conn   net.Conn
	mu     sync.Mutex
	logger *slog.Logger
}

func NewSyslog(cfg SyslogConfig, logger *slog.Logger) (*SyslogSink, error) {
	if cfg.Protocol == "" {
		cfg.Protocol = "tcp"
	}
	if cfg.Protocol != "tcp" && cfg.Protocol != "udp" {
		return nil, fmt.Errorf("invalid syslog protocol %q: must be tcp or udp", cfg.Protocol)
	}
	if cfg.Facility == "" {
		cfg.Facility = "local0"
	}

	s := &SyslogSink{
		cfg:    cfg,
		logger: logger.With("sink", "syslog"),
	}

	if err := s.connect(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *SyslogSink) connect() error {
	// Close old connection to avoid file descriptor leak
	if s.conn != nil {
		_ = s.conn.Close()
	}
	conn, err := net.DialTimeout(s.cfg.Protocol, s.cfg.Endpoint, 10*time.Second)
	if err != nil {
		return fmt.Errorf("syslog connect to %s/%s: %w", s.cfg.Protocol, s.cfg.Endpoint, err)
	}
	s.conn = conn
	s.logger.Info("connected to syslog",
		"endpoint", s.cfg.Endpoint,
		"protocol", s.cfg.Protocol,
	)
	return nil
}

func (s *SyslogSink) Send(records []Record) []Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]Result, len(records))

	for i, rec := range records {
		// RFC 5424 syslog message format:
		// <priority>1 timestamp hostname app-name procid msgid msg
		priority := facilityCode(s.cfg.Facility)*8 + 6 // facility + severity INFO
		msg := fmt.Sprintf("<%d>1 %s cicdecoy siem-forwarder - - %s\n",
			priority,
			time.Now().UTC().Format(time.RFC3339),
			string(rec.Data),
		)

		if err := s.write([]byte(msg)); err != nil {
			// Try reconnecting once
			s.logger.Warn("syslog write failed, reconnecting", "error", err)
			if reconnErr := s.connect(); reconnErr != nil {
				results[i] = Result{NATSMsg: rec.NATSMsg, Err: reconnErr}
				continue
			}
			// Retry after reconnect
			if err := s.write([]byte(msg)); err != nil {
				results[i] = Result{NATSMsg: rec.NATSMsg, Err: err}
				continue
			}
		}

		results[i] = Result{NATSMsg: rec.NATSMsg, Err: nil}
	}

	return results
}

func (s *SyslogSink) write(data []byte) error {
	if s.conn == nil {
		return fmt.Errorf("no syslog connection")
	}
	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.conn.Write(data)
	return err
}

func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func facilityCode(facility string) int {
	facilities := map[string]int{
		"local0": 16, "local1": 17, "local2": 18, "local3": 19,
		"local4": 20, "local5": 21, "local6": 22, "local7": 23,
	}
	if code, ok := facilities[strings.ToLower(facility)]; ok {
		return code
	}
	return 16 // default: local0
}
