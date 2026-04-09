// Package tpot implements the CI/CDecoy adapter for T-Pot.
//
// T-Pot aggregates multiple honeypots (Cowrie, Dionaea, Conpot,
// Honeytrap, Glutton, etc.) behind a management layer with ELK.
// Rather than writing individual adapters for each honeypot inside
// T-Pot, we read from T-Pot's Elasticsearch index where events are
// already aggregated.
//
// This means someone already running T-Pot can point CI/CDecoy
// at their Elasticsearch instance and immediately get ATT&CK-mapped
// CTI from data they're already collecting.
//
// T-Pot ES index patterns:
//   logstash-*         (legacy)
//   tpot-*             (newer versions)
//   Individual indices per honeypot: cowrie-*, dionaea-*, etc.
//
// T-Pot docs: https://github.com/telekom-security/tpotce
package tpot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/cicdecoy/adapters/pkg/adapter"
	"github.com/cicdecoy/adapters/pkg/schema"
)

type TPotAdapter struct {
	cfg    Config
	common adapter.Config
	logger *slog.Logger

	// Track our read position per index
	lastTimestamp time.Time
}

type Config struct {
	// Elasticsearch URL for the T-Pot instance
	ElasticsearchURL string `yaml:"elasticsearch_url" env:"TPOT_ES_URL"`

	// Index pattern to query
	IndexPattern string `yaml:"index_pattern" env:"TPOT_INDEX_PATTERN"`

	// Poll interval for new events
	PollInterval time.Duration `yaml:"poll_interval" env:"TPOT_POLL_INTERVAL"`

	// Optional: filter to specific honeypot types
	HoneypotFilter []string `yaml:"honeypot_filter" env:"TPOT_HONEYPOT_FILTER"`
}

func DefaultConfig() Config {
	return Config{
		ElasticsearchURL: "http://localhost:64298",
		IndexPattern:     "logstash-*",
		PollInterval:     5 * time.Second,
		HoneypotFilter:   nil, // all honeypots
	}
}

func New(cfg Config, common adapter.Config, logger *slog.Logger) *TPotAdapter {
	if common.SessionPrefix == "" {
		common.SessionPrefix = "tpot"
	}
	return &TPotAdapter{
		cfg:          cfg,
		common:       common,
		logger:       logger,
		lastTimestamp: time.Now().UTC(),
	}
}

func (a *TPotAdapter) Name() string { return "tpot" }

func (a *TPotAdapter) HealthCheck(ctx context.Context) error {
	// In real implementation: HTTP GET to ES _cluster/health
	return nil
}

// Start polls Elasticsearch for new events and emits them.
func (a *TPotAdapter) Start(ctx context.Context, events chan<- schema.Event) error {
	a.logger.Info("tpot adapter starting",
		"elasticsearch", a.cfg.ElasticsearchURL,
		"index", a.cfg.IndexPattern,
		"decoy_name", a.common.DecoyName,
	)

	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			hits, err := a.queryNewEvents(ctx)
			if err != nil {
				a.logger.Error("elasticsearch query failed", "error", err)
				continue
			}
			for _, hit := range hits {
				event, err := a.translate(hit)
				if err != nil {
					a.logger.Warn("failed to translate tpot event", "error", err)
					continue
				}
				if event != nil {
					events <- *event
				}
			}
		}
	}
}

// ── Elasticsearch interaction ─────────────────────────

// esHit represents a single document from T-Pot's ES index.
type esHit struct {
	Source map[string]any `json:"_source"`
	Index  string        `json:"_index"`
}

// queryNewEvents fetches events newer than our last checkpoint.
// In real implementation this builds and executes an ES query.
// Mock-up shows the query structure.
func (a *TPotAdapter) queryNewEvents(ctx context.Context) ([]esHit, error) {
	// The ES query would look like:
	//
	// POST /logstash-*/_search
	// {
	//   "query": {
	//     "bool": {
	//       "must": [
	//         {"range": {"@timestamp": {"gt": lastTimestamp}}}
	//       ],
	//       "filter": [
	//         {"terms": {"type": ["cowrie", "dionaea", "conpot"]}}  // if filtered
	//       ]
	//     }
	//   },
	//   "sort": [{"@timestamp": "asc"}],
	//   "size": 500
	// }

	// In real implementation:
	// - Build query JSON
	// - HTTP POST to a.cfg.ElasticsearchURL + "/" + a.cfg.IndexPattern + "/_search"
	// - Parse response, extract hits
	// - Update a.lastTimestamp from the last hit

	_ = ctx
	return nil, fmt.Errorf("not implemented — mock-up only")
}

// ── Translation logic ─────────────────────────────────

// translate converts a T-Pot ES document into a CI/CDecoy event.
// T-Pot normalizes some fields across honeypots, but the structure
// varies by which honeypot generated the event.
func (a *TPotAdapter) translate(hit esHit) (*schema.Event, error) {
	src := hit.Source

	event := schema.NewEvent("tpot", a.common.DecoyName, a.common.DecoyTier)
	event.Adapter.OriginalEventID = getString(src, "_id")

	// Parse timestamp
	if ts, ok := src["@timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			event.Timestamp = t
		}
	}

	// Common T-Pot fields present across all honeypot types
	event.SourceIP = getString(src, "src_ip")
	event.SourcePort = getInt(src, "src_port")

	// Determine which honeypot generated this event
	honeypotType := getString(src, "type")

	// Build a session ID from honeypot type + source IP + time bucket
	// T-Pot doesn't always propagate the underlying honeypot's session ID,
	// so we synthesize one that enables reasonable correlation.
	event.SessionID = fmt.Sprintf("%s-%s-%s-%s",
		a.common.SessionPrefix,
		honeypotType,
		event.SourceIP,
		event.Timestamp.Format("20060102-150405"),
	)

	switch honeypotType {

	case "cowrie":
		return a.translateCowrie(event, src)

	case "dionaea":
		return a.translateDionaea(event, src)

	case "conpot":
		return a.translateConpot(event, src)

	case "honeytrap":
		return a.translateGeneric(event, src, "honeytrap")

	case "glutton":
		return a.translateGeneric(event, src, "glutton")

	default:
		// Unknown honeypot type — still ingest as a generic connection
		return a.translateGeneric(event, src, honeypotType)
	}
}

// translateCowrie handles Cowrie events that came through T-Pot.
// T-Pot's Logstash pipeline partially normalizes Cowrie output.
func (a *TPotAdapter) translateCowrie(event schema.Event, src map[string]any) (*schema.Event, error) {
	eventID := getString(src, "eventid")

	switch {
	case eventID == "cowrie.login.success" || eventID == "cowrie.login.failed":
		event.EventType = "auth.attempt"
		event.Severity = "medium"
		accepted := eventID == "cowrie.login.success"
		event.Data = map[string]any{
			"client_ip": event.SourceIP,
			"username":  getString(src, "username"),
			"password":  getString(src, "password"),
			"method":    "password",
			"accepted":  accepted,
			"protocol":  "ssh",
		}

	case eventID == "cowrie.command.input":
		event.EventType = "command.exec"
		event.Severity = "medium"
		event.Data = map[string]any{
			"command":  getString(src, "input"),
			"username": getString(src, "username"),
			"protocol": "ssh",
		}

	case eventID == "cowrie.session.file_download":
		event.EventType = "file.access"
		event.Severity = "high"
		event.Data = map[string]any{
			"access_type": "download",
			"url":         getString(src, "url"),
			"sha256":      getString(src, "shasum"),
			"protocol":    "ssh",
		}

	default:
		event.EventType = "connection"
		event.Severity = "info"
		event.Data = map[string]any{
			"protocol":       "ssh",
			"cowrie_eventid": eventID,
		}
	}

	return &event, nil
}

// translateDionaea handles Dionaea events from T-Pot.
func (a *TPotAdapter) translateDionaea(event schema.Event, src map[string]any) (*schema.Event, error) {
	connType := getString(src, "connection_type")

	switch connType {
	case "accept":
		event.EventType = "connection"
		event.Severity = "info"
		event.Data = map[string]any{
			"dst_port": getInt(src, "dst_port"),
			"protocol": getString(src, "connection_protocol"),
		}

	default:
		event.EventType = "connection"
		event.Severity = "info"
		event.Data = map[string]any{
			"protocol":        getString(src, "connection_protocol"),
			"connection_type": connType,
		}
	}

	return &event, nil
}

// translateConpot handles Conpot ICS/SCADA honeypot events from T-Pot.
// These are particularly interesting for OT-focused deception.
func (a *TPotAdapter) translateConpot(event schema.Event, src map[string]any) (*schema.Event, error) {
	event.EventType = "connection"
	event.Severity = "medium" // ICS probing is inherently interesting
	event.Data = map[string]any{
		"protocol":   getString(src, "data_type"),
		"request":    getString(src, "request"),
		"ics_device": "conpot",
	}
	return &event, nil
}

// translateGeneric handles any honeypot we don't have specific logic for.
// Captures what we can from common T-Pot fields.
func (a *TPotAdapter) translateGeneric(event schema.Event, src map[string]any, hpType string) (*schema.Event, error) {
	event.EventType = "connection"
	event.Severity = "info"
	event.Data = map[string]any{
		"dst_port":      getInt(src, "dst_port"),
		"honeypot_type": hpType,
	}
	return &event, nil
}

// ── Helpers ───────────────────────────────────────────

func getString(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func getInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	default:
		return 0
	}
}
