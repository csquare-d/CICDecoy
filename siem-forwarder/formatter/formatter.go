// Package formatter transforms raw CI/CDecoy events into
// SIEM-consumable formats. Each formatter takes the NATS subject
// and a parsed event map, and returns serialized bytes in the
// target format.
//
// The raw event from NATS looks roughly like:
//
//	{
//	  "event_id": "evt-abc123",
//	  "event_type": "command.exec",
//	  "timestamp": "2025-03-26T14:03:22.847Z",
//	  "session_id": "sess-xyz",
//	  "decoy_name": "bastion-dmz-01",
//	  "decoy_tier": 2,
//	  "source_ip": "198.51.100.42",
//	  "source_port": 54321,
//	  "protocol": "ssh",
//	  "data": { "command": "cat /etc/passwd", "response": "..." },
//	  "raw_data": { ... }
//	}
//
// Formatters reshape this into the target schema without adding
// any enrichment (no ATT&CK mapping, no GeoIP, no severity scoring).
// That's the CTI pipeline's job.
package formatter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Formatter transforms a parsed event into serialized bytes
// for a specific SIEM format.
type Formatter interface {
	// Format takes the NATS subject and parsed event, returns
	// serialized bytes ready for the output sink.
	Format(subject string, event map[string]interface{}) ([]byte, error)

	// Name returns the format identifier for logging.
	Name() string
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  JSON — Passthrough with envelope
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// JSONFormatter passes the event through as structured JSON
// with a thin envelope for SIEM indexing. This is the simplest
// and most flexible format — works with any SIEM that accepts JSON.
type JSONFormatter struct{}

func NewJSON() *JSONFormatter { return &JSONFormatter{} }

func (f *JSONFormatter) Name() string { return "json" }

func (f *JSONFormatter) Format(subject string, event map[string]interface{}) ([]byte, error) {
	// Ensure there's always a top-level timestamp for SIEM parsing.
	if _, ok := event["timestamp"]; !ok {
		event["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	// Tag the source so SIEM rules can filter on it.
	event["_source"] = "cicdecoy"
	event["_format_version"] = "1.0"

	return json.Marshal(event)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  CEF — ArcSight Common Event Format
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// CEFFormatter outputs ArcSight CEF format. Used by ArcSight,
// QRadar (via CEF), and many legacy SIEMs.
//
// Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
type CEFFormatter struct{}

func NewCEF() *CEFFormatter { return &CEFFormatter{} }

func (f *CEFFormatter) Name() string { return "cef" }

func (f *CEFFormatter) Format(subject string, event map[string]interface{}) ([]byte, error) {
	eventType := getString(event, "event_type")
	severity := mapCEFSeverity(eventType, subject)
	signatureID := eventTypeToCEFSignature(eventType)
	name := cefEventName(eventType)

	// Build extension key-value pairs
	ext := []string{}

	if v := getString(event, "source_ip"); v != "" {
		ext = append(ext, "src="+cefEscape(v))
	}
	if v := getString(event, "source_port"); v != "" {
		ext = append(ext, "spt="+v)
	}
	if v := getString(event, "decoy_name"); v != "" {
		ext = append(ext, "dhost="+cefEscape(v))
	}
	if v := getString(event, "protocol"); v != "" {
		ext = append(ext, "proto="+cefEscape(v))
	}
	if v := getString(event, "session_id"); v != "" {
		ext = append(ext, "externalId="+cefEscape(v))
	}
	if v := getString(event, "event_id"); v != "" {
		ext = append(ext, "cs1="+cefEscape(v))
		ext = append(ext, "cs1Label=EventID")
	}
	if v := getString(event, "timestamp"); v != "" {
		ext = append(ext, "rt="+cefEscape(v))
	}

	// Extract command from nested data if present
	if data, ok := event["data"].(map[string]interface{}); ok {
		if cmd := getString(data, "command"); cmd != "" {
			ext = append(ext, "cs2="+cefEscape(cmd))
			ext = append(ext, "cs2Label=Command")
		}
		if user := getString(data, "username"); user != "" {
			ext = append(ext, "suser="+cefEscape(user))
		}
	}

	// Also check top-level username
	if v := getString(event, "username"); v != "" {
		ext = append(ext, "suser="+cefEscape(v))
	}

	// Decoy tier as custom field
	if v := getString(event, "decoy_tier"); v != "" {
		ext = append(ext, "cs3="+v)
		ext = append(ext, "cs3Label=DecoyTier")
	}

	// Falco-specific fields
	if strings.Contains(subject, "falco") {
		if v := getString(event, "rule"); v != "" {
			ext = append(ext, "cs4="+cefEscape(v))
			ext = append(ext, "cs4Label=FalcoRule")
		}
		if v := getString(event, "output"); v != "" {
			ext = append(ext, "msg="+cefEscape(v))
		}
	}

	cef := fmt.Sprintf("CEF:0|CICDecoy|SIEMForwarder|1.0|%s|%s|%d|%s",
		cefEscape(signatureID),
		cefEscape(name),
		severity,
		strings.Join(ext, " "),
	)

	return []byte(cef), nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  LEEF — IBM QRadar Log Event Extended Format
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// LEEFFormatter outputs IBM LEEF 2.0 format, native to QRadar.
//
// leefEscape escapes values for LEEF format.  LEEF uses tab as the
// key-value pair separator, so tabs, newlines, and backslashes must
// be escaped.
func leefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

// Format: LEEF:2.0|Vendor|Product|Version|EventID|<tab-separated KV>
type LEEFFormatter struct{}

func NewLEEF() *LEEFFormatter { return &LEEFFormatter{} }

func (f *LEEFFormatter) Name() string { return "leef" }

func (f *LEEFFormatter) Format(subject string, event map[string]interface{}) ([]byte, error) {
	eventType := getString(event, "event_type")
	eventID := eventTypeToCEFSignature(eventType) // reuse the mapping

	kvs := []string{}

	if v := getString(event, "source_ip"); v != "" {
		kvs = append(kvs, "src="+leefEscape(v))
	}
	if v := getString(event, "source_port"); v != "" {
		kvs = append(kvs, "srcPort="+leefEscape(v))
	}
	if v := getString(event, "decoy_name"); v != "" {
		kvs = append(kvs, "dstName="+leefEscape(v))
	}
	if v := getString(event, "protocol"); v != "" {
		kvs = append(kvs, "proto="+leefEscape(v))
	}
	if v := getString(event, "session_id"); v != "" {
		kvs = append(kvs, "sessionID="+leefEscape(v))
	}
	if v := getString(event, "timestamp"); v != "" {
		kvs = append(kvs, "devTime="+leefEscape(v))
	}
	if v := getString(event, "username"); v != "" {
		kvs = append(kvs, "usrName="+leefEscape(v))
	}

	if data, ok := event["data"].(map[string]interface{}); ok {
		if cmd := getString(data, "command"); cmd != "" {
			kvs = append(kvs, "command="+leefEscape(cmd))
		}
	}

	sev := mapCEFSeverity(eventType, subject)
	kvs = append(kvs, fmt.Sprintf("sev=%d", sev))

	leef := fmt.Sprintf("LEEF:2.0|CICDecoy|SIEMForwarder|1.0|%s|\t%s",
		eventID,
		strings.Join(kvs, "\t"),
	)

	return []byte(leef), nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ECS — Elastic Common Schema
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ECSFormatter maps events to Elastic Common Schema v8.x.
// This gives the best out-of-box experience with Kibana,
// Elastic SIEM, and Elastic Security.
type ECSFormatter struct{}

func NewECS() *ECSFormatter { return &ECSFormatter{} }

func (f *ECSFormatter) Name() string { return "ecs" }

func (f *ECSFormatter) Format(subject string, event map[string]interface{}) ([]byte, error) {
	ecs := map[string]interface{}{
		// ECS base fields
		"@timestamp": getTimestamp(event),
		"message":    getString(event, "event_type"),
		"tags":       []string{"cicdecoy", "honeypot"},

		// ECS event fields
		"event": map[string]interface{}{
			"kind":     "alert",
			"category": []string{"intrusion_detection"},
			"type":     []string{ecsEventType(getString(event, "event_type"))},
			"module":   "cicdecoy",
			"dataset":  "cicdecoy.raw",
			"id":       getString(event, "event_id"),
			"action":   getString(event, "event_type"),
		},

		// ECS source fields
		"source": map[string]interface{}{
			"ip":   getString(event, "source_ip"),
			"port": getNumber(event, "source_port"),
		},

		// ECS observer (the decoy itself)
		"observer": map[string]interface{}{
			"name":    getString(event, "decoy_name"),
			"type":    "honeypot",
			"product": "cicdecoy",
			"vendor":  "cicdecoy",
		},

		// ECS network
		"network": map[string]interface{}{
			"protocol": getString(event, "protocol"),
		},

		// Preserve the original event for full fidelity
		"cicdecoy": map[string]interface{}{
			"session_id": getString(event, "session_id"),
			"decoy_tier": getNumber(event, "decoy_tier"),
			"raw_event":  event,
		},
	}

	// Add user info if present
	if user := getString(event, "username"); user != "" {
		ecs["user"] = map[string]interface{}{
			"name": user,
		}
	}

	// Add process info for command events
	if data, ok := event["data"].(map[string]interface{}); ok {
		if cmd := getString(data, "command"); cmd != "" {
			ecs["process"] = map[string]interface{}{
				"command_line": cmd,
			}
		}
	}

	// Falco-specific ECS mapping
	if strings.Contains(subject, "falco") {
		ecs["event"].(map[string]interface{})["category"] = []string{"intrusion_detection", "process"}
		ecs["rule"] = map[string]interface{}{
			"name":        getString(event, "rule"),
			"description": getString(event, "output"),
		}
		if priority := getString(event, "priority"); priority != "" {
			ecs["event"].(map[string]interface{})["severity"] = falcoPriorityToECS(priority)
		}
	}

	return json.Marshal(ecs)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func getNumber(m map[string]interface{}, key string) interface{} {
	if v, ok := m[key]; ok {
		return v
	}
	return nil
}

func getTimestamp(event map[string]interface{}) string {
	if v := getString(event, "timestamp"); v != "" {
		return v
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// cefEscape escapes characters that are special in CEF format.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

// eventTypeToCEFSignature maps CI/CDecoy event types to CEF signature IDs.
func eventTypeToCEFSignature(eventType string) string {
	signatures := map[string]string{
		"connection.new":     "CICD-1001",
		"connection.close":   "CICD-1002",
		"auth.attempt":       "CICD-2001",
		"auth.success":       "CICD-2002",
		"auth.failure":       "CICD-2003",
		"command.exec":       "CICD-3001",
		"command.response":   "CICD-3002",
		"file.upload":        "CICD-4001",
		"file.download":      "CICD-4002",
		"session.start":      "CICD-5001",
		"session.end":        "CICD-5002",
		"honeytoken.trigger": "CICD-6001",
		"falco.alert":        "CICD-7001",
	}
	if sig, ok := signatures[eventType]; ok {
		return sig
	}
	return "CICD-9999" // Unknown event type
}

func cefEventName(eventType string) string {
	names := map[string]string{
		"connection.new":     "New Connection to Decoy",
		"connection.close":   "Connection Closed",
		"auth.attempt":       "Authentication Attempt",
		"auth.success":       "Authentication Success",
		"auth.failure":       "Authentication Failure",
		"command.exec":       "Command Executed in Decoy",
		"command.response":   "Command Response",
		"file.upload":        "File Upload to Decoy",
		"file.download":      "File Download from Decoy",
		"session.start":      "Interactive Session Started",
		"session.end":        "Session Ended",
		"honeytoken.trigger": "Honeytoken Triggered",
	}
	if name, ok := names[eventType]; ok {
		return name
	}
	return "CICDecoy Event: " + eventType
}

// mapCEFSeverity returns a CEF severity (0-10) based on event type.
// Without enrichment we can't do deep severity analysis, but we
// can assign baseline severities based on what the event represents.
func mapCEFSeverity(eventType, subject string) int {
	// Falco alerts are always high — they indicate kernel-level activity.
	if strings.Contains(subject, "falco") {
		return 8
	}
	if strings.Contains(subject, "honeytoken") {
		return 9
	}

	severities := map[string]int{
		"connection.new":   3,
		"connection.close": 1,
		"auth.attempt":     4,
		"auth.success":     6, // successful auth to a decoy is notable
		"auth.failure":     3,
		"command.exec":     5,
		"command.response": 2,
		"file.upload":      7, // uploading to a decoy is suspicious
		"file.download":    5,
		"session.start":    5,
		"session.end":      2,
	}
	if sev, ok := severities[eventType]; ok {
		return sev
	}
	return 3
}

func ecsEventType(eventType string) string {
	switch {
	case strings.HasPrefix(eventType, "connection"):
		return "connection"
	case strings.HasPrefix(eventType, "auth"):
		return "access"
	case strings.HasPrefix(eventType, "command"):
		return "info"
	case strings.HasPrefix(eventType, "file"):
		return "creation"
	case strings.HasPrefix(eventType, "session"):
		return "start"
	default:
		return "info"
	}
}

func falcoPriorityToECS(priority string) int {
	switch strings.ToLower(priority) {
	case "emergency", "alert":
		return 1
	case "critical":
		return 2
	case "error":
		return 3
	case "warning":
		return 4
	case "notice":
		return 5
	case "informational", "info":
		return 6
	case "debug":
		return 7
	default:
		return 5
	}
}
