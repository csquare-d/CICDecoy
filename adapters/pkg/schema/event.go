// Package schema defines the CI/CDecoy common event schema.
//
// These types map directly to:
//   - The decoy_events table in TimescaleDB
//   - The NormalizedEvent dataclass in the Python CTI pipeline
//   - The NATS message payload on cicdecoy.decoy.events.>
//
// Adapters translate honeypot-native output into this format.
// Everything downstream consumes this and doesn't care about the source.
package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Event is the common envelope published to NATS.
// One of these becomes one row in decoy_events.
type Event struct {
	// ── Identity ──────────────────────────────────────
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"` // "1.0"

	// ── Source decoy info ─────────────────────────────
	// Maps to: decoy_name, decoy_tier in decoy_events
	Source SourceInfo `json:"source"`

	// ── Session tracking ──────────────────────────────
	// Maps to: session_id in decoy_events
	// Adapters generate deterministic session IDs from
	// the honeypot's native session concept.
	SessionID string `json:"session_id"`

	// ── What happened ─────────────────────────────────
	// Maps to: event_type in decoy_events
	// Values: connection | auth.attempt | auth.success | auth.failure |
	//         command.exec | file.access | alert | honeytoken.triggered |
	//         session.closed
	EventType string `json:"event_type"`

	// ── Network context ───────────────────────────────
	// Maps to: source_ip, source_port in decoy_events
	SourceIP   string `json:"source_ip,omitempty"`
	SourcePort int    `json:"source_port,omitempty"`

	// ── Classification ────────────────────────────────
	// Maps to: severity in decoy_events
	// Values: info | low | medium | high | critical
	// Adapters set a baseline; enrichment may escalate.
	Severity string `json:"severity"`

	// ── Event-specific payload ────────────────────────
	// Maps to: raw_data (JSONB) in decoy_events
	// Contains the action-specific fields. For auth.attempt
	// this has username, password, method. For command.exec
	// this has command, cwd, uid, etc.
	Data map[string]any `json:"data"`

	// ── Integrity ────────────────────────────────────
	// ContentHash is a SHA-256 digest of the canonical event payload
	// (excluding this field itself), enabling downstream consumers to
	// detect tampering.  Set by the adapter before publishing.
	ContentHash string `json:"content_hash,omitempty"`

	// ── Adapter provenance ────────────────────────────
	// NOT stored in decoy_events directly, but useful for
	// debugging and metrics. Stripped before DB insert.
	Adapter AdapterMeta `json:"_adapter,omitempty"`
}

// SourceInfo identifies which decoy generated this event.
type SourceInfo struct {
	Decoy string `json:"decoy"`          // decoy_name: "bastion-dmz-01"
	Tier  int    `json:"tier"`           // decoy_tier: 1-5
	Pod   string `json:"pod,omitempty"`  // k8s pod name (native decoys)
	Node  string `json:"node,omitempty"` // k8s node (native decoys)
}

// AdapterMeta records which adapter produced this event.
// Useful for debugging adapter issues without polluting the
// core schema. Downstream enrichment can inspect this if needed.
type AdapterMeta struct {
	Name            string `json:"name"`              // "cowrie", "dionaea", "tpot"
	Version         string `json:"version"`           // adapter version
	OriginalEventID string `json:"original_event_id"` // honeypot's native event ID
	IngestLatencyMs int64  `json:"ingest_latency_ms"` // time from honeypot log to NATS publish
}

// NewEvent creates an Event with defaults filled in.
func NewEvent(adapterName string, decoyName string, tier int) Event {
	return Event{
		EventID:   uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Version:   "1.0",
		Source: SourceInfo{
			Decoy: decoyName,
			Tier:  tier,
		},
		Severity: "info",
		Data:     make(map[string]any),
		Adapter: AdapterMeta{
			Name: adapterName,
		},
	}
}

// NATSSubject returns the subject this event should be published to.
// Format: cicdecoy.decoy.events.{decoy_name}.{event_type}
//
// Examples:
//   cicdecoy.decoy.events.bastion-dmz-01.auth.attempt
//   cicdecoy.decoy.events.smb-fileshare-02.command.exec
// sanitizeSubjectToken strips characters that have special meaning in NATS
// subjects (`.` separates tokens, `*` and `>` are wildcards).  Only
// alphanumerics, hyphens, and underscores are kept; everything else is
// replaced with `_`.  An empty result becomes "unknown".
func sanitizeSubjectToken(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func (e *Event) NATSSubject() string {
	return "cicdecoy.decoy.events." + sanitizeSubjectToken(e.Source.Decoy) + "." + sanitizeSubjectToken(e.EventType)
}

// ComputeHash populates ContentHash with a SHA-256 digest of the
// serialised event (with content_hash temporarily cleared to avoid
// a circular dependency).
func (e *Event) ComputeHash() {
	e.ContentHash = "" // clear before hashing
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	sum := sha256.Sum256(data)
	e.ContentHash = hex.EncodeToString(sum[:])
}

// JSON serializes the event for NATS publishing.
func (e *Event) JSON() ([]byte, error) {
	return json.Marshal(e)
}
