// Package output provides SIEM output adapters (sinks) that send
// formatted events to external systems. Each sink handles connection
// management, batching, retries, and error reporting for its target.
//
// The Sink interface is intentionally batch-oriented — the consumer
// sends batches of records and gets back per-record results so it
// can ACK/NAK individual NATS messages.
package output

import "github.com/nats-io/nats.go"

// Sink sends formatted events to an external SIEM.
type Sink interface {
	// Send delivers a batch of records. Returns a result for each
	// record indicating success or failure. The consumer uses these
	// results to ACK/NAK individual NATS messages.
	Send(records []Record) []Result

	// Close flushes any buffered data and releases resources.
	Close() error
}

// Record is a single formatted event ready for delivery.
type Record struct {
	Data    []byte    // Formatted event bytes (CEF, JSON, etc.)
	NATSMsg *nats.Msg // Original NATS message for ACK/NAK
}

// Result is the outcome of sending a single record.
type Result struct {
	NATSMsg *nats.Msg
	Err     error
}
