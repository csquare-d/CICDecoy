package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cicdecoy/siem-forwarder/formatter"
	"github.com/cicdecoy/siem-forwarder/output"
	"github.com/nats-io/nats.go"
)

// ── Consumer ─────────────────────────────────────────

// Consumer pulls events from JetStream streams and forwards
// them through a formatter to an output sink.
type Consumer struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	cfg    ConsumerConfig
	fmtr   formatter.Formatter
	sink   output.Sink
	logger *slog.Logger

	retry RetryPolicy
	cb    *CircuitBreaker

	// Dead-letter
	dlqSubject string // NATS subject for dead-letter messages (e.g., "cicdecoy.siem.dlq")

	// Metrics
	mu           sync.Mutex
	received     int64
	forwarded    int64
	errors       int64
	nakd         int64
	retried      int64
	deadLettered int64
	circuitOpen  int64
}

type ConsumerConfig struct {
	NATSUrl       string
	Streams       []StreamConfig
	BatchSize     int
	FlushInterval time.Duration
	MaxWorkers    int // Maximum concurrent stream consumer goroutines (default 20)

	RetryPolicy     RetryPolicy
	CBFailThreshold int           // circuit breaker failure threshold (default 5)
	CBSuccThreshold int           // circuit breaker success threshold (default 2)
	CBOpenTimeout   time.Duration // circuit breaker open timeout (default 30s)
	DLQSubject      string        // dead-letter subject (default "cicdecoy.siem.dlq")
}

func NewConsumer(cfg ConsumerConfig, fmtr formatter.Formatter, sink output.Sink, logger *slog.Logger) (*Consumer, error) {
	nc, err := nats.Connect(cfg.NATSUrl,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("nats disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			logger.Info("nats reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream context: %w", err)
	}

	// Apply defaults for circuit breaker / DLQ settings.
	dlqSubject := cfg.DLQSubject
	if dlqSubject == "" {
		dlqSubject = "cicdecoy.siem.dlq"
	}

	return &Consumer{
		nc:         nc,
		js:         js,
		cfg:        cfg,
		fmtr:       fmtr,
		sink:       sink,
		logger:     logger,
		retry:      cfg.RetryPolicy,
		cb:         NewCircuitBreaker(cfg.CBFailThreshold, cfg.CBSuccThreshold, cfg.CBOpenTimeout, logger),
		dlqSubject: dlqSubject,
	}, nil
}

// Run starts a pull subscription for each configured stream.
// Blocks until ctx is cancelled. Concurrent stream goroutines are
// capped by MaxWorkers (default 20) to prevent unbounded goroutine growth.
func (c *Consumer) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	maxWorkers := c.cfg.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = 20
	}
	sem := make(chan struct{}, maxWorkers)

	for _, sc := range c.cfg.Streams {
		sem <- struct{}{} // acquire semaphore slot
		wg.Add(1)
		go func(sc StreamConfig) {
			defer func() { <-sem }() // release semaphore slot
			defer wg.Done()
			c.consumeStream(ctx, sc)
		}(sc)
	}

	// Periodic metrics reporting
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.reportMetrics(ctx)
	}()

	wg.Wait()
	return nil
}

// consumeStream runs a pull-based subscription loop for a single
// stream/consumer pair. Uses batched fetch for throughput.
func (c *Consumer) consumeStream(ctx context.Context, sc StreamConfig) {
	log := c.logger.With("stream", sc.Stream, "consumer", sc.Consumer)
	log.Info("starting stream consumer")

	// Bind to the existing durable consumer (created by nats-init).
	// We don't create consumers here — the Helm/compose init handles that.
	sub, err := c.js.PullSubscribe("", sc.Consumer,
		nats.Bind(sc.Stream, sc.Consumer),
	)
	if err != nil {
		log.Error("failed to subscribe — is the durable consumer created?",
			"error", err,
			"hint", "Run nats-init or check your Helm values",
		)
		return
	}
	defer func() {
		if subErr := sub.Unsubscribe(); subErr != nil {
			log.Debug("unsubscribe cleanup", "error", subErr)
		}
	}()

	batch := make([]pendingMsg, 0, c.cfg.BatchSize)
	flushTicker := time.NewTicker(c.cfg.FlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush before exit
			if len(batch) > 0 {
				c.flushBatch(ctx, log, batch)
			}
			log.Info("stream consumer stopped",
				"stream", sc.Stream,
			)
			return

		case <-flushTicker.C:
			if len(batch) > 0 {
				c.flushBatch(ctx, log, batch)
				batch = batch[:0]
			}

		default:
			// Pull a batch of messages. Short timeout so we stay
			// responsive to ctx cancellation and flush ticks.
			msgs, err := sub.Fetch(c.cfg.BatchSize-len(batch),
				nats.MaxWait(5*time.Second),
			)
			if err != nil {
				// Timeout is normal when there's no traffic — not an error.
				if err != nats.ErrTimeout {
					log.Warn("fetch error", "error", err)
				}
				continue
			}

			for _, msg := range msgs {
				c.mu.Lock()
				c.received++
				c.mu.Unlock() // Short critical section; defer not needed here

				batch = append(batch, pendingMsg{
					natsMsg: msg,
					subject: msg.Subject,
					data:    msg.Data,
				})
			}

			// Flush if batch is full
			if len(batch) >= c.cfg.BatchSize {
				c.flushBatch(ctx, log, batch)
				batch = batch[:0]
			}
		}
	}
}

type pendingMsg struct {
	natsMsg *nats.Msg
	subject string
	data    []byte
}

// flushBatch formats and sends a batch of messages to the SIEM sink.
// Integrates circuit breaker, retry with exponential backoff, and
// dead-letter queue support. ACKs successful messages, NAKs failures
// so JetStream redelivers them (unless sent to the DLQ).
func (c *Consumer) flushBatch(ctx context.Context, log *slog.Logger, batch []pendingMsg) {
	// ── Step 1: Circuit breaker gate ─────────────────
	if !c.cb.Allow() {
		log.Warn("circuit breaker open, NAKing batch", "batch_size", len(batch))
		for _, pm := range batch {
			pm.natsMsg.Nak()
		}
		c.mu.Lock()
		c.nakd += int64(len(batch))
		c.circuitOpen++
		c.mu.Unlock()
		return
	}

	// ── Format records ───────────────────────────────
	// Build a parallel slice so we can correlate records back to pendingMsgs.
	type indexedRecord struct {
		record output.Record
		pm     pendingMsg
	}

	formatted := make([]indexedRecord, 0, len(batch))

	for _, pm := range batch {
		var event map[string]interface{}
		if err := json.Unmarshal(pm.data, &event); err != nil {
			log.Warn("failed to parse event, forwarding raw",
				"subject", pm.subject,
				"error", err,
			)
			event = map[string]interface{}{
				"_raw":     string(pm.data),
				"_subject": pm.subject,
				"_error":   "parse_failed",
			}
		}

		event["_nats_subject"] = pm.subject

		out, err := c.fmtr.Format(pm.subject, event)
		if err != nil {
			log.Warn("format error, falling back to raw JSON",
				"subject", pm.subject,
				"error", err,
			)
			raw, _ := json.Marshal(event)
			out = raw
		}

		formatted = append(formatted, indexedRecord{
			record: output.Record{
				Data:    out,
				NATSMsg: pm.natsMsg,
			},
			pm: pm,
		})
	}

	// Helper: extract []output.Record from []indexedRecord
	toRecords := func(items []indexedRecord) []output.Record {
		recs := make([]output.Record, len(items))
		for i, ir := range items {
			recs[i] = ir.record
		}
		return recs
	}

	// ── Step 2: First send attempt ───────────────────
	results := c.sink.Send(toRecords(formatted))

	var succeeded []indexedRecord
	var failed []indexedRecord
	var failErrors []error // track last error per failed record

	for i, r := range results {
		if r.Err == nil {
			succeeded = append(succeeded, formatted[i])
		} else {
			failed = append(failed, formatted[i])
			failErrors = append(failErrors, r.Err)
		}
	}

	// ACK first-attempt successes
	for _, ir := range succeeded {
		ir.record.NATSMsg.Ack()
	}

	// ── Step 3: Retry loop ───────────────────────────
	if len(failed) > 0 && c.retry.MaxRetries > 0 {
		for attempt := 1; attempt <= c.retry.MaxRetries; attempt++ {
			delay := c.retry.Backoff(attempt)
			log.Debug("retrying failed records",
				"attempt", attempt,
				"remaining", len(failed),
				"backoff", delay,
			)

			// Sleep respecting context cancellation
			select {
			case <-ctx.Done():
				log.Warn("context cancelled during retry backoff, NAKing remaining")
				for _, ir := range failed {
					ir.record.NATSMsg.Nak()
				}
				c.mu.Lock()
				c.nakd += int64(len(failed))
				c.mu.Unlock()
				return
			case <-time.After(delay):
			}

			retryResults := c.sink.Send(toRecords(failed))

			var stillFailing []indexedRecord
			var stillFailErrors []error
			retrySucceeded := 0

			for i, r := range retryResults {
				if r.Err == nil {
					failed[i].record.NATSMsg.Ack()
					retrySucceeded++
				} else {
					stillFailing = append(stillFailing, failed[i])
					stillFailErrors = append(stillFailErrors, r.Err)
				}
			}

			c.mu.Lock()
			c.retried += int64(retrySucceeded)
			c.mu.Unlock()

			failed = stillFailing
			failErrors = stillFailErrors

			if len(failed) == 0 {
				break
			}
		}
	}

	// ── Step 4: Dead-letter or NAK exhausted failures ─
	if len(failed) > 0 {
		for i, ir := range failed {
			errMsg := "unknown"
			if i < len(failErrors) && failErrors[i] != nil {
				errMsg = failErrors[i].Error()
			}

			if c.dlqSubject != "" {
				dlqMsg := map[string]interface{}{
					"_dlq":              true,
					"_original_subject": ir.pm.subject,
					"_error":            errMsg,
					"_attempts":         c.retry.MaxRetries + 1,
					"_timestamp":        time.Now().UTC().Format(time.RFC3339),
					"_data":             string(ir.pm.data),
				}
				dlqBytes, _ := json.Marshal(dlqMsg)

				if pubErr := c.nc.Publish(c.dlqSubject, dlqBytes); pubErr != nil {
					log.Error("failed to publish to DLQ, NAKing instead",
						"subject", ir.pm.subject,
						"error", pubErr,
					)
					ir.record.NATSMsg.Nak()
					c.mu.Lock()
					c.nakd++
					c.mu.Unlock()
					continue
				}

				log.Warn("message sent to dead-letter queue",
					"subject", ir.pm.subject,
					"dlq_subject", c.dlqSubject,
					"error", errMsg,
					"attempts", c.retry.MaxRetries+1,
				)

				// ACK the original so JetStream doesn't redeliver forever
				ir.record.NATSMsg.Ack()
				c.mu.Lock()
				c.deadLettered++
				c.mu.Unlock()
			} else {
				// No DLQ configured — NAK and let JetStream handle redelivery
				ir.record.NATSMsg.Nak()
				c.mu.Lock()
				c.nakd++
				c.mu.Unlock()
			}
		}
	}

	// ── Step 5: Circuit breaker feedback ─────────────
	if len(failed) > 0 {
		c.cb.RecordFailure()
	} else {
		c.cb.RecordSuccess()
	}

	// ── Step 6: Update aggregate metrics ─────────────
	totalAcked := len(succeeded) // first-attempt successes
	totalNakd := 0
	// retried and deadLettered already updated above

	c.mu.Lock()
	c.forwarded += int64(totalAcked)
	// nakd already incremented inline above for failures
	c.mu.Unlock()

	if len(failed) > 0 {
		log.Warn("batch partially failed",
			"first_attempt_acked", totalAcked,
			"exhausted_failures", len(failed),
			"batch_size", len(batch),
		)
	} else {
		log.Debug("batch flushed",
			"acked", totalAcked,
			"batch_size", len(batch),
		)
	}

	_ = totalNakd // consumed via inline increments
}

// reportMetrics logs throughput stats periodically.
func (c *Consumer) reportMetrics(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			c.logger.Info("forwarder metrics",
				"received", c.received,
				"forwarded", c.forwarded,
				"errors", c.errors,
				"nakd", c.nakd,
				"retried", c.retried,
				"dead_lettered", c.deadLettered,
				"circuit_open", c.circuitOpen,
				"circuit_state", c.cb.State().String(),
				"pending", c.received-c.forwarded-c.errors,
			)
			c.mu.Unlock()
		}
	}
}

func (c *Consumer) Close() {
	if c.nc != nil {
		c.nc.Drain()
	}
}
