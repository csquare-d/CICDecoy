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

// Consumer pulls events from JetStream streams and forwards
// them through a formatter to an output sink.
type Consumer struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	cfg    ConsumerConfig
	fmtr   formatter.Formatter
	sink   output.Sink
	logger *slog.Logger

	// Metrics
	mu        sync.Mutex
	received  int64
	forwarded int64
	errors    int64
	nakd      int64
}

type ConsumerConfig struct {
	NATSUrl       string
	Streams       []StreamConfig
	BatchSize     int
	FlushInterval time.Duration
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

	return &Consumer{
		nc:     nc,
		js:     js,
		cfg:    cfg,
		fmtr:   fmtr,
		sink:   sink,
		logger: logger,
	}, nil
}

// Run starts a pull subscription for each configured stream.
// Blocks until ctx is cancelled.
func (c *Consumer) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	for _, sc := range c.cfg.Streams {
		wg.Add(1)
		go func(sc StreamConfig) {
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

	batch := make([]pendingMsg, 0, c.cfg.BatchSize)
	flushTicker := time.NewTicker(c.cfg.FlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush before exit
			if len(batch) > 0 {
				c.flushBatch(log, batch)
			}
			log.Info("stream consumer stopped",
				"stream", sc.Stream,
			)
			return

		case <-flushTicker.C:
			if len(batch) > 0 {
				c.flushBatch(log, batch)
				batch = batch[:0]
			}

		default:
			// Pull a batch of messages. Short timeout so we stay
			// responsive to ctx cancellation and flush ticks.
			msgs, err := sub.Fetch(c.cfg.BatchSize-len(batch),
				nats.MaxWait(1*time.Second),
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
				c.mu.Unlock()

				batch = append(batch, pendingMsg{
					natsMsg: msg,
					subject: msg.Subject,
					data:    msg.Data,
				})
			}

			// Flush if batch is full
			if len(batch) >= c.cfg.BatchSize {
				c.flushBatch(log, batch)
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
// ACKs successful messages, NAKs failures so JetStream redelivers them.
func (c *Consumer) flushBatch(log *slog.Logger, batch []pendingMsg) {
	formatted := make([]output.Record, 0, len(batch))

	for _, pm := range batch {
		// Parse the raw NATS event into a generic map.
		var event map[string]interface{}
		if err := json.Unmarshal(pm.data, &event); err != nil {
			log.Warn("failed to parse event, forwarding raw",
				"subject", pm.subject,
				"error", err,
			)
			// Still forward it — let the SIEM deal with the raw bytes.
			// Better to have a malformed log than a lost one.
			event = map[string]interface{}{
				"_raw":     string(pm.data),
				"_subject": pm.subject,
				"_error":   "parse_failed",
			}
		}

		// Inject NATS metadata the SIEM might need for correlation.
		event["_nats_subject"] = pm.subject

		// Format into the target schema (CEF, ECS, etc.)
		out, err := c.fmtr.Format(pm.subject, event)
		if err != nil {
			log.Warn("format error, falling back to raw JSON",
				"subject", pm.subject,
				"error", err,
			)
			raw, _ := json.Marshal(event)
			out = raw
		}

		formatted = append(formatted, output.Record{
			Data:    out,
			NATSMsg: pm.natsMsg,
		})
	}

	// Send the batch to the SIEM.
	results := c.sink.Send(formatted)

	acked, nakd := 0, 0
	for _, r := range results {
		if r.Err == nil {
			r.NATSMsg.Ack()
			acked++
		} else {
			// NAK with delay — JetStream will redeliver after backoff.
			r.NATSMsg.NakWithDelay(5 * time.Second)
			nakd++
			log.Warn("send failed, will retry",
				"subject", r.NATSMsg.Subject,
				"error", r.Err,
			)
		}
	}

	c.mu.Lock()
	c.forwarded += int64(acked)
	c.nakd += int64(nakd)
	c.errors += int64(nakd)
	c.mu.Unlock()

	if nakd > 0 {
		log.Warn("batch partially failed",
			"acked", acked,
			"nakd", nakd,
			"batch_size", len(batch),
		)
	} else {
		log.Debug("batch flushed",
			"acked", acked,
			"batch_size", len(batch),
		)
	}
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
