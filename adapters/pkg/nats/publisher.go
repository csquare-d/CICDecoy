// Package publisher connects adapters to NATS.
//
// It reads schema.Event from a channel and publishes to NATS
// using the CI/CDecoy subject hierarchy:
//   cicdecoy.decoy.events.{decoy_name}.{event_type}
//
// This is the only component that touches NATS. Adapters never
// import the NATS client — they just emit events to a channel.
package nats

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cicdecoy/adapters/pkg/schema"
	"github.com/nats-io/nats.go"
)

type Publisher struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	logger *slog.Logger

	// Metrics
	published int64
	errors    int64
}

type Config struct {
	NATSUrl  string `yaml:"nats_url" env:"NATS_URL"`
	Stream   string `yaml:"stream" env:"NATS_STREAM"`   // "DECOY_EVENTS"
}

func DefaultConfig() Config {
	return Config{
		NATSUrl: "nats://nats.cicdecoy.svc.cluster.local:4222",
		Stream:  "DECOY_EVENTS",
	}
}

func New(cfg Config, logger *slog.Logger) (*Publisher, error) {
	nc, err := nats.Connect(cfg.NATSUrl,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1), // reconnect forever
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("NATS disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			logger.Info("NATS reconnected")
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

	return &Publisher{
		nc:     nc,
		js:     js,
		logger: logger,
	}, nil
}

// Run reads events from the channel and publishes to NATS.
// Blocks until ctx is cancelled or the channel is closed.
func (p *Publisher) Run(ctx context.Context, events <-chan schema.Event) error {
	p.logger.Info("publisher started, waiting for events")

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("publisher stopping",
				"published", p.published,
				"errors", p.errors,
			)
			p.nc.Close()
			return ctx.Err()

		case event, ok := <-events:
			if !ok {
				p.logger.Info("event channel closed")
				return nil
			}

			if err := p.publish(event); err != nil {
				// Retry once before dropping
				time.Sleep(100 * time.Millisecond)
				if retryErr := p.publish(event); retryErr != nil {
					p.errors++
					p.logger.Error("publish failed after retry",
						"event_id", event.EventID,
						"subject", event.NATSSubject(),
						"error", retryErr,
					)
					continue
				}
			}

			p.published++
			if p.published%1000 == 0 {
				p.logger.Info("publish progress",
					"published", p.published,
					"errors", p.errors,
				)
			}
		}
	}
}

func (p *Publisher) publish(event schema.Event) error {
	// Record ingest latency
	event.Adapter.IngestLatencyMs = time.Since(event.Timestamp).Milliseconds()

	payload, err := event.JSON()
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	subject := event.NATSSubject()

	// Publish via JetStream for persistence guarantees.
	// Falls back to core NATS if JetStream isn't available
	// (e.g. during NATS upgrades).
	_, err = p.js.Publish(subject, payload)
	if err != nil {
		// Fallback to core NATS — at-most-once but better than dropping
		p.logger.Warn("jetstream publish failed, falling back to core",
			"error", err,
		)
		return p.nc.Publish(subject, payload)
	}

	return nil
}

func (p *Publisher) Close() {
	if p.nc != nil {
		p.nc.Drain()
	}
}
