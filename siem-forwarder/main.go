// CI/CDecoy — SIEM Forwarder
//
// Lightweight service that consumes raw events from NATS JetStream
// and forwards them to external SIEMs without enrichment. This is
// the "raw export" path — an alternative (or complement) to the
// full CTI enrichment pipeline.
//
// Supports multiple output formats (JSON, CEF, LEEF, ECS) and
// multiple SIEM targets (Syslog, Splunk HEC, Elasticsearch, Webhook).
//
// Each JetStream stream gets its own durable consumer with independent
// cursor tracking. The CTI pipeline's consumers are completely separate —
// both can run simultaneously without interference.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cicdecoy/siem-forwarder/formatter"
	"github.com/cicdecoy/siem-forwarder/output"
)

// Config holds all forwarder configuration, populated from env vars.
type Config struct {
	// NATS connection
	NATSUrl string

	// Streams to consume from — each gets its own pull subscription.
	// Format: "STREAM_NAME:CONSUMER_NAME"
	// e.g. "DECOY_EVENTS:siem-forwarder,ALERTS:siem-alert-forwarder,FALCO_ALERTS:siem-falco-forwarder"
	Streams []StreamConfig

	// Output format for events
	Format string // "json" | "cef" | "leef" | "ecs"

	// SIEM target
	SIEMType string // "syslog" | "splunk_hec" | "elastic" | "webhook"

	// Syslog settings
	SyslogEndpoint string // "host:port"
	SyslogProtocol string // "tcp" | "udp"
	SyslogFacility string // "local0" through "local7"

	// Splunk HEC settings
	SplunkEndpoint string // "https://splunk:8088"
	SplunkToken    string
	SplunkIndex    string
	SplunkSource   string

	// Elasticsearch settings
	ElasticEndpoint string // "https://elastic:9200"
	ElasticIndex    string
	ElasticUsername string
	ElasticPassword string
	ElasticAPIKey   string

	// Webhook settings
	WebhookURL     string
	WebhookHeaders map[string]string

	// Operational
	BatchSize    int
	FlushInterval time.Duration
	LogLevel     string
}

type StreamConfig struct {
	Stream   string
	Consumer string
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(envOr("LOG_LEVEL", "info")),
	}))

	cfg := loadConfig()

	logger.Info("siem-forwarder starting",
		"nats_url", cfg.NATSUrl,
		"streams", len(cfg.Streams),
		"format", cfg.Format,
		"siem_type", cfg.SIEMType,
		"batch_size", cfg.BatchSize,
		"flush_interval", cfg.FlushInterval,
	)

	// ── Build the formatter ───────────────────────────
	var fmtr formatter.Formatter
	switch cfg.Format {
	case "json":
		fmtr = formatter.NewJSON()
	case "cef":
		fmtr = formatter.NewCEF()
	case "leef":
		fmtr = formatter.NewLEEF()
	case "ecs":
		fmtr = formatter.NewECS()
	default:
		logger.Error("unknown output format", "format", cfg.Format)
		os.Exit(1)
	}

	// ── Build the output sink ─────────────────────────
	var sink output.Sink
	var err error

	switch cfg.SIEMType {
	case "syslog":
		sink, err = output.NewSyslog(output.SyslogConfig{
			Endpoint: cfg.SyslogEndpoint,
			Protocol: cfg.SyslogProtocol,
			Facility: cfg.SyslogFacility,
		}, logger)

	case "splunk_hec":
		sink, err = output.NewSplunkHEC(output.SplunkConfig{
			Endpoint: cfg.SplunkEndpoint,
			Token:    cfg.SplunkToken,
			Index:    cfg.SplunkIndex,
			Source:   cfg.SplunkSource,
		}, logger)

	case "elastic":
		sink, err = output.NewElasticsearch(output.ElasticConfig{
			Endpoint: cfg.ElasticEndpoint,
			Index:    cfg.ElasticIndex,
			Username: cfg.ElasticUsername,
			Password: cfg.ElasticPassword,
			APIKey:   cfg.ElasticAPIKey,
		}, logger)

	case "webhook":
		sink, err = output.NewWebhook(output.WebhookConfig{
			URL:     cfg.WebhookURL,
			Headers: cfg.WebhookHeaders,
		}, logger)

	default:
		logger.Error("unknown SIEM type", "siem_type", cfg.SIEMType)
		os.Exit(1)
	}

	if err != nil {
		logger.Error("failed to create output sink", "error", err)
		os.Exit(1)
	}
	defer sink.Close()

	// ── Build and run the consumer ────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	consumer, err := NewConsumer(ConsumerConfig{
		NATSUrl:       cfg.NATSUrl,
		Streams:       cfg.Streams,
		BatchSize:     cfg.BatchSize,
		FlushInterval: cfg.FlushInterval,
	}, fmtr, sink, logger)
	if err != nil {
		logger.Error("failed to create consumer", "error", err)
		os.Exit(1)
	}
	defer consumer.Close()

	// ── Signal handling ───────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- consumer.Run(ctx)
	}()

	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
		// Give consumers time to finish in-flight batches
		<-time.After(5 * time.Second)
	case err := <-errCh:
		if err != nil {
			logger.Error("consumer exited with error", "error", err)
			os.Exit(1)
		}
	}

	logger.Info("siem-forwarder stopped")
}

// ── Config loading ────────────────────────────────────

func loadConfig() Config {
	cfg := Config{
		NATSUrl:         envOr("NATS_URL", "nats://nats:4222"),
		Format:          envOr("OUTPUT_FORMAT", "json"),
		SIEMType:        envOr("SIEM_TYPE", "syslog"),
		SyslogEndpoint:  envOr("SYSLOG_ENDPOINT", "localhost:514"),
		SyslogProtocol:  envOr("SYSLOG_PROTOCOL", "tcp"),
		SyslogFacility:  envOr("SYSLOG_FACILITY", "local0"),
		SplunkEndpoint:  envOr("SPLUNK_ENDPOINT", ""),
		SplunkToken:     envOr("SPLUNK_HEC_TOKEN", ""),
		SplunkIndex:     envOr("SPLUNK_INDEX", "cicdecoy"),
		SplunkSource:    envOr("SPLUNK_SOURCE", "cicdecoy-forwarder"),
		ElasticEndpoint: envOr("ELASTIC_ENDPOINT", ""),
		ElasticIndex:    envOr("ELASTIC_INDEX", "cicdecoy-raw"),
		ElasticUsername: envOr("ELASTIC_USERNAME", ""),
		ElasticPassword: envOr("ELASTIC_PASSWORD", ""),
		ElasticAPIKey:   envOr("ELASTIC_API_KEY", ""),
		WebhookURL:      envOr("WEBHOOK_URL", ""),
		BatchSize:       envInt("BATCH_SIZE", 100),
		FlushInterval:   envDuration("FLUSH_INTERVAL", 5*time.Second),
		LogLevel:        envOr("LOG_LEVEL", "info"),
	}

	// Parse webhook headers: "Key1:Value1,Key2:Value2"
	if h := os.Getenv("WEBHOOK_HEADERS"); h != "" {
		cfg.WebhookHeaders = make(map[string]string)
		for _, pair := range strings.Split(h, ",") {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				cfg.WebhookHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Parse streams: "DECOY_EVENTS:siem-forwarder,ALERTS:siem-alert-forwarder"
	streamStr := envOr("STREAMS", "DECOY_EVENTS:siem-forwarder,ALERTS:siem-alert-forwarder,FALCO_ALERTS:siem-falco-forwarder")
	for _, s := range strings.Split(streamStr, ",") {
		parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
		if len(parts) == 2 {
			cfg.Streams = append(cfg.Streams, StreamConfig{
				Stream:   parts[0],
				Consumer: parts[1],
			})
		}
	}

	return cfg
}

// ── Helpers ───────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var i int
	fmt.Sscanf(v, "%d", &i)
	if i <= 0 {
		return fallback
	}
	return i
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
