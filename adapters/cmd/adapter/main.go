// CI/CDecoy Adapter Runner
//
// Wires together: adapter → channel → NATS publisher
//
// Usage:
//   cicdecoy-adapter --adapter cowrie --decoy-name bastion-dmz-01 --decoy-tier 3
//   cicdecoy-adapter --adapter dionaea --decoy-name smb-fileshare-02
//   cicdecoy-adapter --adapter tpot --decoy-name tpot-external-01  (reserved — not yet implemented)
//
// The adapter reads from its honeypot source, translates to the CI/CDecoy
// common event schema, and publishes to NATS. That's the entire job.
// Enrichment, ATT&CK mapping, correlation, storage — all downstream.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cicdecoy/adapters/adapters/cowrie"
	"github.com/cicdecoy/adapters/adapters/dionaea"
	"github.com/cicdecoy/adapters/adapters/tpot"
	"github.com/cicdecoy/adapters/pkg/adapter"
	"github.com/cicdecoy/adapters/pkg/nats"
	"github.com/cicdecoy/adapters/pkg/schema"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// ── Config from env vars ──────────────────────────
	adapterName := envOr("ADAPTER_TYPE", "cowrie")
	commonCfg := adapter.Config{
		DecoyName:     envOr("ADAPTER_DECOY_NAME", adapterName+"-default"),
		DecoyTier:     envInt("ADAPTER_DECOY_TIER", 1),
		SessionPrefix: envOr("ADAPTER_SESSION_PREFIX", adapterName),
	}

	natsCfg := nats.Config{
		NATSUrl: envOr("NATS_URL", "nats://nats.cicdecoy.svc.cluster.local:4222"),
		Stream:  envOr("NATS_STREAM", "DECOY_EVENTS"),
	}

	// ── Build the adapter ─────────────────────────────
	var a adapter.Adapter

	switch adapterName {
	case "cowrie":
		a = cowrie.New(cowrie.Config{
			LogPath: envOr("COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json"),
		}, commonCfg, logger)

	case "dionaea":
		a = dionaea.New(dionaea.Config{
			LogPath: envOr("DIONAEA_LOG_PATH", "/var/lib/dionaea/dionaea.json"),
		}, commonCfg, logger)

	case "tpot":
		a = tpot.New(tpot.Config{
			ElasticsearchURL: envOr("TPOT_ES_URL", "http://localhost:64298"),
			IndexPattern:     envOr("TPOT_INDEX_PATTERN", "logstash-*"),
		}, commonCfg, logger)

	default:
		logger.Error("unknown adapter type", "adapter", adapterName)
		os.Exit(1)
	}

	// ── Wire it up ────────────────────────────────────
	//
	//   [Honeypot] → [Adapter] → chan Event → [Publisher] → [NATS]
	//                                                          ↓
	//                                              cicdecoy.decoy.events.{decoy}.{type}
	//                                                          ↓
	//                                              [Enrichment Pipeline]
	//                                                          ↓
	//                                              [TimescaleDB / STIX / SIEM]

	pub, err := nats.New(natsCfg, logger)
	if err != nil {
		logger.Error("failed to create publisher", "error", err)
		os.Exit(1)
	}
	defer pub.Close()

	events := make(chan schema.Event, 1000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Health check
	if err := a.HealthCheck(ctx); err != nil {
		logger.Error("adapter health check failed",
			"adapter", a.Name(),
			"error", err,
		)
		os.Exit(1)
	}

	logger.Info("starting adapter",
		"adapter", a.Name(),
		"decoy_name", commonCfg.DecoyName,
		"decoy_tier", commonCfg.DecoyTier,
		"nats_url", natsCfg.NATSUrl,
	)

	// Start publisher (consumes from channel, publishes to NATS)
	go func() {
		if err := pub.Run(ctx, events); err != nil && ctx.Err() == nil {
			logger.Error("publisher error", "error", err)
		}
	}()

	// Start adapter (reads from honeypot, produces to channel)
	if err := a.Start(ctx, events); err != nil && ctx.Err() == nil {
		logger.Error("adapter error", "error", err, "adapter", a.Name())
		os.Exit(1)
	}

	logger.Info("adapter shutdown complete", "adapter", a.Name())
}

// ── Env helpers ───────────────────────────────────────

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
	var n int
	fmt.Sscanf(v, "%d", &n)
	if n == 0 {
		return fallback
	}
	return n
}
