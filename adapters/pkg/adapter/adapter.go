// Package adapter defines the interface every honeypot adapter implements.
//
// The contract is deliberately narrow: read from your source, emit Events.
// No enrichment, no ATT&CK mapping, no correlation. Those happen downstream.
package adapter

import (
	"context"

	"github.com/cicdecoy/adapters/pkg/schema"
)

// Adapter is what every honeypot integration implements.
// Read from the honeypot's native output, transform to schema.Event,
// push to the output channel. That's it.
type Adapter interface {
	// Name returns the adapter identifier (e.g. "cowrie", "dionaea").
	Name() string

	// Start begins reading from the honeypot source and emitting
	// normalized events. Blocks until ctx is cancelled.
	// Events are sent to the provided channel.
	Start(ctx context.Context, events chan<- schema.Event) error

	// HealthCheck returns nil if the adapter can read from its source.
	HealthCheck(ctx context.Context) error
}

// Config is common configuration shared across all adapters.
type Config struct {
	// DecoyName is the CI/CDecoy decoy name this honeypot maps to.
	// This becomes source.decoy in the event and decoy_name in the DB.
	// Must match whatever the operator uses in their decoy YAML.
	DecoyName string `yaml:"decoy_name" env:"ADAPTER_DECOY_NAME"`

	// DecoyTier maps to decoy_tier in decoy_events. 1-5.
	DecoyTier int `yaml:"decoy_tier" env:"ADAPTER_DECOY_TIER"`

	// SessionPrefix is prepended to honeypot session IDs to avoid
	// collisions with native CI/CDecoy sessions and other adapters.
	// Default: adapter name (e.g. "cowrie-{original_session_id}")
	SessionPrefix string `yaml:"session_prefix" env:"ADAPTER_SESSION_PREFIX"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig(adapterName string) Config {
	return Config{
		DecoyName:     adapterName + "-default",
		DecoyTier:     1,
		SessionPrefix: adapterName,
	}
}
