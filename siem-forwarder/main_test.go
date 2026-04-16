package main

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestEnvOr(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envValue string
		fallback string
		want     string
	}{
		{
			name:     "returns env value when set",
			key:      "TEST_ENVOR_SET",
			envValue: "from_env",
			fallback: "default",
			want:     "from_env",
		},
		{
			name:     "returns fallback when unset",
			key:      "TEST_ENVOR_UNSET",
			envValue: "",
			fallback: "default",
			want:     "default",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				os.Setenv(tc.key, tc.envValue)
				defer os.Unsetenv(tc.key)
			} else {
				os.Unsetenv(tc.key)
			}
			got := envOr(tc.key, tc.fallback)
			if got != tc.want {
				t.Errorf("envOr(%q, %q) = %q, want %q", tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestEnvInt(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envValue string
		fallback int
		want     int
	}{
		{
			name:     "returns parsed int when set",
			key:      "TEST_ENVINT_SET",
			envValue: "42",
			fallback: 10,
			want:     42,
		},
		{
			name:     "returns fallback when unset",
			key:      "TEST_ENVINT_UNSET",
			envValue: "",
			fallback: 100,
			want:     100,
		},
		{
			name:     "returns fallback for invalid value",
			key:      "TEST_ENVINT_BAD",
			envValue: "notanumber",
			fallback: 50,
			want:     50,
		},
		{
			name:     "returns fallback for zero",
			key:      "TEST_ENVINT_ZERO",
			envValue: "0",
			fallback: 25,
			want:     25,
		},
		{
			name:     "returns fallback for negative",
			key:      "TEST_ENVINT_NEG",
			envValue: "-5",
			fallback: 25,
			want:     25,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				os.Setenv(tc.key, tc.envValue)
				defer os.Unsetenv(tc.key)
			} else {
				os.Unsetenv(tc.key)
			}
			got := envInt(tc.key, tc.fallback)
			if got != tc.want {
				t.Errorf("envInt(%q, %d) = %d, want %d", tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestEnvDuration(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envValue string
		fallback time.Duration
		want     time.Duration
	}{
		{
			name:     "parses valid duration",
			key:      "TEST_ENVDUR_SET",
			envValue: "10s",
			fallback: 5 * time.Second,
			want:     10 * time.Second,
		},
		{
			name:     "returns fallback when unset",
			key:      "TEST_ENVDUR_UNSET",
			envValue: "",
			fallback: 5 * time.Second,
			want:     5 * time.Second,
		},
		{
			name:     "returns fallback for invalid",
			key:      "TEST_ENVDUR_BAD",
			envValue: "notaduration",
			fallback: 3 * time.Second,
			want:     3 * time.Second,
		},
		{
			name:     "parses minutes",
			key:      "TEST_ENVDUR_MIN",
			envValue: "2m",
			fallback: 1 * time.Minute,
			want:     2 * time.Minute,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				os.Setenv(tc.key, tc.envValue)
				defer os.Unsetenv(tc.key)
			} else {
				os.Unsetenv(tc.key)
			}
			got := envDuration(tc.key, tc.fallback)
			if got != tc.want {
				t.Errorf("envDuration(%q, %v) = %v, want %v", tc.key, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"INFO", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseLogLevel(tc.input)
			if got != tc.want {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear all env vars that loadConfig reads
	envVars := []string{
		"NATS_URL", "OUTPUT_FORMAT", "SIEM_TYPE", "SYSLOG_ENDPOINT",
		"SYSLOG_PROTOCOL", "SYSLOG_FACILITY", "SPLUNK_ENDPOINT",
		"SPLUNK_HEC_TOKEN", "SPLUNK_INDEX", "SPLUNK_SOURCE",
		"ELASTIC_ENDPOINT", "ELASTIC_INDEX", "ELASTIC_USERNAME",
		"ELASTIC_PASSWORD", "ELASTIC_API_KEY", "WEBHOOK_URL",
		"WEBHOOK_HEADERS", "BATCH_SIZE", "FLUSH_INTERVAL",
		"LOG_LEVEL", "STREAMS",
	}
	for _, k := range envVars {
		os.Unsetenv(k)
	}

	cfg := loadConfig()

	if cfg.NATSUrl != "nats://nats:4222" {
		t.Errorf("NATSUrl = %q, want default", cfg.NATSUrl)
	}
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Format)
	}
	if cfg.SIEMType != "syslog" {
		t.Errorf("SIEMType = %q, want syslog", cfg.SIEMType)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("BatchSize = %d, want 100", cfg.BatchSize)
	}
	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want 5s", cfg.FlushInterval)
	}
	if cfg.SplunkIndex != "cicdecoy" {
		t.Errorf("SplunkIndex = %q, want cicdecoy", cfg.SplunkIndex)
	}
	if cfg.ElasticIndex != "cicdecoy-raw" {
		t.Errorf("ElasticIndex = %q, want cicdecoy-raw", cfg.ElasticIndex)
	}

	// Default streams
	if len(cfg.Streams) != 3 {
		t.Fatalf("expected 3 default streams, got %d", len(cfg.Streams))
	}
	if cfg.Streams[0].Stream != "DECOY_EVENTS" || cfg.Streams[0].Consumer != "siem-forwarder" {
		t.Errorf("stream[0] = %+v", cfg.Streams[0])
	}
}

func TestLoadConfig_CustomStreams(t *testing.T) {
	os.Setenv("STREAMS", "MY_STREAM:my-consumer,OTHER:other-consumer")
	defer os.Unsetenv("STREAMS")

	cfg := loadConfig()

	if len(cfg.Streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(cfg.Streams))
	}
	if cfg.Streams[0].Stream != "MY_STREAM" || cfg.Streams[0].Consumer != "my-consumer" {
		t.Errorf("stream[0] = %+v", cfg.Streams[0])
	}
	if cfg.Streams[1].Stream != "OTHER" || cfg.Streams[1].Consumer != "other-consumer" {
		t.Errorf("stream[1] = %+v", cfg.Streams[1])
	}
}

func TestLoadConfig_WebhookHeaders(t *testing.T) {
	os.Setenv("WEBHOOK_HEADERS", "Authorization:Bearer tok123,X-Custom:value")
	defer os.Unsetenv("WEBHOOK_HEADERS")

	cfg := loadConfig()

	if cfg.WebhookHeaders == nil {
		t.Fatal("WebhookHeaders should not be nil")
	}
	if cfg.WebhookHeaders["Authorization"] != "Bearer tok123" {
		t.Errorf("Authorization = %q", cfg.WebhookHeaders["Authorization"])
	}
	if cfg.WebhookHeaders["X-Custom"] != "value" {
		t.Errorf("X-Custom = %q", cfg.WebhookHeaders["X-Custom"])
	}
}

func TestLoadConfig_CustomEnvValues(t *testing.T) {
	os.Setenv("NATS_URL", "nats://custom:4222")
	os.Setenv("OUTPUT_FORMAT", "cef")
	os.Setenv("SIEM_TYPE", "splunk_hec")
	os.Setenv("BATCH_SIZE", "50")
	os.Setenv("FLUSH_INTERVAL", "10s")
	defer func() {
		os.Unsetenv("NATS_URL")
		os.Unsetenv("OUTPUT_FORMAT")
		os.Unsetenv("SIEM_TYPE")
		os.Unsetenv("BATCH_SIZE")
		os.Unsetenv("FLUSH_INTERVAL")
	}()

	cfg := loadConfig()

	if cfg.NATSUrl != "nats://custom:4222" {
		t.Errorf("NATSUrl = %q", cfg.NATSUrl)
	}
	if cfg.Format != "cef" {
		t.Errorf("Format = %q", cfg.Format)
	}
	if cfg.SIEMType != "splunk_hec" {
		t.Errorf("SIEMType = %q", cfg.SIEMType)
	}
	if cfg.BatchSize != 50 {
		t.Errorf("BatchSize = %d", cfg.BatchSize)
	}
	if cfg.FlushInterval != 10*time.Second {
		t.Errorf("FlushInterval = %v", cfg.FlushInterval)
	}
}
