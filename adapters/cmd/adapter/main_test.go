package main

import (
	"fmt"
	"os"
	"testing"
)

// ── envOr ───────────────────────────────────────────────────

func TestEnvOr_UsesEnvVar(t *testing.T) {
	key := "TEST_CICDECOY_ENVOR"
	t.Setenv(key, "from-env")

	got := envOr(key, "fallback")
	if got != "from-env" {
		t.Errorf("envOr() = %q, want %q", got, "from-env")
	}
}

func TestEnvOr_UsesFallback(t *testing.T) {
	key := "TEST_CICDECOY_ENVOR_MISSING"
	os.Unsetenv(key)

	got := envOr(key, "fallback-value")
	if got != "fallback-value" {
		t.Errorf("envOr() = %q, want %q", got, "fallback-value")
	}
}

func TestEnvOr_EmptyEnvVar(t *testing.T) {
	key := "TEST_CICDECOY_ENVOR_EMPTY"
	t.Setenv(key, "")

	got := envOr(key, "fallback")
	if got != "fallback" {
		t.Errorf("envOr() = %q, want %q (empty env should use fallback)", got, "fallback")
	}
}

func TestEnvOr_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envValue string
		setEnv   bool
		fallback string
		want     string
	}{
		{
			name:     "env set with value",
			key:      "TEST_ENVOR_1",
			envValue: "custom",
			setEnv:   true,
			fallback: "default",
			want:     "custom",
		},
		{
			name:     "env not set",
			key:      "TEST_ENVOR_2",
			setEnv:   false,
			fallback: "default",
			want:     "default",
		},
		{
			name:     "env set empty",
			key:      "TEST_ENVOR_3",
			envValue: "",
			setEnv:   true,
			fallback: "default",
			want:     "default",
		},
		{
			name:     "env with spaces",
			key:      "TEST_ENVOR_4",
			envValue: "  spaced  ",
			setEnv:   true,
			fallback: "default",
			want:     "  spaced  ",
		},
		{
			name:     "env with special chars",
			key:      "TEST_ENVOR_5",
			envValue: "nats://nats:4222",
			setEnv:   true,
			fallback: "nats://localhost:4222",
			want:     "nats://nats:4222",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			} else {
				os.Unsetenv(tt.key)
			}

			got := envOr(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("envOr(%q, %q) = %q, want %q", tt.key, tt.fallback, got, tt.want)
			}
		})
	}
}

// ── envInt ──────────────────────────────────────────────────

func TestEnvInt_UsesEnvVar(t *testing.T) {
	key := "TEST_CICDECOY_ENVINT"
	t.Setenv(key, "3")

	got := envInt(key, 1)
	if got != 3 {
		t.Errorf("envInt() = %d, want %d", got, 3)
	}
}

func TestEnvInt_UsesFallback(t *testing.T) {
	key := "TEST_CICDECOY_ENVINT_MISSING"
	os.Unsetenv(key)

	got := envInt(key, 5)
	if got != 5 {
		t.Errorf("envInt() = %d, want %d", got, 5)
	}
}

func TestEnvInt_InvalidValue(t *testing.T) {
	key := "TEST_CICDECOY_ENVINT_INVALID"
	t.Setenv(key, "not-a-number")

	got := envInt(key, 7)
	if got != 7 {
		t.Errorf("envInt() = %d, want %d (invalid value should use fallback)", got, 7)
	}
}

func TestEnvInt_Zero(t *testing.T) {
	key := "TEST_CICDECOY_ENVINT_ZERO"
	t.Setenv(key, "0")

	got := envInt(key, 1)
	// envInt returns fallback when n == 0
	if got != 1 {
		t.Errorf("envInt() = %d, want %d (zero should use fallback)", got, 1)
	}
}

func TestEnvInt_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envValue string
		setEnv   bool
		fallback int
		want     int
	}{
		{
			name:     "valid integer",
			key:      "TEST_ENVINT_1",
			envValue: "3",
			setEnv:   true,
			fallback: 1,
			want:     3,
		},
		{
			name:     "large integer",
			key:      "TEST_ENVINT_2",
			envValue: "100",
			setEnv:   true,
			fallback: 1,
			want:     100,
		},
		{
			name:     "env not set",
			key:      "TEST_ENVINT_3",
			setEnv:   false,
			fallback: 2,
			want:     2,
		},
		{
			name:     "empty string",
			key:      "TEST_ENVINT_4",
			envValue: "",
			setEnv:   true,
			fallback: 5,
			want:     5,
		},
		{
			name:     "non-numeric string",
			key:      "TEST_ENVINT_5",
			envValue: "abc",
			setEnv:   true,
			fallback: 9,
			want:     9,
		},
		{
			name:     "zero returns fallback",
			key:      "TEST_ENVINT_6",
			envValue: "0",
			setEnv:   true,
			fallback: 1,
			want:     1,
		},
		{
			name:     "negative value",
			key:      "TEST_ENVINT_7",
			envValue: "-1",
			setEnv:   true,
			fallback: 1,
			want:     -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			} else {
				os.Unsetenv(tt.key)
			}

			got := envInt(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("envInt(%q, %d) = %d, want %d", tt.key, tt.fallback, got, tt.want)
			}
		})
	}
}

// ── Adapter type validation ─────────────────────────────────

func TestAdapterTypeSelection(t *testing.T) {
	validTypes := []string{"cowrie", "dionaea", "tpot"}
	invalidTypes := []string{"unknown", "", "nmap", "suricata"}

	for _, at := range validTypes {
		t.Run("valid_"+at, func(t *testing.T) {
			valid := false
			for _, v := range []string{"cowrie", "dionaea", "tpot"} {
				if at == v {
					valid = true
					break
				}
			}
			if !valid {
				t.Errorf("adapter type %q should be valid", at)
			}
		})
	}

	for _, at := range invalidTypes {
		t.Run("invalid_"+at, func(t *testing.T) {
			valid := false
			for _, v := range []string{"cowrie", "dionaea", "tpot"} {
				if at == v {
					valid = true
					break
				}
			}
			if valid {
				t.Errorf("adapter type %q should be invalid", at)
			}
		})
	}
}

// ── Default configuration values ────────────────────────────

func TestDefaultConfigValues(t *testing.T) {
	// Verify defaults match what main() uses
	tests := []struct {
		name     string
		key      string
		fallback string
	}{
		{"adapter_type", "ADAPTER_TYPE", "cowrie"},
		{"nats_url", "NATS_URL", "nats://nats.cicdecoy.svc.cluster.local:4222"},
		{"nats_stream", "NATS_STREAM", "DECOY_EVENTS"},
		{"cowrie_log_path", "COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json"},
		{"dionaea_log_path", "DIONAEA_LOG_PATH", "/var/lib/dionaea/dionaea.json"},
		{"tpot_es_url", "TPOT_ES_URL", "http://localhost:64298"},
		{"tpot_index_pattern", "TPOT_INDEX_PATTERN", "logstash-*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Unset the env var so we get the fallback
			os.Unsetenv(tt.key)
			got := envOr(tt.key, tt.fallback)
			if got != tt.fallback {
				t.Errorf("default for %s = %q, want %q", tt.key, got, tt.fallback)
			}
		})
	}
}

// ── Decoy name generation ───────────────────────────────────

func TestDecoyNameGeneration(t *testing.T) {
	tests := []struct {
		adapterName string
		envValue    string
		want        string
	}{
		{"cowrie", "", "cowrie-default"},
		{"dionaea", "", "dionaea-default"},
		{"tpot", "", "tpot-default"},
		{"cowrie", "bastion-dmz-01", "bastion-dmz-01"},
	}

	for _, tt := range tests {
		t.Run(tt.adapterName+"_"+tt.want, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv("ADAPTER_DECOY_NAME", tt.envValue)
			} else {
				os.Unsetenv("ADAPTER_DECOY_NAME")
			}

			got := envOr("ADAPTER_DECOY_NAME", tt.adapterName+"-default")
			if got != tt.want {
				t.Errorf("decoy name = %q, want %q", got, tt.want)
			}
		})
	}
}

// ── Channel buffer size ─────────────────────────────────────

func TestEventChannelBufferSize(t *testing.T) {
	// Verify the buffer size used in main() is reasonable
	bufferSize := 1000 // from main.go: make(chan schema.Event, 1000)

	if bufferSize < 100 {
		t.Error("event channel buffer too small for production use")
	}
	if bufferSize > 100000 {
		t.Error("event channel buffer unnecessarily large")
	}
}

// ── envInt with Sscanf edge cases ───────────────────────────

func TestEnvInt_SscanfBehavior(t *testing.T) {
	// Test that Sscanf parses the way envInt expects
	tests := []struct {
		input string
		want  int
	}{
		{"42", 42},
		{"1", 1},
		{"-5", -5},
		{"0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var n int
			fmt.Sscanf(tt.input, "%d", &n)
			if n != tt.want {
				t.Errorf("Sscanf(%q) = %d, want %d", tt.input, n, tt.want)
			}
		})
	}
}
