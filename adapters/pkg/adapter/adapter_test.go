package adapter

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		name              string
		adapterName       string
		wantDecoyName     string
		wantTier          int
		wantSessionPrefix string
	}{
		{
			name:              "cowrie",
			adapterName:       "cowrie",
			wantDecoyName:     "cowrie-default",
			wantTier:          1,
			wantSessionPrefix: "cowrie",
		},
		{
			name:              "dionaea",
			adapterName:       "dionaea",
			wantDecoyName:     "dionaea-default",
			wantTier:          1,
			wantSessionPrefix: "dionaea",
		},
		{
			name:              "tpot",
			adapterName:       "tpot",
			wantDecoyName:     "tpot-default",
			wantTier:          1,
			wantSessionPrefix: "tpot",
		},
		{
			name:              "custom",
			adapterName:       "my-honeypot",
			wantDecoyName:     "my-honeypot-default",
			wantTier:          1,
			wantSessionPrefix: "my-honeypot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig(tt.adapterName)

			if cfg.DecoyName != tt.wantDecoyName {
				t.Errorf("DecoyName = %q, want %q", cfg.DecoyName, tt.wantDecoyName)
			}
			if cfg.DecoyTier != tt.wantTier {
				t.Errorf("DecoyTier = %d, want %d", cfg.DecoyTier, tt.wantTier)
			}
			if cfg.SessionPrefix != tt.wantSessionPrefix {
				t.Errorf("SessionPrefix = %q, want %q", cfg.SessionPrefix, tt.wantSessionPrefix)
			}
		})
	}
}

func TestDefaultConfig_EmptyName(t *testing.T) {
	cfg := DefaultConfig("")
	if cfg.DecoyName != "-default" {
		t.Errorf("DecoyName = %q, want %q", cfg.DecoyName, "-default")
	}
	if cfg.SessionPrefix != "" {
		t.Errorf("SessionPrefix = %q, want empty", cfg.SessionPrefix)
	}
}
