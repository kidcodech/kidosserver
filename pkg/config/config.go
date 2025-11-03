package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Config represents runtime configuration persisted on disk.
type Config struct {
	Interfaces InterfaceConfig `json:"interfaces"`
	DNS        DNSConfig       `json:"dns"`
	Web        WebConfig       `json:"web"`
}

// InterfaceConfig describes NIC and veth names.
type InterfaceConfig struct {
	Physical string `json:"physical"`
	Veth     string `json:"veth"`
}

// DNSConfig holds DNS policy settings.
type DNSConfig struct {
	Blocklist []string `json:"blocklist"`
}

// WebConfig holds HTTP API config.
type WebConfig struct {
	Listen string `json:"listen"`
}

// Default returns a sane default configuration for fresh setups.
func Default() Config {
	return Config{
		Interfaces: InterfaceConfig{Physical: "eth0", Veth: "kidos"},
		DNS:        DNSConfig{Blocklist: []string{}},
		Web:        WebConfig{Listen: ":8080"},
	}
}

// Load reads config from disk or returns default if file missing.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Save writes config to disk.
func Save(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
