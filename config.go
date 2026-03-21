package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds application settings loaded from a YAML or JSON file.
type Config struct {
	ClientID            string `json:"client_id"            yaml:"client_id"`
	ClientSecret        string `json:"client_secret"        yaml:"client_secret"`
	RefreshToken        string `json:"refresh_token"        yaml:"refresh_token"`
	DeviceID            string `json:"device_id"            yaml:"device_id"`
	OutputDir           string `json:"output_dir"           yaml:"output_dir"`
	FontPath            string `json:"font_path"            yaml:"font_path"`
	SegmentSeconds      int    `json:"segment_seconds"      yaml:"segment_seconds"`
	ExtendMarginSeconds int    `json:"extend_margin_seconds" yaml:"extend_margin_seconds"`
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	switch ext := filepath.Ext(path); ext {
	case ".yaml", ".yml":
		if err = yaml.NewDecoder(f).Decode(&cfg); err != nil {
			return nil, err
		}
	case ".json":
		if err = json.NewDecoder(f).Decode(&cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported config type: %s", ext)
	}

	// Validate required fields
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}
	if cfg.RefreshToken == "" {
		return nil, fmt.Errorf("refresh_token is required")
	}
	if cfg.DeviceID == "" {
		return nil, fmt.Errorf("device_id is required")
	}

	if cfg.FontPath == "" {
		cfg.FontPath = "/usr/share/DejaVuSansMono.ttf"
	}
	if cfg.SegmentSeconds <= 0 {
		cfg.SegmentSeconds = 1800 // default 30 min
	}
	if cfg.ExtendMarginSeconds <= 0 {
		cfg.ExtendMarginSeconds = 30 // default 30 sec
	}
	return &cfg, nil
}
