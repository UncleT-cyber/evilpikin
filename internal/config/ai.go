// Package config holds operator-tunable settings for Evil Pikin. The AI block is
// defined here so the control plane can load it from ai.json, but the proxy core
// never requires it: when disabled (the default), traffic runs entirely through
// the pure-Go StaticTransformer. This is the "zero-AI fallback" guarantee.
package config

import (
	"encoding/json"
	"os"
)

// AIConfig describes a pluggable LLM provider. It is intentionally inert by
// default. The proxy treats a missing key, a disabled flag, or any runtime error
// as a signal to stay on the static path.
//
// Provider is one of: "openai" | "anthropic" | "deepseek" | "local". BaseURL
// overrides the endpoint (e.g. an internal Ollama/vLLM instance) so tokens never
// leave the lab. APIKey is read from the environment at load time, never stored
// in source.
type AIConfig struct {
	Enabled   bool   `json:"enabled"`
	Provider  string `json:"provider"`
	APIKeyEnv string `json:"api_key_env"` // name of env var holding the key
	ModelName string `json:"model_name"`
	BaseURL   string `json:"base_url"`
}

// DefaultAIConfig returns a safe, disabled configuration.
func DefaultAIConfig() *AIConfig {
	return &AIConfig{Enabled: false, Provider: "local"}
}

// LoadAIConfig reads ai.json if present. A missing file is not an error: it
// simply yields the default (disabled) config, so the tool runs fully offline.
func LoadAIConfig(path string) (*AIConfig, error) {
	cfg := DefaultAIConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ResolveKey returns the API key from the configured environment variable, or ""
// if unset. Keys are never persisted in the config file.
func (c *AIConfig) ResolveKey() string {
	if c.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(c.APIKeyEnv)
}
