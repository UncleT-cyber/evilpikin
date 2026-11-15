package firewall

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync"
)

type GeoFenceConfig struct {
	Mode       string   `json:"mode"`
	AllowCIDRs []string `json:"allow_cidrs"`
	DenyCIDRs  []string `json:"deny_cidrs"`
	DenyASNs   []string `json:"deny_asns"`
	DecoyURL   string   `json:"decoy_url"`
}

type ASNResolver interface {
	ASN(ip net.IP) (string, error)
}

type GeoFence struct {
	mu          sync.RWMutex
	mode        string
	allowCIDRs  []*net.IPNet
	denyCIDRs   []*net.IPNet
	denyASNs    map[string]bool
	asnResolver ASNResolver
	decoyURL    string
}

func NewGeoFence() *GeoFence {
	return &GeoFence{
		mode:     "deny",
		denyASNs: make(map[string]bool),
		decoyURL: "https://www.microsoft.com/",
	}
}

func (g *GeoFence) SetASNResolver(r ASNResolver) {
	g.mu.Lock()
	g.asnResolver = r
	g.mu.Unlock()
}

func (g *GeoFence) LoadConfig(cfg GeoFenceConfig) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mode = cfg.Mode
	if g.mode == "" {
		g.mode = "deny"
	}
	if cfg.DecoyURL != "" {
		g.decoyURL = cfg.DecoyURL
	}
	g.allowCIDRs = parseCIDRs(cfg.AllowCIDRs)
	g.denyCIDRs = parseCIDRs(cfg.DenyCIDRs)
	g.denyASNs = make(map[string]bool)
	for _, a := range cfg.DenyASNs {
		g.denyASNs[a] = true
	}
	return nil
}

func (g *GeoFence) LoadConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg GeoFenceConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	return g.LoadConfig(cfg)
}

func parseCIDRs(in []string) []*net.IPNet {
	out := []*net.IPNet{}
	for _, c := range in {
		if _, ipnet, err := net.ParseCIDR(c); err == nil {
			out = append(out, ipnet)
		}
	}
	return out
}

func (g *GeoFence) Check(ipStr string) (bool, string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, "invalid-ip"
	}
	for _, n := range g.denyCIDRs {
		if n.Contains(ip) {
			return false, "denied-cidr"
		}
	}
	if g.asnResolver != nil {
		if asn, err := g.asnResolver.ASN(ip); err == nil && g.denyASNs[asn] {
			return false, "denied-asn"
		}
	}
	if g.mode == "allow" {
		for _, n := range g.allowCIDRs {
			if n.Contains(ip) {
				return true, "allowed-cidr"
			}
		}
		return false, "not-in-allowlist"
	}
	for _, n := range g.allowCIDRs {
		if n.Contains(ip) {
			return false, "allowlist-override-deny"
		}
	}
	return true, "default-allow"
}

func (g *GeoFence) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		allowed, _ := g.Check(host)
		if !allowed {
			g.redirect(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *GeoFence) redirect(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	decoy := g.decoyURL
	g.mu.RUnlock()
	http.Redirect(w, r, decoy, http.StatusFound)
}
