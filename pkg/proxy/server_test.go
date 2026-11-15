package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestNewSingleHostReverseProxyStripsForwardedHeaders verifies the spec/path
// Director mirrors the live engine: upstream only sees the real origin Host and
// no forwarding headers that trip upstream security drops.
func TestNewSingleHostReverseProxyStripsForwardedHeaders(t *testing.T) {
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

	pe := NewProxyEngine(nil)
	pe.Scheme = "http" // test against plaintext httptest upstream
	pe.LureParam = "id"

	p := pe.proxyFor(u.Host)

	req := httptest.NewRequest(http.MethodGet, "http://ms.test/", nil)
	req.Host = "ms.test"
	req.Header.Set("Forwarded", "for=1.2.3.4")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Host", "ms.test")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

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
}
