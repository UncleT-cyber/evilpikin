package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScannerGuardDecoysBots(t *testing.T) {
	e := NewEngine()
	e.SetScannerShield(true)
	kit := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("LIVE KIT"))
	})
	h := e.scannerGuard(kit)

	cases := []struct {
		name string
		ua   string
		hdr  http.Header
		pass bool
	}{
		{"curl", "curl/8.0", http.Header{}, false},
		{"python", "python-requests/2.31", http.Header{}, false},
		{"empty ua", "", http.Header{}, false},
		{"headless", "Mozilla/5.0 HeadlessChrome/120", http.Header{}, false},
		{"chrome real", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
			http.Header{"Accept-Language": []string{"en-US"}, "Accept": []string{"text/html"}}, true},
		{"chrome missing headers", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
			http.Header{}, false},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "http://x/login", nil)
		req.Header.Set("User-Agent", c.ua)
		for k, v := range c.hdr {
			req.Header[k] = v
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		body := rec.Body.String()
		if c.pass && !strings.Contains(body, "LIVE KIT") {
			t.Errorf("%s: expected kit, got %q", c.name, body)
		}
		if !c.pass {
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s: expected 404 decoy, got %d", c.name, rec.Code)
			}
			if strings.Contains(body, "LIVE KIT") {
				t.Errorf("%s: scanner received the live kit", c.name)
			}
		}
	}
}

func TestScannerGuardCIDR(t *testing.T) {
	e := NewEngine()
	e.SetScannerShield(true)
	if err := e.AddScannerCIDR("203.0.113.0/24"); err != nil {
		t.Fatal(err)
	}
	kit := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("LIVE KIT"))
	})
	h := e.scannerGuard(kit)

	req := httptest.NewRequest("GET", "http://x/login", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "203.0.113.44:55555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("CIDR host expected decoy 404, got %d", rec.Code)
	}
}
