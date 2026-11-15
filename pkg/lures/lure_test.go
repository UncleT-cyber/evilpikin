package lures

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistryCreateValidateDelete(t *testing.T) {
	r := NewRegistry()
	l, err := r.Create("login-reset", "ms-live", "https://decoy.example/loggedout")
	if err != nil {
		t.Fatal(err)
	}
	if l.ID == "" || l.Path != "login-reset" {
		t.Fatalf("bad lure: %+v", l)
	}
	if got, ok := r.Validate(l.ID); !ok || got.ID != l.ID {
		t.Fatal("valid lure not found")
	}
	// Inactive lures must not validate.
	r.SetActive(l.ID, false)
	if _, ok := r.Validate(l.ID); ok {
		t.Fatal("inactive lure should not validate")
	}
	r.SetActive(l.ID, true)
	if _, ok := r.Validate(l.ID); !ok {
		t.Fatal("re-activated lure should validate")
	}
	if !r.Delete(l.ID) {
		t.Fatal("delete returned false")
	}
	if _, ok := r.Get(l.ID); ok {
		t.Fatal("lure still present after delete")
	}
}

func TestRegistryRequiresPath(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Create("", "x", ""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestSessionBinding(t *testing.T) {
	r := NewRegistry()
	l, _ := r.Create("reset", "t1", "")
	tok := r.BindSession("sess1", l.ID, "t1", "1.2.3.4", "curl").Token
	if tok != "sess1" {
		t.Fatalf("token = %q", tok)
	}
	s, ok := r.GetSession("sess1")
	if !ok || s.TargetProfile != "t1" || s.ClientIP != "1.2.3.4" {
		t.Fatalf("bad session: %+v", s)
	}
	r.Touch("sess1", "/page1")
	r.Touch("sess1", "/page1") // dedupe last
	r.Touch("sess1", "/page2")
	if len(s.Pages) != 2 {
		t.Fatalf("pages = %v", s.Pages)
	}
	r.RecordCredential("sess1", "victim@corp")
	r.RecordTokenCaptured("sess1")
	if s.Username != "victim@corp" || !s.TokenCaptured {
		t.Fatalf("credential capture failed: %+v", s)
	}
}

func TestHTTPHelpers(t *testing.T) {
	r := NewRegistry()
	l, _ := r.Create("portal", "t1", "")

	// Valid token -> EP_SESS cookie set, param stripped, session bound.
	req := httptest.NewRequest("GET", "https://x.test/portal?id="+l.ID, nil)
	rec := httptest.NewRecorder()
	tok := SetSessionCookie(rec, req, "evil.test")
	if tok == "" {
		t.Fatal("no session token generated")
	}
	if c, err := req.Cookie(SessionCookieName); err == nil {
		t.Fatalf("cookie should not be readable back from the same request: %v", c)
	}
	if rec.Result().Cookies()[0].Name != SessionCookieName {
		t.Fatal("EP_SESS cookie not set on response")
	}
	_ = r.BindSession(tok, l.ID, "t1", "9.9.9.9", "ua")
	StripParam(req, DefaultParamName)
	if req.URL.Query().Get(DefaultParamName) != "" {
		t.Fatal("param not stripped")
	}

	// SafeRedirect.
	rec2 := httptest.NewRecorder()
	SafeRedirect(rec2, httptest.NewRequest("GET", "/", nil), "")
	if rec2.Result().StatusCode != http.StatusFound {
		t.Fatalf("redirect status = %d", rec2.Result().StatusCode)
	}
	if loc := rec2.Header().Get("Location"); loc != DefaultSafeRedirect {
		t.Fatalf("location = %q", loc)
	}
}

func TestMaskingHelpers(t *testing.T) {
	if got := RLOHideExtension("invoice", "pdf", "exe"); got == "" {
		t.Fatal("RLO returned empty")
	}
	// The RLO char must be present in the output.
	if !containsRune(RLOHideExtension("invoice", "pdf", "exe"), '\u202e') {
		t.Fatal("RLO char missing")
	}
	open := OpenRedirectLure("trusted.com", "/go", "https://evil.test/x")
	if !containsSub(open, "trusted.com/go") {
		t.Fatalf("open redirect malformed: %s", open)
	}
	if !containsSub(open, "url=https%3A%2F%2Fevil.test%2Fx") {
		t.Fatalf("open redirect did not embed phishing url: %s", open)
	}
	sp := SpoofableURL("evi1pikin.com", "login-reset", "abc123")
	if got := (Lure{ID: "abc123", Path: "login-reset"}).TrackingURL("evi1pikin.com", ""); got != sp {
		t.Fatalf("tracking url mismatch: %s vs %s", got, sp)
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
