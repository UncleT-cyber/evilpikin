// Package tui implements the multi-pane terminal UI for Evil Pikin. It splits the
// screen into a status bar, an interactive shell pane, and a live log stream that
// is fully isolated from the shell prompt (so asynchronous events like dns sync
// never tear the input line). The same model runs locally (stdin/stdout) or over
// an SSH session.
//
// The TUI depends only on the Backend interface below, never on the concrete
// console package, so there is no import cycle between tui and console.
package tui

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/user/evilpikin/internal/log"
)

// StatusInfo is the read-only console state the TUI renders in its status bar.
type StatusInfo struct {
	Domain    string
	IP        string
	IPVersion string
	IPSource  string
	DNS       string
}

// Backend is the narrow surface the TUI needs from the control plane. The
// concrete console.Console implements it.
type Backend interface {
	BuildRootCmd() *cobra.Command
	Status() StatusInfo
}

// logMsg carries a new log line from the background bus into the Update loop.
type logMsg struct{ line string }

// doneMsg carries the result of an asynchronously executed shell command.
type doneMsg struct {
	line string
	err  error
}

type model struct {
	b      Backend
	input  textinput.Model
	shell  viewport.Model // shell output history
	logs   viewport.Model // live, isolated log stream
	logCh  <-chan log.BusEntry
	width  int
	height int
}

// NewModel builds a TUI model bound to a backend. It subscribes to the log bus
// immediately (before any program runs) so no log entries are missed.
func NewModel(b Backend) model {
	ti := textinput.New()
	ti.Placeholder = "type a command (help)"
	ti.Prompt = "evil_pikin > "
	ti.Focus()
	ti.CharLimit = 512

	return model{
		b:     b,
		input: ti,
		shell: viewport.New(80, 10),
		logs:  viewport.New(80, 10),
		logCh: log.DefaultBus.Subscribe(),
	}
}

// LogChannel returns the model's dedicated log bus subscription.
func (m model) LogChannel() <-chan log.BusEntry { return m.logCh }

// LogLineMsg builds a logMsg for external senders (e.g. the SSH path).
func LogLineMsg(level, msg string) tea.Msg {
	return logMsg{line: fmt.Sprintf("[%s] %s", level, msg)}
}

// RunLine executes a single command line against the backend's cobra tree and
// returns the captured output. Exported so the SSH path and tests can drive the
// same command loop the TUI uses.
func RunLine(b Backend, line string) (string, error) {
	return runCommand(b, line)
}

// runCommand executes a single command line against the backend's cobra tree and
// returns the captured output. It is invoked in a goroutine so the UI never blocks.
func runCommand(b Backend, line string) (string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil
	}
	root := b.BuildRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(strings.Fields(line))
	err := root.Execute()
	return buf.String(), err
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Some transports (e.g. headless/scripted SSH) never report a size;
		// degrade gracefully to a sane default so the UI still renders.
		w, h := msg.Width, msg.Height
		if w <= 0 {
			w = 80
		}
		if h <= 0 {
			h = 24
		}
		m.width = w
		m.height = h
		// Status bar 3 rows; logs get ~35% of the rest, shell the remainder.
		logH := msg.Height - 3 - 8
		if logH < 5 {
			logH = 5
		}
		shellH := msg.Height - 3 - logH - 3
		if shellH < 5 {
			shellH = 5
		}
		m.logs.Width = msg.Width - 2
		m.logs.Height = logH
		m.shell.Width = msg.Width - 2
		m.shell.Height = shellH
		return m, nil

	case logMsg:
		newContent := m.logs.View() + "\n" + msg.line
		m.logs.SetContent(newContent)
		m.logs.GotoBottom()
		return m, nil

	case doneMsg:
		out := msg.line
		if out == "" {
			out = "(ok)\n"
		}
		newContent := m.shell.View() + "\n" + out
		m.shell.SetContent(newContent)
		m.shell.GotoBottom()
		return m, nil

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEnter:
			line := m.input.Value()
			m.input.SetValue("")
			// Echo the command into the shell pane immediately.
			m.shell.SetContent(m.shell.View() + "\nevil_pikin > " + line)
			if line == "exit" || line == "quit" {
				return m, tea.Quit
			}
			b := m.b
			return m, func() tea.Msg {
				out, err := runCommand(b, line)
				if err != nil {
					out += "\nerror: " + err.Error() + "\n"
				}
				return doneMsg{line: out}
			}
		}

	case tea.MouseMsg:
		// Let the viewports handle scrolling.
		var cmd tea.Cmd
		m.shell, cmd = m.shell.Update(msg)
		m.logs, _ = m.logs.Update(msg)
		return m, cmd
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

var (
	statusStyle = lipgloss.NewStyle().Background(lipgloss.Color("63")).Foreground(lipgloss.Color("230")).Padding(0, 1).Bold(true)
	titleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	borderStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63"))
)

func (m model) View() string {
	if m.width == 0 {
		return "initializing..."
	}
	s := m.b.Status()
	status := fmt.Sprintf("Domain: %s   |   IP: %s [%s] (%s)   |   DNS: %s", s.Domain, s.IP, s.IPVersion, s.IPSource, s.DNS)
	statusBar := statusStyle.Render(status)

	shellPane := borderStyle.Width(m.width - 2).Render(
		titleStyle.Render("SHELL") + "\n" + m.shell.View() + "\n" + m.input.View(),
	)
	logPane := borderStyle.Width(m.width - 2).Render(
		titleStyle.Render("LIVE LOG STREAM (isolated)") + "\n" + m.logs.View(),
	)
	return lipgloss.JoinVertical(lipgloss.Left, statusBar, shellPane, logPane)
}

// Start launches the TUI on the current process terminal (stdin/stdout). Bubble
// Tea determines the size from the TTY automatically.
func Start(b Backend) error {
	m := NewModel(b)
	p := tea.NewProgram(m)
	return m.Launch(p)
}

// Launch starts the log pump and runs the program. It is transport-agnostic: the
// caller builds the program with whatever input/output it needs (a local TTY, an
// SSH session, etc.) and forwards window-size messages via p.Send. Quitting the
// TUI ends only this session; the proxy engine keeps running.
func (m model) Launch(p *tea.Program) error {
	go forwardLogs(p, m.logCh)
	_, err := p.Run()
	return err
}

// Program builds a Bubble Tea program from this model with the given options
// (e.g. tea.WithInput/WithOutput for an SSH session).
func (m model) Program(opts ...tea.ProgramOption) *tea.Program {
	return tea.NewProgram(m, opts...)
}

// forwardLogs pumps bus entries into the running program.
func forwardLogs(p *tea.Program, ch <-chan log.BusEntry) {
	for e := range ch {
		p.Send(logMsg{line: fmt.Sprintf("[%s] %s", e.Level, e.Message)})
	}
}
