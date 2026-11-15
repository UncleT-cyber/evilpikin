package console

import (
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gliderlabs/ssh"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/tui"
	gossh "golang.org/x/crypto/ssh"
)

// LoadAuthorizedKeys parses an OpenSSH authorized_keys file into a set of
// canonical key strings used by the embedded SSH server's public-key check.
func LoadAuthorizedKeys(path string) (map[string]bool, error) {
	keys := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			log.Error("ssh auth keys: skipping bad line: %v", err)
			continue
		}
		keys[strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pub)))] = true
	}
	return keys, nil
}

// ServeSSH starts the embedded management SSH listener. Each authenticated
// operator session is granted an isolated multi-pane TUI (status bar + shell +
// live log stream). The server runs independently of client connections, so
// operators disconnecting (or all sessions dropping) never stops the proxy
// engine.
func (c *Console) ServeSSH(listenAddr string, authorizedKeys map[string]bool) error {
	srv := &ssh.Server{
		Addr: listenAddr,
		Handler: func(s ssh.Session) {
			m := tui.NewModel(c)
			p := m.Program(tea.WithInput(s), tea.WithOutput(s))
			go func() {
				for e := range m.LogChannel() {
					p.Send(tui.LogLineMsg(e.Level, e.Message))
				}
			}()
			// Forward PTY window changes so the TUI lays out correctly. The
			// initial size is delivered via pty.Window (not the change channel),
			// so send it explicitly before the change loop starts.
			if pty, winCh, ok := s.Pty(); ok {
				if pty.Window.Width > 0 {
					p.Send(tea.WindowSizeMsg{Width: pty.Window.Width, Height: pty.Window.Height})
				}
				go func() {
					for w := range winCh {
						p.Send(tea.WindowSizeMsg{Width: w.Width, Height: w.Height})
					}
				}()
			}
			_ = m.Launch(p)
			s.Exit(0)
		},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			if authorizedKeys == nil {
				return false
			}
			_, ok := authorizedKeys[strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key)))]
			return ok
		},
		// Allow any PTY the client requests so the TUI renders.
		PtyCallback: func(ctx ssh.Context, pty ssh.Pty) bool { return true },
	}
	log.Info("ssh control plane listening on %s", listenAddr)
	return srv.ListenAndServe()
}
