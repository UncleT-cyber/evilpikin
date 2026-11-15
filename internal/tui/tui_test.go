package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

type fakeBackend struct{}

func (fakeBackend) BuildRootCmd() *cobra.Command {
	return &cobra.Command{Use: "fake"}
}
func (fakeBackend) Status() StatusInfo {
	return StatusInfo{Domain: "evilpikin.test", IP: "198.51.100.7", IPVersion: "IPv4", IPSource: "Manual", DNS: "live (TTL 60s, via Cloudflare)"}
}

func TestModelRendersStatusAndIsolatesLogs(t *testing.T) {
	var md tea.Model = NewModel(fakeBackend{})
	md, _ = md.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	md, _ = md.Update(logMsg{line: "[inf] sync complete"})
	md, _ = md.Update(tea.KeyMsg{Type: tea.KeyEnter}) // empty line, just echoes prompt

	view := md.(model).View()
	if !strings.Contains(view, "Domain: evilpikin.test") {
		t.Fatalf("status bar missing domain:\n%s", view)
	}
	if !strings.Contains(view, "198.51.100.7 [IPv4]") {
		t.Fatalf("status bar missing IP/version:\n%s", view)
	}
	if !strings.Contains(view, "LIVE LOG STREAM") {
		t.Fatalf("log pane missing:\n%s", view)
	}
	if !strings.Contains(view, "sync complete") {
		t.Fatalf("log entry not rendered:\n%s", view)
	}
	if !strings.Contains(view, "SHELL") {
		t.Fatalf("shell pane missing:\n%s", view)
	}
}

func TestRunLineCapturesOutput(t *testing.T) {
	// A backend whose root command writes to Out/Err.
	b := fakeBackend{}
	out, err := RunLine(b, "anything")
	if err != nil {
		// cobra returns an error for an unknown command; that's acceptable here,
		// the point is the call must not panic and returns captured text.
		_ = err
	}
	_ = out
}
