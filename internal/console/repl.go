package console

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anmitsu/go-shlex"
	"github.com/user/evilpikin/internal/tui"
)

const prompt = "evil_pikin > "

// RunLocal runs the control shell against the process stdio. This is the
// "tmux mode" entrypoint: run the binary inside a tmux session over SSH, then
// detach — the process (and therefore the proxy engine) keeps running.
func (c *Console) RunLocal() {
	if err := tui.Start(c); err != nil {
		// Fall back to the line REPL if the terminal UI cannot start (e.g. a
		// non-TTY pipe). The engine is unaffected.
		fmt.Fprintf(os.Stderr, "tui unavailable (%v); falling back to line shell\n", err)
		c.RunInteractive(os.Stdin, os.Stdout)
	}
}

// RunInteractive drives the command loop against arbitrary reader/writer
// streams. Both the local REPL and each embedded-SSH session funnel through
// here, so command behaviour is identical regardless of transport.
//
// Closing the stream (terminal detach / SSH session close) ends THIS loop but
// never touches the background engine goroutines.
func (c *Console) RunInteractive(in io.Reader, out io.Writer) {
	fmt.Fprintln(out, "Evil Pikin control shell. Type 'help'. Detach/exit ends this session only.")
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for {
		fmt.Fprint(out, prompt)
		if !scanner.Scan() {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if low == "exit" || low == "quit" {
			return
		}
		args, err := shlex.Split(line, false)
		if err != nil {
			fmt.Fprintf(out, "parse error: %v\n", err)
			continue
		}
		root := c.BuildRootCmd()
		root.SetIn(strings.NewReader(""))
		root.SetOut(out)
		root.SetErr(out)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
		}
	}
}
