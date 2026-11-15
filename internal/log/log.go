package log

import (
	"fmt"
	stdlog "log"
	"time"
)

func stamp() string {
	t := time.Now()
	return fmt.Sprintf("%02d:%02d:%02d", t.Hour(), t.Minute(), t.Second())
}

// quiet suppresses the stdlog (stdout) mirror of log entries. The TUI enables
// this so entries are delivered only via the bus (telemetry pane) and do not
// also print raw beneath the UI (which looks like the telemetry duplicating
// at the bottom of the screen). publish() still runs, so the pane stays live.
var quiet bool

// SetQuiet toggles the stdlog mirror. Call with true from the TUI at startup.
func SetQuiet(q bool) { quiet = q }

func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !quiet {
		stdlog.Printf("[%s] [inf] %s", stamp(), msg)
	}
	publish("inf", msg)
}

func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !quiet {
		stdlog.Printf("[%s] [err] %s", stamp(), msg)
	}
	publish("err", msg)
}

func Debug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !quiet {
		stdlog.Printf("[%s] [dbg] %s", stamp(), msg)
	}
	publish("dbg", msg)
}

func Important(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !quiet {
		stdlog.Printf("[%s] [imp] %s", stamp(), msg)
	}
	publish("imp", msg)
}

func Fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	stdlog.Fatalf("[%s] [!!!] %s", stamp(), msg)
	publish("!!!", msg)
}
