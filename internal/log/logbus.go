package log

import (
	"sync"
	"time"
)

// BusEntry is a single log line emitted to subscribers.
type BusEntry struct {
	Time    time.Time
	Level   string
	Message string
}

// LogBus is a concurrency-safe pub/sub broadcaster for structured log lines. It
// exists so the TUI can render a live, isolated log stream without tearing the
// interactive shell prompt. Publishing never blocks: if a subscriber's buffer is
// full the line is dropped, keeping the proxy hot path safe under load.
type LogBus struct {
	mu   sync.Mutex
	subs []chan BusEntry
}

// NewBus returns an empty bus.
func NewBus() *LogBus { return &LogBus{} }

// Subscribe registers a new subscriber and returns a channel that receives log
// entries. The channel is buffered; callers should drain it promptly.
func (b *LogBus) Subscribe() <-chan BusEntry {
	ch := make(chan BusEntry, 256)
	b.mu.Lock()
	b.subs = append(b.subs, ch)
	b.mu.Unlock()
	return ch
}

// Publish sends an entry to all subscribers without blocking.
func (b *LogBus) Publish(e BusEntry) {
	b.mu.Lock()
	subs := b.subs
	b.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- e:
		default:
			// Drop rather than block the caller.
		}
	}
}

// DefaultBus is the process-wide bus that the package-level log functions feed.
var DefaultBus = NewBus()

func publish(level, msg string) {
	DefaultBus.Publish(BusEntry{Time: time.Now(), Level: level, Message: msg})
}
