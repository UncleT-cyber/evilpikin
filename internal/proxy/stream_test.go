package proxy

import (
	"io"
	"strings"
	"testing"
)

type byteReader struct {
	data []byte
	pos  int
}

func (b *byteReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	p[0] = b.data[b.pos]
	b.pos++
	return 1, nil
}

func TestStreamReplacerSplitToken(t *testing.T) {
	src := &byteReader{data: []byte("a login.microsoftonline.com b login.microsoftonline.com end")}
	rep := map[string]string{"login.microsoftonline.com": "login.microsoftonline.com.evilpikin.net"}
	r := NewStreamReplacer(src, rep)

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(out)
	if strings.Contains(got, "login.microsoftonline.com") && !strings.Contains(got, ".evilpikin.net") {
		t.Fatalf("replacement failed, got: %s", got)
	}
	if !strings.Contains(got, "login.microsoftonline.com.evilpikin.net") {
		t.Fatalf("expected replaced domain, got: %s", got)
	}
}

func TestStreamReplacerNoAllocGrowth(t *testing.T) {
	big := strings.Repeat("x login.microsoftonline.com y ", 5000)
	src := &byteReader{data: []byte(big)}
	rep := map[string]string{"login.microsoftonline.com": "login.microsoftonline.com.evilpikin.net"}
	r := NewStreamReplacer(src, rep)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Count(string(out), ".evilpikin.net") != 5000 {
		t.Fatalf("expected 5000 replacements, got %d", strings.Count(string(out), ".evilpikin.net"))
	}
}
