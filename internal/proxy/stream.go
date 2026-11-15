package proxy

import (
	"bytes"
	"io"
	"net"
	"strings"
)

type replaceOp struct {
	old string
	new string
}

type StreamReplacer struct {
	src     io.Reader
	ops     []replaceOp
	buf     []byte
	carried []byte
	eof     bool
}

func NewStreamReplacer(src io.Reader, replacements map[string]string) *StreamReplacer {
	r := &StreamReplacer{src: src}
	for k, v := range replacements {
		if k != "" {
			r.ops = append(r.ops, replaceOp{old: k, new: v})
		}
	}
	return r
}

func (s *StreamReplacer) maxOld() int {
	m := 0
	for _, op := range s.ops {
		if len(op.old) > m {
			m = len(op.old)
		}
	}
	return m
}

func (s *StreamReplacer) replace(data []byte) []byte {
	if len(s.ops) == 0 {
		return data
	}
	out := string(data)
	for _, op := range s.ops {
		if op.old == "" {
			continue
		}
		out = strings.ReplaceAll(out, op.old, op.new)
	}
	return []byte(out)
}

const streamWindow = 1 << 16

func (s *StreamReplacer) Read(p []byte) (int, error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	if s.eof {
		return 0, io.EOF
	}

	for {
		chunk := make([]byte, 8192)
		n, readErr := s.src.Read(chunk)
		if n > 0 {
			s.carried = append(s.carried, chunk[:n]...)
		}
		if n == 0 && readErr == nil {
			break
		}
		if readErr != nil {
			s.eof = true
			if len(s.carried) > 0 {
				s.buf = s.replace(s.carried)
				s.carried = nil
			}
			break
		}
		if len(s.carried) >= streamWindow {
			hold := s.holdBackPoint(s.carried)
			s.buf = s.replace(s.carried[:hold])
			tail := make([]byte, len(s.carried)-hold)
			copy(tail, s.carried[hold:])
			s.carried = tail
			break
		}
	}

	if len(s.buf) == 0 {
		if s.eof {
			return 0, io.EOF
		}
		return 0, nil
	}
	n2 := copy(p, s.buf)
	s.buf = s.buf[n2:]
	return n2, nil
}

type DomainPair struct {
	ProxyHost string
	Origin    string
}

// BuildDomainTranslations returns the origin->proxy-host string map used to
// rewrite URLs inside response bodies. proxyPort, when non-empty and not "443",
// is appended to the proxy host so rewritten links stay on the listening port
// (e.g. dev mode on :9443).
func BuildDomainTranslations(pairs []DomainPair, proxyPort string) map[string]string {
	m := make(map[string]string)
	for _, p := range pairs {
		if p.Origin == "" || p.ProxyHost == "" {
			continue
		}
		ph := p.ProxyHost
		if proxyPort != "" && proxyPort != "443" {
			ph = net.JoinHostPort(p.ProxyHost, proxyPort)
		}
		m["https://"+p.Origin] = "https://" + ph
		m["http://"+p.Origin] = "http://" + ph
		m["//"+p.Origin] = "//" + ph
		m[p.Origin] = ph
	}
	return m
}

func (s *StreamReplacer) holdBackPoint(raw []byte) int {
	M := s.maxOld()
	if M <= 0 {
		return len(raw)
	}
	start := len(raw) - M + 1
	if start < 0 {
		start = 0
	}
	for i := start; i < len(raw); i++ {
		for _, op := range s.ops {
			if len(op.old) == 0 {
				continue
			}
			rem := len(raw) - i
			if rem < len(op.old) && bytes.HasPrefix([]byte(op.old), raw[i:]) {
				return i
			}
		}
	}
	return len(raw)
}
