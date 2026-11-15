package proxy

import (
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/user/evilpikin/internal/storage"
)

var injectWorkPool = sync.Pool{New: func() interface{} { b := make([]byte, 0, 64*1024); return &b }}
var injectReadPool = sync.Pool{New: func() interface{} { b := make([]byte, 32*1024); return &b }}

const (
	injectHead = 0
	injectEnd  = 1
)

type injectOp struct {
	kind int // injectHead | injectEnd
	code string
	done bool
}

type injectionReader struct {
	src     io.Reader
	ops     []injectOp
	work    *[]byte
	readBuf *[]byte
	pending []byte
	eof     bool
}

// wrapInjectionCode emits a properly fenced HTML element for the injection so
// the browser executes it instead of leaking it as literal text. It is
// idempotent: code that already carries its own <script>/<style> tags is left
// untouched (this keeps hand-authored payloads and tests working).
func wrapInjectionCode(inj *storage.InjectionRule) string {
	code := inj.Code
	low := strings.ToLower(code)
	switch strings.ToLower(inj.Type) {
	case "css", "style":
		if strings.Contains(low, "<style") {
			return code
		}
		return "<style>" + code + "</style>"
	default:
		if strings.Contains(low, "<script") {
			return code
		}
		return "<script type=\"text/javascript\">" + code + "</script>"
	}
}

func NewInjectionReader(src io.Reader, injections []*storage.InjectionRule, path string) io.Reader {
	ops := buildInjectOps(injections, path)
	if len(ops) == 0 {
		return src
	}
	return &injectionReader{
		src:     src,
		ops:     ops,
		work:    injectWorkPool.Get().(*[]byte),
		readBuf: injectReadPool.Get().(*[]byte),
	}
}

func buildInjectOps(injections []*storage.InjectionRule, path string) []injectOp {
	out := []injectOp{}
	for _, inj := range injections {
		if inj == nil || inj.Code == "" {
			continue
		}
		if inj.URLPattern != "" && inj.URLPattern != "*" && !strings.Contains(path, inj.URLPattern) {
			continue
		}
		code := wrapInjectionCode(inj)
		switch strings.ToLower(inj.Position) {
		case "body", "end":
			out = append(out, injectOp{kind: injectEnd, code: code})
		default:
			out = append(out, injectOp{kind: injectHead, code: code})
		}
	}
	return out
}

var (
	headTagRE = regexp.MustCompile(`(?i)<head[^>]*>`)
	htmlTagRE = regexp.MustCompile(`(?i)<html[^>]*>`)
	bodyEndRE = regexp.MustCompile(`(?i)</body>`)
)

// insertPos returns the byte offset where op should be spliced into data, or -1
// if the anchor is not present yet. Head injections go right after <head> (or
// <html> if absent, or at the very start); end injections go right before
// </body>. Matching is case-insensitive and tolerant of tag attributes, so the
// payload lands inside valid HTML rather than leaking as raw text.
func insertPos(data []byte, op injectOp) int {
	switch op.kind {
	case injectHead:
		if m := headTagRE.FindIndex(data); m != nil {
			return m[1]
		}
		if m := htmlTagRE.FindIndex(data); m != nil {
			return m[1]
		}
		return 0
	case injectEnd:
		if m := bodyEndRE.FindIndex(data); m != nil {
			return m[0]
		}
		return -1
	}
	return -1
}

func (r *injectionReader) Read(p []byte) (int, error) {
	for {
		if len(r.pending) > 0 {
			n := copy(p, r.pending)
			r.pending = r.pending[n:]
			return n, nil
		}
		if r.eof {
			injectWorkPool.Put(r.work)
			injectReadPool.Put(r.readBuf)
			return 0, io.EOF
		}
		n, err := r.src.Read((*r.readBuf)[:cap(*r.readBuf)])
		if n > 0 {
			*r.work = append(*r.work, (*r.readBuf)[:n]...)
		}
		if err != nil {
			r.eof = true
			r.process(true)
			continue
		}
		r.process(false)
	}
}

func (r *injectionReader) process(flush bool) {
	for {
		bestOp, bestPos := -1, -1
		for i := range r.ops {
			if r.ops[i].done {
				continue
			}
			pos := insertPos(*r.work, r.ops[i])
			if pos < 0 {
				continue
			}
			if bestOp == -1 || pos < bestPos {
				bestOp, bestPos = i, pos
			}
		}
		if bestOp < 0 {
			break
		}
		op := &r.ops[bestOp]
		op.done = true
		*r.work = append((*r.work)[:bestPos], append([]byte(op.code), (*r.work)[bestPos:]...)...)
	}

	hold := 0
	for i := range r.ops {
		if !r.ops[i].done && r.ops[i].kind == injectEnd {
			hold = 8 // len("</body>")
		}
	}

	if flush {
		for i := range r.ops {
			if r.ops[i].done {
				continue
			}
			r.ops[i].done = true
			if r.ops[i].kind == injectEnd {
				*r.work = append(*r.work, []byte(r.ops[i].code)...)
			} else {
				*r.work = append([]byte(r.ops[i].code), *r.work...)
			}
		}
		r.pending = append(r.pending, *r.work...)
		*r.work = (*r.work)[:0]
		return
	}

	if hold > 0 && len(*r.work) > hold {
		keep := len(*r.work) - hold
		r.pending = append(r.pending, (*r.work)[:keep]...)
		copy(*r.work, (*r.work)[keep:])
		*r.work = (*r.work)[:len(*r.work)-keep]
	}
}
