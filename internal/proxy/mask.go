package proxy

import (
	"bytes"
	"io"

	"github.com/user/evilpikin/internal/storage"
)

// subFilterReader applies SubFilter rules (real-domain -> benign-sub) to a
// response body. It is instantiated only when a target configures SubFilters,
// so the common path keeps the zero-allocation streaming pipeline untouched.
type subFilterReader struct {
	src     io.Reader
	filters []storage.SubFilter
	data    []byte
	sent    bool
}

func NewSubFilterReader(src io.Reader, filters []storage.SubFilter) io.Reader {
	if len(filters) == 0 {
		return src
	}
	return &subFilterReader{src: src, filters: filters}
}

func (r *subFilterReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		raw, err := io.ReadAll(r.src)
		if err != nil {
			return 0, err
		}
		r.data = ApplySubFilters(raw, r.filters)
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// ApplySubFilters performs literal string substitution of each filter's Domain
// with its Sub across the body. Used both streaming (served pages) and by
// tests. Order is as configured; later rules operate on earlier output.
func ApplySubFilters(body []byte, filters []storage.SubFilter) []byte {
	out := body
	for _, f := range filters {
		if f.Domain == "" || f.Sub == "" {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(f.Domain), []byte(f.Sub))
	}
	return out
}
