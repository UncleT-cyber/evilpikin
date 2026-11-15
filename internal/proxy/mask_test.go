package proxy

import (
	"bytes"
	"testing"

	"github.com/user/evilpikin/internal/storage"
)

func TestApplySubFilters(t *testing.T) {
	body := []byte("visit login.microsoftonline.com and /login now")
	filters := []storage.SubFilter{
		{Domain: "login.microsoftonline.com", Sub: "portal.evilpikin.net"},
		{Domain: "/login", Sub: "/portal"},
	}
	out := ApplySubFilters(body, filters)
	want := []byte("visit portal.evilpikin.net and /portal now")
	if !bytes.Equal(out, want) {
		t.Fatalf("got %q want %q", out, want)
	}
}
