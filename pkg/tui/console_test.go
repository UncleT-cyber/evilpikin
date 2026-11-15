package tui

import (
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/pkg/lures"
)

func TestLureListAndAdd(t *testing.T) {
	db := t.TempDir() + "/t.db"
	store, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLure(&lures.Lure{ID: "abc123", Path: "login-reset", TargetProfile: "login.ms.test", IsActive: true}); err != nil {
		t.Fatal(err)
	}

	m := NewModel(Config{Store: store})
	m.listLures()
	if !strings.Contains(m.shellBuf, "Registered Lures") {
		t.Fatalf("listLures did not render header: %q", m.shellBuf)
	}
	if !strings.Contains(m.shellBuf, "login-reset") {
		t.Fatalf("existing lure path missing: %q", m.shellBuf)
	}

	invoked := false
	m.cfg.OnLureAdd = func(path, target, redirect string) (string, error) {
		invoked = true
		if err := store.SaveLure(&lures.Lure{ID: "def456", Path: path, TargetProfile: target, IsActive: true}); err != nil {
			return "", err
		}
		return "lure def456 registered", nil
	}
	m.addLure([]string{"vpn-portal", "microsoft"})
	if !invoked {
		t.Fatal("OnLureAdd hook was not invoked")
	}
	m.listLures()
	if !strings.Contains(m.shellBuf, "def456") {
		t.Fatalf("added lure not present in list: %q", m.shellBuf)
	}
}

func TestLureRemove(t *testing.T) {
	db := t.TempDir() + "/t.db"
	store, err := storage.OpenSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLure(&lures.Lure{ID: "toremove", Path: "x", TargetProfile: "login.ms.test", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	m := NewModel(Config{Store: store})
	removed := ""
	m.cfg.OnLureRemove = func(id string) error {
		removed = id
		return store.DeleteLure(id)
	}
	m.removeLure([]string{"toremove"})
	if removed != "toremove" {
		t.Fatal("OnLureRemove hook not invoked")
	}
	ls, _ := store.ListLures()
	for _, l := range ls {
		if l.ID == "toremove" {
			t.Fatal("lure was not removed from store")
		}
	}
}

func TestHelpMentionsLures(t *testing.T) {
	m := NewModel(Config{})
	m.appendShell(m.helpText(nil))
	if !strings.Contains(m.shellBuf, "lure") {
		t.Fatal("help text does not mention lure commands")
	}
}
