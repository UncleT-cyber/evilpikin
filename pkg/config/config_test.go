package config

import "testing"

func TestSetServerIPValidation(t *testing.T) {
	c := NewRuntimeConfig()
	if err := c.SetServerIP("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if err := c.SetServerIP("192.168.1.10"); err != nil {
		t.Fatalf("valid IPv4 rejected: %v", err)
	}
	if err := c.SetServerIP("2001:db8::1"); err != nil {
		t.Fatalf("valid IPv6 rejected: %v", err)
	}
	if got := c.ServerIP; got != "2001:db8::1" {
		t.Fatalf("ServerIP = %q", got)
	}
}

func TestTargetForStripsPort(t *testing.T) {
	c := NewRuntimeConfig()
	c.SetTarget("login.evilpikin.com", "login.microsoftonline.com")

	// Exact match.
	if u, ok := c.TargetFor("login.evilpikin.com"); !ok || u != "login.microsoftonline.com" {
		t.Fatalf("exact match failed: %q %v", u, ok)
	}
	// TLS/SNI passes host:port.
	if u, ok := c.TargetFor("login.evilpikin.com:443"); !ok || u != "login.microsoftonline.com" {
		t.Fatalf("port-stripped match failed: %q %v", u, ok)
	}
	// Unknown host.
	if _, ok := c.TargetFor("unknown.evilpikin.com"); ok {
		t.Fatal("unknown host should not resolve")
	}
}

func TestSnapshotIsolated(t *testing.T) {
	c := NewRuntimeConfig()
	c.SetBaseDomain("evilpikin.com")
	c.SetTarget("a.evilpikin.com", "x.com")
	_, _, _, m := c.Snapshot()
	m["a.evilpikin.com"] = "mutated" // must not affect the live config
	if v, _ := c.TargetFor("a.evilpikin.com"); v != "x.com" {
		t.Fatalf("snapshot leaked mutation: %q", v)
	}
}
