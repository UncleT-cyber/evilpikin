package firewall

import (
	"net"
	"testing"
)

type fakeASN struct {
	m map[string]string
}

func (f *fakeASN) ASN(ip net.IP) (string, error) {
	return f.m[ip.String()], nil
}

func TestGeoFenceDenyCIDR(t *testing.T) {
	g := NewGeoFence()
	g.LoadConfig(GeoFenceConfig{DenyCIDRs: []string{"192.0.2.0/24"}})
	if ok, _ := g.Check("192.0.2.5"); ok {
		t.Fatal("expected 192.0.2.5 blocked")
	}
	if ok, _ := g.Check("8.8.8.8"); !ok {
		t.Fatal("expected 8.8.8.8 allowed")
	}
}

func TestGeoFenceAllowMode(t *testing.T) {
	g := NewGeoFence()
	g.LoadConfig(GeoFenceConfig{Mode: "allow", AllowCIDRs: []string{"10.0.0.0/8"}})
	if ok, _ := g.Check("10.1.2.3"); !ok {
		t.Fatal("expected 10.1.2.3 allowed")
	}
	if ok, _ := g.Check("8.8.8.8"); ok {
		t.Fatal("expected 8.8.8.8 blocked in allow mode")
	}
}

func TestGeoFenceDenyASN(t *testing.T) {
	g := NewGeoFence()
	g.SetASNResolver(&fakeASN{m: map[string]string{"203.0.113.5": "AS13335"}})
	g.LoadConfig(GeoFenceConfig{DenyASNs: []string{"AS13335"}})
	if ok, _ := g.Check("203.0.113.5"); ok {
		t.Fatal("expected ASN AS13335 blocked")
	}
	if ok, _ := g.Check("198.51.100.5"); !ok {
		t.Fatal("expected non-denied ASN allowed")
	}
}
