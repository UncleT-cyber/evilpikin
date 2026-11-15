package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestWildcardResolve(t *testing.T) {
	addr := "127.0.0.1:15353"
	s := NewServer("ms.test", addr)
	go s.Start()
	time.Sleep(200 * time.Millisecond)

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return net.Dial("udp", addr)
		},
	}

	cases := []string{
		"aadcdn.msftauth.net.ms.test",
		"login.microsoftonline.com.ms.test",
		"go.microsoft.com.ms.test",
		"ms.test",
	}
	for _, name := range cases {
		ips, err := r.LookupIPAddr(context.Background(), name)
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		found := false
		for _, ip := range ips {
			if ip.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("resolve %s: expected 127.0.0.1, got %v", name, ips)
		}
	}

	// Unrelated domain must NOT resolve to 127.0.0.1.
	ips, err := r.LookupIPAddr(context.Background(), "example.com")
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				t.Fatalf("example.com wrongly resolved to 127.0.0.1")
			}
		}
	}
}
