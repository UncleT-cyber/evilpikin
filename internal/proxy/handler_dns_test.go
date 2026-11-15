package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestResolveAllNoHangOnFailure(t *testing.T) {
	old := upstreamResolver
	oldSys := net.DefaultResolver
	oldPub := publicResolvers
	defer func() { upstreamResolver = old; net.DefaultResolver = oldSys; publicResolvers = oldPub }()

	// Simulate ALL resolvers dead (out-of-band + public fallbacks + system).
	// resolveAll must return (not hang) within its 8s cap and report an error.
	dead := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return nil, errors.New("dead resolver")
		},
	}
	upstreamResolver = dead
	publicResolvers = []*net.Resolver{dead}
	net.DefaultResolver = dead

	start := time.Now()
	_, err := resolveAll(context.Background(), "login.microsoftonline.com")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error when all resolvers fail")
	}
	if elapsed > 12*time.Second {
		t.Fatalf("resolveAll hung for %v (expected <= ~8s cap)", elapsed)
	}
}

// fakeResolverA starts a UDP DNS server that answers EVERY A query with ip, and
// returns a *net.Resolver pointed at it. Used to simulate a resolver that
// returns a specific (possibly dead) IP.
func fakeResolverA(t *testing.T, ip net.IP) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, ra, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := buildFakeA(buf[:n], ip); resp != nil {
				pc.WriteTo(resp, ra)
			}
		}
	}()
	addr := pc.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func buildFakeA(req []byte, ip net.IP) []byte {
	if len(req) < 12 {
		return nil
	}
	off := 12
	for off < len(req) {
		llen := int(req[off])
		if llen == 0 {
			off++
			break
		}
		if llen&0xC0 == 0xC0 {
			off += 2
			break
		}
		off += llen + 1
	}
	if off+4 > len(req) {
		return nil
	}
	header := make([]byte, 12)
	copy(header, req[:2])
	header[2] = 0x85 // QR=1 AA=1 RD=1
	header[3] = 0x80 // RA=1 RCODE=0
	header[4] = 0
	header[5] = 1 // QDCOUNT=1
	header[6] = 0
	header[7] = 1 // ANCOUNT=1
	out := append(header, req[12:off+4]...)
	v4 := ip.To4()
	out = append(out, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04)
	out = append(out, v4...)
	return out
}

func deadResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return nil, errors.New("dead resolver")
		},
	}
}

// TestResolveAllMergesExternalIgnoresSystem proves the blackhole fix: when the
// out-of-band resolvers return usable IPs, they are MERGED (not just the first)
// and the system resolver's (dead/blackhole) IP is NOT consulted. Previously the
// fast local system resolver won the race with its dead IP and sank the request.
func TestResolveAllMergesExternalIgnoresSystem(t *testing.T) {
	oldUp, oldPub, oldSys := upstreamResolver, publicResolvers, net.DefaultResolver
	defer func() { upstreamResolver, publicResolvers, net.DefaultResolver = oldUp, oldPub, oldSys }()

	dnsCache = sync.Map{}
	upstreamResolver = fakeResolverA(t, net.ParseIP("198.51.100.1"))
	publicResolvers = []*net.Resolver{fakeResolverA(t, net.ParseIP("198.51.100.2"))}
	net.DefaultResolver = fakeResolverA(t, net.ParseIP("198.51.100.3")) // would-be blackhole

	ips, err := resolveAll(context.Background(), "aadcdn.msftauth.net")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, ip := range ips {
		got[ip.IP.String()] = true
	}
	if !got["198.51.100.1"] || !got["198.51.100.2"] {
		t.Fatalf("expected out-of-band IPs merged, got %v", ips)
	}
	if got["198.51.100.3"] {
		t.Fatalf("system resolver must be ignored when out-of-band succeeds, got %v", ips)
	}
}

// TestResolveAllFallsBackToSystem proves that when every out-of-band resolver
// fails, the system resolver is still used (and we don't hang the full 8s).
func TestResolveAllFallsBackToSystem(t *testing.T) {
	oldUp, oldPub, oldSys := upstreamResolver, publicResolvers, net.DefaultResolver
	defer func() { upstreamResolver, publicResolvers, net.DefaultResolver = oldUp, oldPub, oldSys }()

	dnsCache = sync.Map{}
	upstreamResolver = deadResolver()
	publicResolvers = []*net.Resolver{deadResolver()}
	net.DefaultResolver = fakeResolverA(t, net.ParseIP("198.51.100.9"))

	ips, err := resolveAll(context.Background(), "aadcdn.msftauth.net")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].IP.String() != "198.51.100.9" {
		t.Fatalf("expected system fallback IP, got %v", ips)
	}
}
