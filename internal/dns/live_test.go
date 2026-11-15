package dns

import (
	"net"
	"testing"
	"time"
)

// TestDynamicResolutionLive proves the DNS server answers A queries for ANY
// *.ms.test host (including multi-label dynamically-derived aliases like
// passwordreset.microsoftonline.com.ms.test) with 127.0.0.1 — and that it does
// NOT need any pre-listed host. This is the "everything resolves on its own"
// guarantee the operator relies on (no /etc/hosts entries).
func TestDynamicResolutionLive(t *testing.T) {
	s := NewServer("ms.test", "127.0.0.1:5533")
	s.Start()
	defer func() { _ = s }()

	hosts := []string{
		"login.ms.test",
		"aadcdn.ms.test",
		"aadcdn-auth.ms.test",
		"passwordreset.microsoftonline.com.ms.test",
		"go.microsoft.com.ms.test",
		"eu-mobile.events.data.microsoft.com.ms.test",
	}
	for _, h := range hosts {
		got, err := queryA("127.0.0.1:5533", h)
		if err != nil {
			t.Fatalf("query %s: %v", h, err)
		}
		if got != "127.0.0.1" {
			t.Fatalf("host %s resolved to %q, want 127.0.0.1", h, got)
		}
	}
}

func queryA(server, name string) (string, error) {
	req := buildAQuery(name)
	pc, err := net.Dial("udp", server)
	if err != nil {
		return "", err
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := pc.Write(req); err != nil {
		return "", err
	}
	buf := make([]byte, 512)
	n, err := pc.Read(buf)
	if err != nil {
		return "", err
	}
	// Last 4 bytes of a single A answer are the IPv4 (127.0.0.1).
	if n < 4 {
		return "", err
	}
	ip := buf[n-4 : n]
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]).String(), nil
}

func buildAQuery(name string) []byte {
	var q []byte
	q = append(q, 0x12, 0x34) // id
	q = append(q, 0x01, 0x00) // flags: RD
	q = append(q, 0x00, 0x01) // qdcount
	q = append(q, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range splitLabels(name) {
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0x00) // root
	q = append(q, 0x00, 0x01) // qtype A
	q = append(q, 0x00, 0x01) // qclass IN
	return q
}

func splitLabels(name string) []string {
	var out []string
	cur := ""
	for _, c := range name {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
