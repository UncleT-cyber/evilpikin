package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/user/evilpikin/internal/core"
	"github.com/user/evilpikin/internal/log"
)

type CertResolver interface {
	Resolve(chi *tls.ClientHelloInfo) (*tls.Certificate, error)
}

type peekedConn struct {
	net.Conn
	buf []byte
	pos int
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if c.pos < len(c.buf) {
		n := copy(p, c.buf[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(p)
}

func readClientHello(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 0x16 {
		return nil, fmt.Errorf("not a tls handshake record")
	}
	recLen := int(header[3])<<8 | int(header[4])
	if recLen <= 0 {
		return nil, fmt.Errorf("invalid record length")
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func parseSNIFromClientHello(record []byte) (string, error) {
	if len(record) < 5 {
		return "", fmt.Errorf("record too short")
	}
	if record[0] != 0x16 {
		return "", fmt.Errorf("not a handshake record")
	}
	body := record[5:]
	if len(body) < 4 {
		return "", fmt.Errorf("handshake too short")
	}
	if body[0] != 0x01 {
		return "", fmt.Errorf("not a client hello")
	}
	ch := body[4:]
	if len(ch) < 2+32+1 {
		return "", fmt.Errorf("client hello too short")
	}
	pos := 2 + 32
	if pos >= len(ch) {
		return "", fmt.Errorf("truncated after random")
	}
	sidLen := int(ch[pos])
	pos += 1 + sidLen
	if pos+2 > len(ch) {
		return "", fmt.Errorf("bad cipher suite length")
	}
	csLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2 + csLen
	if pos+1 > len(ch) {
		return "", fmt.Errorf("bad compression length")
	}
	compLen := int(ch[pos])
	pos += 1 + compLen
	if pos+2 > len(ch) {
		return "", fmt.Errorf("bad extensions length")
	}
	extTotal := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	limit := pos + extTotal
	if limit > len(ch) {
		limit = len(ch)
	}
	for pos+4 <= limit {
		extType := int(ch[pos])<<8 | int(ch[pos+1])
		extLen := int(ch[pos+2])<<8 | int(ch[pos+3])
		pos += 4
		if pos+extLen > limit {
			break
		}
		if extType == 0x00 {
			if extLen < 2 {
				return "", fmt.Errorf("bad server name extension")
			}
			listLen := int(ch[pos])<<8 | int(ch[pos+1])
			p := pos + 2
			end := pos + extLen
			if p+listLen > end {
				return "", fmt.Errorf("bad server name list")
			}
			for p+3 <= pos+2+listLen {
				nameType := ch[p]
				nameLen := int(ch[p+1])<<8 | int(ch[p+2])
				p += 3
				if nameType == 0x00 {
					if p+nameLen > end {
						return "", fmt.Errorf("bad host name")
					}
					return string(ch[p : p+nameLen]), nil
				}
				p += nameLen
			}
		}
		pos += extLen
	}
	return "", fmt.Errorf("no sni found")
}

func normalizeSNI(sni string) string {
	return strings.ToLower(strings.TrimSpace(sni))
}

type Router struct {
	store    *core.SessionStore
	resolver CertResolver
	tlsCfg   *tls.Config
	handler  func(sni string, conn *tls.Conn)
	mu       sync.Mutex
}

func NewRouter(store *core.SessionStore, resolver CertResolver) *Router {
	r := &Router{
		store:    store,
		resolver: resolver,
	}
	r.tlsCfg = &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return r.resolver.Resolve(chi)
		},
		MinVersion: tls.VersionTLS12,
	}
	return r
}

func (r *Router) SetHandler(h func(sni string, conn *tls.Conn)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handler = h
}

func (r *Router) HandleIncoming(conn net.Conn) {
	raw, err := readClientHello(conn)
	if err != nil {
		log.Debug("router: read client hello: %v", err)
		conn.Close()
		return
	}
	sni, err := parseSNIFromClientHello(raw)
	if err != nil {
		log.Debug("router: parse sni: %v", err)
		conn.Close()
		return
	}
	sni = normalizeSNI(sni)

	r.store.Mutate(sni, func(s *core.TargetSession) {
		s.Touch()
	})
	if _, ok := r.store.Get(sni); !ok {
		r.store.Register(core.NewTargetSession(sni, conn.RemoteAddr().String(), sni, "", ""))
		log.Info("router: new target session for sni=%s", sni)
	}

	pc := &peekedConn{Conn: conn, buf: raw}
	tlsConn := tls.Server(pc, r.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Debug("router: handshake sni=%s: %v", sni, err)
		tlsConn.Close()
		return
	}

	r.mu.Lock()
	h := r.handler
	r.mu.Unlock()
	if h != nil {
		h(sni, tlsConn)
	} else {
		tlsConn.Close()
	}
}

type MemoryCertResolver struct {
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func NewMemoryCertResolver() *MemoryCertResolver {
	return &MemoryCertResolver{
		cache: make(map[string]*tls.Certificate),
	}
}

func (m *MemoryCertResolver) Resolve(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := normalizeSNI(chi.ServerName)
	if sni == "" {
		return nil, fmt.Errorf("empty sni")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.cache[sni]; ok {
		return c, nil
	}
	c, err := generateSelfSigned(sni)
	if err != nil {
		return nil, err
	}
	m.cache[sni] = c
	return c, nil
}

func generateSelfSigned(sni string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
