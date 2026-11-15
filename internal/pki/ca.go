// Package pki implements the "install once" development certificate
// authority used by the Evil Pikin data plane.
//
// In dev mode we do not control authoritative DNS, so operators point the
// phishing hostnames at the engine IP via /etc/hosts and install a single
// root CA (certs/dev-ca.pem) into the browser / OS trust store. The engine
// then mints a per-SNI leaf certificate signed by that CA for every proxied
// host, so browsers trust the TLS connection without per-host warnings.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// CA is a loaded (or freshly generated) root certificate authority.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// LoadOrGenerate returns the CA stored at certPath/keyPath, or generates a
// new one and persists it when the files are absent. The generated cert is
// valid for ~10 years so it only needs to be installed once per lab.
func LoadOrGenerate(certPath, keyPath string) (*CA, error) {
	if certPEM, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			return parseCA(certPEM, keyPEM)
		}
	}
	ca, err := generateCA()
	if err != nil {
		return nil, err
	}
	if err := ca.persist(certPath, keyPath); err != nil {
		return nil, err
	}
	return ca, nil
}

func generateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Evil Pikin Dev CA", Organization: []string{"Arkspan Labs"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key}, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("pki: invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("pki: invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key}, nil
}

func (c *CA) persist(certPath, keyPath string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
	keyPEM, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyOut, 0600)
}

// CertPEM returns the root CA certificate in PEM form so the operator can
// install it into the browser / OS trust store.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// Sign mints a leaf certificate for sni, chained to (signed by) this CA.
func (c *CA) Sign(sni string) (*tls.Certificate, error) {
	sni = normalizeHost(sni)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{leaf.Raw, c.cert.Raw},
		PrivateKey:  key,
	}, nil
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

// Resolver is a proxy.CertResolver that lazily signs and caches a leaf
// certificate per SNI using the dev CA.
type Resolver struct {
	ca    *CA
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func NewResolver(ca *CA) *Resolver {
	return &Resolver{ca: ca, cache: make(map[string]*tls.Certificate)}
}

func (r *Resolver) Resolve(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := normalizeHost(chi.ServerName)
	if sni == "" {
		return nil, fmt.Errorf("pki: empty sni")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.cache[sni]; ok {
		return c, nil
	}
	c, err := r.ca.Sign(sni)
	if err != nil {
		return nil, err
	}
	r.cache[sni] = c
	return c, nil
}
