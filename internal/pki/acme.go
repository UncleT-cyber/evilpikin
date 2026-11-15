package pki

import (
	"crypto/tls"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// ACMEResolver is a proxy.CertResolver backed by an embedded ACME client
// (Let's Encrypt). It obtains and renews real, browser-trusted certificates
// entirely in memory/on disk with no external Certbot dependency, so a
// production deployment with a real BaseDomain gets hands-free HTTPS.
//
// It relies on the TLS-ALPN-01 challenge, which is answered during the TLS
// handshake on port 443 — no plaintext HTTP-01 listener is required.
type ACMEResolver struct {
	mgr *autocert.Manager
}

// NewACMEResolver builds an ACME resolver for the given domain names. Certs
// are cached under cacheDir (e.g. "certs") so renewals survive restarts.
func NewACMEResolver(domains []string, cacheDir string) *ACMEResolver {
	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache(cacheDir),
	}
	return &ACMEResolver{mgr: mgr}
}

// Resolve implements proxy.CertResolver.
func (a *ACMEResolver) Resolve(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return a.mgr.GetCertificate(chi)
}

// HTTPHandler wraps an HTTP handler so ACME HTTP-01 challenges can be served
// on the plaintext listener if a deployment cannot use TLS-ALPN-01. Pass the
// app's redirect handler as `next`.
func (a *ACMEResolver) HTTPHandler(next http.Handler) http.Handler {
	return a.mgr.HTTPHandler(next)
}
