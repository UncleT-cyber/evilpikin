package console

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/user/evilpikin/internal/log"
)

// IPVersion returns "IPv4" or "IPv6" for a parsed IP, or "" if nil.
func IPVersion(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

// PublicIP discovers the server's outward-facing IPv4 address (string form).
// It is retained for callers that only need the textual address; new code
// should prefer DetectPublicIP, which is version-aware and dual-stack safe.
func PublicIP() (string, error) {
	ip, _, err := DetectPublicIP()
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// DetectPublicIP returns the server's public IP using dual-stack-aware
// detection. IPv4 is the industry-standard primary: the first probe hits the
// plain ipify endpoint, which returns a 32-bit IPv4 string by default. Only if
// that fails (e.g. an IPv6-only host with no IPv4 egress) do we fall back to
// the IPv6 endpoint. This matches the operational reality that VPS deployments
// ship a dedicated public IPv4 out of the box, while IPv6 may be unconfigured.
func DetectPublicIP() (net.IP, string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	// Primary: IPv4. ipify returns v4 unless forced to a v6 endpoint.
	probes := []string{"https://api.ipify.org", "https://api64.ipify.org"}
	var lastErr error
	for _, u := range probes {
		resp, err := client.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		s := strings.TrimSpace(string(buf[:n]))
		ip := net.ParseIP(s)
		if ip == nil {
			lastErr = fmt.Errorf("echo service returned unparsable address %q", s)
			continue
		}
		return ip, IPVersion(ip), nil
	}
	return nil, "", fmt.Errorf("could not auto-detect public IP: %v", lastErr)
}

// VerifyDomainPointsToServer confirms the domain resolves to this server's
// public IP before we bind it. net.LookupIP performs the A-record lookup; a
// mismatch produces the exact error the operator expects. If the public IP
// cannot be determined (e.g. offline lab), verification is skipped with a
// warning rather than blocking configuration.
func VerifyDomainPointsToServer(domain string) error {
	if net.ParseIP(domain) != nil {
		return fmt.Errorf("use a real domain name, not an IP address (browsers reject bare IPs for HTTPS cookie/auth flows)")
	}
	ips, err := net.LookupIP(domain)
	if err != nil {
		// The name does not resolve. In dev/lab the operator maps it locally
		// via /etc/hosts, so we accept it here; the strict "points to this
		// server" check only fires when the name actually resolves elsewhere.
		log.Info("domain %q does not resolve; accepting for dev/lab (map it in /etc/hosts). Use --no-check to suppress entirely.", domain)
		return nil
	}
	pub, err := PublicIP()
	if err != nil || pub == "" {
		log.Info("could not determine server public IP; skipping strict DNS verification")
		return nil
	}
	for _, ip := range ips {
		if ip.String() == pub {
			return nil
		}
	}
	return fmt.Errorf("Error: Domain is not pointing to this server's IP yet. (resolved %v, server %s)", ips, pub)
}
