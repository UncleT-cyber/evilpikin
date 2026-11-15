// Package dns automates Cloudflare DNS so Evil Pikin needs zero manual registrar
// or /etc/hosts work. It punches root and wildcard A records pointing at the VPS
// with a 60-second TTL, so any subdomain the operator spins up routes to the proxy
// immediately.
//
// It uses Cloudflare's REST API v4 via net/http (no third-party SDK dependency)
// and hides the transport behind an interface so the logic is fully testable
// against a mock server.
package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultAPIBase = "https://api.cloudflare.com/client/v4"

// HTTPClient is the minimal transport surface we depend on. http.Client and
// httptest servers both satisfy it, so tests never touch the network.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DNSManager drives Cloudflare record synchronization for one domain.
type DNSManager struct {
	Token    string
	Domain   string
	TargetIP string

	// Client is the HTTP transport. Defaults to a 15s-timeout http.Client.
	Client HTTPClient
	// APIBase overrides the Cloudflare endpoint (used in tests).
	APIBase string
}

// NewDNSManager builds a manager for the given token, domain, and VPS IP.
func NewDNSManager(token, domain, targetIP string) *DNSManager {
	return &DNSManager{
		Token:    token,
		Domain:   domain,
		TargetIP: targetIP,
		Client:   &http.Client{Timeout: 15 * time.Second},
		APIBase:  defaultAPIBase,
	}
}

func (m *DNSManager) client() HTTPClient {
	if m.Client != nil {
		return m.Client
	}
	return http.DefaultClient
}

func (m *DNSManager) base() string {
	if m.APIBase != "" {
		return strings.TrimRight(m.APIBase, "/")
	}
	return defaultAPIBase
}

// cfEnvelope is the standard Cloudflare success/error wrapper.
type cfEnvelope struct {
	Success  bool            `json:"success"`
	Errors   []cfError       `json:"errors"`
	Messages []string        `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// doJSON performs an authenticated request and decodes the envelope. On a
// non-2xx status or a Cloudflare "success:false" it returns a descriptive error
// suitable for surfacing in the TUI.
func (m *DNSManager) doJSON(method, path string, body interface{}, out *cfEnvelope) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, m.base()+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("cloudflare returned non-JSON (%d): %s", resp.StatusCode, string(raw))
	}
	if out != nil {
		*out = env
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare %s %s -> %d: %s", method, path, resp.StatusCode, string(raw))
	}
	if !env.Success {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d: %s", e.Code, e.Message))
		}
		return fmt.Errorf("cloudflare %s %s rejected: %s", method, path, strings.Join(msgs, "; "))
	}
	return nil
}

// zoneID resolves the Cloudflare Zone ID for the configured domain.
func (m *DNSManager) zoneID() (string, error) {
	var env cfEnvelope
	path := "/zones?name=" + url.QueryEscape(m.Domain)
	if err := m.doJSON("GET", path, nil, &env); err != nil {
		return "", err
	}
	var zones []cfZone
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", fmt.Errorf("decode zone list: %w", err)
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("no Cloudflare zone found for domain %q", m.Domain)
	}
	return zones[0].ID, nil
}

// findRecord returns the existing A record for the given FQDN name, or nil.
func (m *DNSManager) findRecord(zoneID, name string) (*cfRecord, error) {
	var env cfEnvelope
	path := fmt.Sprintf("/zones/%s/dns_records?name=%s&type=A", zoneID, url.QueryEscape(name))
	if err := m.doJSON("GET", path, nil, &env); err != nil {
		return nil, err
	}
	var recs []cfRecord
	if err := json.Unmarshal(env.Result, &recs); err != nil {
		return nil, fmt.Errorf("decode record list: %w", err)
	}
	if len(recs) == 0 {
		return nil, nil
	}
	return &recs[0], nil
}

// upsertRecord creates or updates the A record for name so it points at TargetIP
// with TTL 60 and proxying disabled.
func (m *DNSManager) upsertRecord(zoneID, name string) error {
	existing, err := m.findRecord(zoneID, name)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"type":    "A",
		"name":    name,
		"content": m.TargetIP,
		"ttl":     60,
		"proxied": false,
	}
	if existing == nil {
		var env cfEnvelope
		if err := m.doJSON("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), payload, &env); err != nil {
			return fmt.Errorf("create record %q: %w", name, err)
		}
		return nil
	}
	// Only write if something actually drifted (avoids needless API churn).
	if existing.Content == m.TargetIP && existing.TTL == 60 && !existing.Proxied {
		return nil
	}
	var env cfEnvelope
	if err := m.doJSON("PATCH", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existing.ID), payload, &env); err != nil {
		return fmt.Errorf("update record %q: %w", name, err)
	}
	return nil
}

// SyncRecords ensures the root (@) and wildcard (*) A records point at the VPS
// with a 60s TTL and proxying off. It is safe to call repeatedly; it only writes
// when the live state has drifted.
func (m *DNSManager) SyncRecords() error {
	if m.Token == "" {
		return fmt.Errorf("cloudflare token is empty")
	}
	if m.Domain == "" {
		return fmt.Errorf("domain is empty")
	}
	if m.TargetIP == "" {
		return fmt.Errorf("target IP (VPS public IP) is empty")
	}
	zoneID, err := m.zoneID()
	if err != nil {
		return err
	}
	// Root record is stored with name == FQDN; wildcard with name == "*".
	for _, name := range []string{m.Domain, "*"} {
		if err := m.upsertRecord(zoneID, name); err != nil {
			return err
		}
	}
	return nil
}
