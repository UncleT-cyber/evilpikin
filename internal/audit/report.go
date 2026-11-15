// Package audit produces a defensive mitigation summary from intercepted
// sessions. It is intentionally pure-Go and rule-based: no external AI is
// required, so it runs offline and deterministically. The goal is to turn
// captured session artifacts into actionable hardening guidance for the target
// organization (e.g. "enforce FIDO2/WebAuthn, enable number-matching").
package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/user/evilpikin/internal/storage"
)

// tokenIntel maps a captured cookie/token name to what it implies about the
// victim's auth posture. This is the knowledge base the report reasons over.
var tokenIntel = map[string]struct {
	label  string
	phish  bool // true => stealable via AiTM session replay
	resist bool // true => phishing-resistant (FIDO2/WebAuthn-derived)
}{
	"estsauth":            {label: "Entra session ticket", phish: true},
	"estsauthpersistent":  {label: "Entra persistent session ticket", phish: true},
	"oisecureauth":        {label: "Office persistent auth cookie", phish: true},
	"signinsessioncookie": {label: "Entra sign-in session", phish: true},
	"apsidalgo":           {label: "Entra device/proof-of-possession", phish: false, resist: true},
	"x-ms-refreshtoken":   {label: "OAuth refresh token", phish: true},
}

// Generate renders a defensive report from the supplied captured sessions.
// It returns a ready-to-print summary with per-finding severity and concrete
// mitigations.
func Generate(sessions []*storage.CapturedSession) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== Evil Pikin — Defensive Audit Report ===\n")
	fmt.Fprintf(&b, "sessions analyzed : %d\n", len(sessions))
	if len(sessions) == 0 {
		fmt.Fprintf(&b, "\nNo captured sessions yet. Run a simulation, then re-run `audit report`.\n")
		return b.String()
	}

	// Aggregate signals across all sessions.
	var creds, tokens, fido int
	perTarget := map[string]int{}
	phishTokens := map[string]int{}
	for _, s := range sessions {
		if s.Username != "" && s.Password != "" {
			creds++
		}
		perTarget[s.TargetName] += 1
		for _, cs := range s.Cookies {
			for _, c := range cs {
				if intel, ok := tokenIntel[strings.ToLower(c.Name)]; ok {
					if intel.phish {
						tokens++
						phishTokens[c.Name]++
					}
					if intel.resist {
						fido++
					}
				}
			}
		}
	}

	fmt.Fprintf(&b, "credential captures: %d\n", creds)
	fmt.Fprintf(&b, "stealable tokens   : %d\n", tokens)
	fmt.Fprintf(&b, "phishing-resistant : %d\n", fido)
	b.WriteString("\n-- Findings --\n")

	idx := 1
	if creds > 0 {
		fmt.Fprintf(&b, "[%d] CRITICAL  Credential harvesting succeeded (%d session(s) with username+password).\n", idx, creds)
		fmt.Fprintf(&b, "    Mitigation: enforce phishing-resistant MFA (FIDO2/WebAuthn); remove password-only auth paths.\n")
		idx++
	}
	if tokens > 0 {
		names := make([]string, 0, len(phishTokens))
		for n := range phishTokens {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintf(&b, "[%d] CRITICAL  Session-token theft confirmed via AiTM replay (%d token(s): %s).\n", idx, tokens, strings.Join(names, ", "))
		fmt.Fprintf(&b, "    Mitigation: bind sessions to device posture (compliant device + proof-of-possession); short token TTLs; continuous access evaluation (CAE).\n")
		idx++
	}
	if fido == 0 && (creds > 0 || tokens > 0) {
		fmt.Fprintf(&b, "[%d] HIGH      No phishing-resistant auth observed — legacy push/OTP MFA is bypassable by AiTM.\n", idx)
		fmt.Fprintf(&b, "    Mitigation: deploy number-matching + FIDO2/WebAuthn; treat every session as device-bound.\n")
		idx++
	}
	if fido > 0 {
		fmt.Fprintf(&b, "[%d] INFO      Phishing-resistant signals present; verify they are enforced org-wide, not optional.\n", idx)
		idx++
	}

	b.WriteString("\n-- Affected targets --\n")
	targets := make([]string, 0, len(perTarget))
	for t := range perTarget {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		fmt.Fprintf(&b, "  %-24s %d session(s)\n", t, perTarget[t])
	}

	b.WriteString("\n-- Overall verdict --\n")
	switch {
	case tokens > 0:
		b.WriteString("Tenant is vulnerable to Adversary-in-the-Middle session replay. Prioritize FIDO2/WebAuthn and device-bound sessions.\n")
	case creds > 0:
		b.WriteString("Credentials are exposed. Enforce MFA and phishing-resistant factors immediately.\n")
	default:
		b.WriteString("No high-severity artifacts captured in this sample; continue monitoring.\n")
	}
	return b.String()
}
