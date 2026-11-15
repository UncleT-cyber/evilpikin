# evilpikin

> **evilpikin** is an open AyTM (Adversary-in-the-Middle) phishing framework written in Go — an independently-developed reverse-proxy phishlet engine for **authorized** red-team engagements, adversary simulation, and security research. It is *not* a hosted service, not turnkey malware, and not a bypass kit for third-party production systems it does not run. It is an engineering artifact for understanding how identity attacks work so they can be detected and defended.

**Status:** experimental / active development. **Not production-ready.** See [Known limitations](#known-limitations).

---

## What it is

- A self-contained reverse proxy that clones a real identity-provider sign-in flow (Microsoft 365 / Entra ID; Google) onto a controlled domain and relays the interaction, capturing credentials, OTPs, and session cookies for evidence and post-compromise analysis.
- A lab-oriented control plane: TUI cockpit, web dashboard, REST API, per-target dashboards, live WebSocket telemetry, session export in evilginx-compatible (Cookie-Editor) JSON format.
- An anti-analysis research toolbase: per-host dev-CA leaf cert issuance, wildcard DNS stub, redirect/cookie rewriting, JS-cookie shim injection, CDN aliasing, transparent-intercept routing.
- A codebase you own and audit end-to-end — no runtime dependency on, or telemetry to, any external project (unlike wrappers that shell out to evilginx).

## Threat model & authorized use

**Use evilpikin only inside an explicitly authorized scope** — a written engagement letter, a consented internal red team, or a local lab. Prohibited and unsupported: use against accounts, domains, or services you do not own or have no authorization to test; credential harvesting of real people; bypassing anti-abuse systems of third-party production services.

This repository documents an attack. Reading it to build **defenses** — detection engineering, phishing-resistant MFA, conditional-access policy, training content — is the intended consumer.

## Features

- **Reverse-proxy phishlets** driven by per-target JSON profiles (`configs/targets/`): routing matrix, cookie tracking, JS injections, Evilpuppet (headless challenge solver) for bot-gated flows.
- **Per-session capture**: username, password, OTP, flow type, telemetry log, remote address — SQLite-persisted, encrypted at rest for control-plane credentials.
- **Session export**: Cookie-Editor / `EditThisCookie` JSON for import into the tester's own browser; Netscape cookie-jar export as well.
- **Multi-target runtime**: one instance can serve Microsoft and Google phishlets concurrently with isolated state.
- **Lures**: tracking paths (`/login`, `/accounts`, …) with per-lure tokens, optional `require_lure` enforcement and scanner shield.
- **Telemetry**: server-sent/websocket event stream (session start/end, capture, page load, lure hit) + dashboard.
- **DNS & PKI**: loopback wildcard DNS stub; on-demand per-SNI leaf certs from a local dev CA for any proxied hostname; optional Cloudflare sync and/or `/etc/resolver` entries for transparent intercept on a test machine.
- **Hardening knobs**: strict-loopback default (refuses non-loopback binds without `-public`), scanner CIDR shielding, encrypted control-plane credentials, sandbox isolation under `.sandbox/`.

## Architecture

```
                    ┌────────────────────────────────────────────┐
                    │              evilpikin (Go)                 │
                    │                                             │
  victim ──TLS──▶   │  :443  data plane (reverse proxy)           │
  browser           │     ├─ routing_matrix (host→host rewrite)   │
                    │     ├─ transformer (HTML/JS rewrite)         │
                    │     ├─ CookieJar (credentials, cookies)      │
                    │     └─ injector (JS cookie shim, __ep_sid)  │
                    │  :8080  REST control API (/api/v1/*, /ws)    │
                    │  :9443  loopback dev data plane              │
                    │  :5333  wildcard DNS stub (*.ms.test etc.)   │
                    │  :9080  loopback dev HTTP plane              │
                    │  TUI cockpit (BubbleTea) / web dashboard    │
                    │  SQLite state (.sandbox/evilpikin.db)        │
                    └────────────────────────────────────────────┘
```

- `cmd/evilpikin/` — unified binary: engine + control shell/TUI + DNS (loopback-default, `-public` required to bind non-loopback).
- `cmd/engine/` — headless engine binary (used for `-public` deployments on a test host).
- `internal/proxy/` — reverse proxy, route table, response transformer, cookie jar, capture, 2FA relay.
- `internal/storage/` — SQLite models + persistence (targets, lures, captured sessions).
- `internal/dns/` — loopback wildcard resolver (answers phish subtree + intercept suffixes).
- `internal/control/` — REST API + telemetry websocket; serves `web/` dashboard.
- `internal/console/` — interactive shell / TUI cockpit, target & lure management commands.
- `internal/pki/` — local dev CA + per-SNI leaf issuance.
- `configs/targets/` — phishlet profiles (Microsoft 365, Google) + disabled examples.
- `web/`, `docs/` — dashboard and setup notes.

## Build

```sh
go build -o evilpikin ./cmd/evilpikin
```

Requires Go 1.26+. No cgo dependencies. Tests: `go test ./...`

## Screenshots

**Monitoring console** — live telemetry feed, captured sessions list, per-session JSON/Netscape export, per-target bulk export. Victim identifiers are redacted in this image.

![EvilPikin monitoring console](docs/screenshots/dashboard.png)

## Quick start (local lab, Microsoft 365)
1. Edit/confirm `configs/targets/microsoft.json` (routing matrix, cookie tracking).
2. Start the instance: `./evilpikin --no-tui` (loopback defaults; TUI if omitted).
3. Point the test browser at the phish host (`login.ms.test` or a configured proxy host) — the dev CA under `.sandbox/certs/` must be trusted for that browser profile.
4. Create an engagement-authorized lure in the TUI (`lure add`), open its tracking URL, and observe captures in the dashboard / `GET /api/v1/sessions`.

See `docs/microsoft-setup.md` and `docs/google-setup.md` for target-specific notes and `docs/cookie-editor-import.md` for session replay.

## Known limitations

- **Google target (`google-transparent`/`google`) is not end-to-end reliable.** Google's production sign-in applies anti-automation (Botguard v3) on top of content-security checks; whether the flow completes depends on the *browser environment* of the visiting client, not on the proxy. This is a Google-side enforcement, not a bug you can patch over in a target profile, and it is accurately measured in upstream docs as a known limit. Treat Google coverage as experimental.
- **Microsoft 365 flow is transmit-verifiable** (login page renders same-origin through the proxy) — see `docs/microsoft-setup.md` for the exact check state; verify against your own authorized lab before relying on it.
- **No production hardening.** TLS cert verification is relaxed in places for lab ergonomics; credential storage is obfuscation-grade, not HSM-grade; no multi-tenant isolation story; no rate limiting; no SLA.
- **The tool does not speak to any third-party control plane** — it is self-contained. That is deliberate, but it means no "works out of the box" guarantees against live services.

## Operational safety notes

- Development default is **strict loopback**; `-public` is required before binding non-loopback addresses. Do that only on isolated lab hosts.
- `.sandbox/` (DB, dev CA, SSH keys, captured sessions) is gitignored — **never** commit it, and never commit a DB containing captured credentials.
- Captured sessions are real credential material. Handle them as secret evidence: encrypted storage, named retention, prompt destruction after the engagement, legal review where applicable.
- Anti-Virus/EDR will flag this binary; that is expected for this class of tooling. Keep it on isolated machines.

## License

License is intentionally not asserted yet — do not redistribute or relicense until the author adds one. All rights reserved in the interim.

## Disclaimer

This software is provided for authorized security testing and defensive research only. The author and contributors accept no liability for misuse. If you do not have explicit authorization to test the systems you target with it, do not use it.
