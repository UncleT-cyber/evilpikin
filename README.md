<p align="center">
  <img src="docs/screenshots/tui.png" alt="EvilPikin TUI cockpit boot sequence" width="100%">
</p>

<h1 align="center">evilpikin</h1>

<p align="center">
  <b>An independent, educational Adversary-in-the-Middle (AiTM) phishing framework in Go —<br>
  built to teach, demonstrate, and study how identity attacks work, and how to defend against them.</b>
</p>

<p align="center">
  <a><img src="https://img.shields.io/badge/use-authorized%20educational%20labs%20only-red?style=flat-square" alt="Authorized educational labs only"></a>
  <img src="https://img.shields.io/badge/language-Go%201.26-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/module-github.com/UncleT-cyber/evilpikin-gray?style=flat-square" alt="module">
  <img src="https://img.shields.io/badge/status-experimental-yellow?style=flat-square" alt="experimental">
  <img src="https://img.shields.io/badge/license-Educational%20Only-orange.svg" alt="Educational use only; non-commercial">
</p>

---

> ### ⚠️ READ THIS BEFORE ANYTHING ELSE
>
> **evilpikin is for non-commercial educational use only. It is not for sale or commercial use.**
> It exists so students, teachers, and security educators can study identity attacks and defenses in controlled, explicitly authorized settings.
>
> **What this means, concretely:**
> - Use it only for education, such as coursework, academic study, or controlled demonstrations in an authorized lab.
> - Use it **only** against systems and accounts you own or for which you have explicit written authorization.
> - **Never** use it to harvest credentials from real people, conduct unsolicited phishing, take over accounts, or perform any non-consensual activity.
> - Commercial use—including paid training, consulting, commercial security assessments, or incorporating it into a paid product or service—is prohibited without prior written permission from the copyright holder.
> - The authors assume no liability for misuse. If your activity is not educational and authorized, do not use this tool.

---

## Why this exists

Identity breaches often begin when someone trusts a page that looks like their identity provider. Defenders and students need safe ways to understand the attack pattern and the controls that prevent it. evilpikin is intended as an educational tool for controlled, authorized labs—not for real-world credential collection or commercial operations.

It is intended for:

- **Security education** — teaching how identity attacks work and how to recognize and prevent them.
- **Defensive learning** — studying detection, MFA, conditional-access, and token-binding controls in an authorized lab.
- **Academic study** — examining security concepts in coursework or other non-commercial educational settings.

---

## What it does

```
victim browser ──TLS──▶ evilpikin (reverse proxy) ──TLS──▶ identity provider
                              │
              ├─ routing matrix  : host → host rewrite
              ├─ transformer     : HTML/JS/CSS host rewriting
              ├─ CookieJar       : lab-session data and telemetry
              └─ dashboard       : local monitoring and event display
```

- Reverse-proxy profiles for Microsoft 365 / Entra ID and Google.
- Per-host development TLS certificates and a local lab DNS stub.
- Session and event telemetry for controlled exercises.
- A TUI cockpit, web dashboard, and REST/WebSocket control plane.

## What's real, what's not

Current state, measured against the code and reproducible in your own lab:

| Capability | Status |
|---|---|
| Microsoft 365 sign-in flow served through the proxy | ✅ demonstrable in a controlled lab |
| Session-cookie capture & export | ✅ implemented for lab analysis |
| Multi-target concurrent runtime (Microsoft + Google profiles) | ✅ implemented |
| Google sign-in end-to-end flow | ❌ **blocked by Google's Botguard / anti-automation** — see [Findings](docs/google-setup.md) |
| Microsoft full post-auth dashboard access | ⚠️ partially verified; see [microsoft-setup.md](docs/microsoft-setup.md) |
| Production hardening | ❌ not present — lab-grade only |

> Modern anti-fraud systems evaluate the visiting browser and bind sign-in flows to the environment. This project is for studying those defenses in an authorized educational lab, not circumventing them in real-world use.

## Features

- **Routing profiles** — per-target host rewrite tables for controlled experiments.
- **Telemetry** — session events and real-time local monitoring.
- **Strict-loopback by default** — refuses non-loopback binds without `-public`.
- **Sandboxed state** — database, development CA, keys, and captures isolated in `.sandbox/` (gitignored, never committed).
- **No external service dependencies** — self-contained lab runtime.

## Screenshots

| TUI cockpit | Web monitoring console |
|---|---|
| ![evilpikin TUI](docs/screenshots/tui.png) | ![dashboard](docs/screenshots/dashboard.png) |

## Quick start (authorized educational lab only)

Requirements: Go 1.26+, a browser profile that trusts the development CA (`.sandbox/certs/dev-ca.pem`), and an explicitly authorized educational lab scope.

```sh
go build -o evilpikin ./cmd/evilpikin
./evilpikin --no-tui          # loopback-only dev instance
ls -la ~/.sandbox              # isolated state (never commit)
```

Then open the local monitoring console (`http://127.0.0.1:8080/`) and use the software only for a non-commercial educational exercise in an authorized lab. See [docs/microsoft-setup.md](docs/microsoft-setup.md) for setup notes.

## Architecture (short)

- `cmd/evilpikin/` — unified binary: engine + TUI cockpit + DNS stub (loopback-default).
- `internal/proxy/` — reverse proxy, routing, response transformer, CookieJar, capture pipeline.
- `internal/pki/` — development CA + per-SNI leaf issuance (lab only).
- `internal/dns/` — local wildcard DNS answers for lab subdomains.
- `internal/control/` — REST API + WebSocket telemetry; serves the `web/` dashboard.
- `internal/storage/` — SQLite models for lab configuration and sessions.
- `configs/targets/` — JSON profiles for the educational lab.

Full detail in [docs/](docs/).

## Legal & ethical use — non-negotiable

Use is permitted only for non-commercial educational purposes, and only in systems and environments you own or are explicitly authorized to test. Educational intent does not replace authorization. Do not use this software for real credential harvesting, unsolicited phishing, account takeover, or any non-consensual activity. Commercial use is prohibited unless you obtain prior written permission from the copyright holder.

## Further reading

- [docs/microsoft-setup.md](docs/microsoft-setup.md) — Microsoft 365 setup notes
- [docs/google-setup.md](docs/google-setup.md) — Google target findings
- [docs/cookie-editor-import.md](docs/cookie-editor-import.md) — session export notes

## License

This project is **not licensed under the MIT License**. It is available only under the [Educational Use Only License](LICENSE), which permits non-commercial educational use and prohibits commercial use. This is a custom, restrictive license and is not an OSI-approved open-source license. Commercial use requires prior written permission from the copyright holder.

---

<p align="center"><sub>evilpikin — understand the attack, end it.</sub></p>
