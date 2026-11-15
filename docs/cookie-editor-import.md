# Operator Runbook — Importing Captured Sessions into Cookie-Editor

EvilPikin exports captured cookies in the **Cookie-Editor / EditThisCookie JSON**
format (evilginx-compatible). This is the array of `{domain, name, value, path,
secure, httpOnly, sameSite, expirationDate}` objects those browser extensions
import directly. Two export scopes exist:

| Scope | Endpoint | Use |
|---|---|---|
| Single session | `GET /api/sessions/{id}/export.json` | one victim's full bag |
| Whole target | `GET /api/targets/{id}/export.json` | union of every cookie across all sessions of a target (per-target dashboard harvest) |

The dashboard also exposes buttons for both: **JSON** on each session row, and
**Export Target JSON** in the target dropdown bar.

## 1. Fetch the JSON

From the dashboard (recommended):
1. Open the dashboard at `http://<CONTROL_HOST:PORT>/` (default `127.0.0.1:8080`).
2. Pick a target (or "All targets") so the live stream is scoped via `?target=`.
3. Click **JSON** on a session row, or **Export Target JSON** for the whole target.

From the command line:

```bash
# single session
curl -s "http://127.0.0.1:8080/api/sessions/<SESSION_ID>/export.json" -o session.json

# entire target harvest
curl -s "http://127.0.0.1:8080/api/targets/<TARGET_ID>/export.json" -o target.json
```

## 2. Import into Cookie-Editor (Chrome / Firefox)

1. Install the **Cookie-Editor** extension.
2. Navigate to the site you want to replay the session against (e.g. the real
   `https://login.microsoftonline.com`).
3. Click the Cookie-Editor icon → **Export** icon (down-arrow) → **Import JSON**.
4. Paste the contents of `session.json` / `target.json` and click **Import**.
5. Reload the page — you should now be authenticated as the victim.

> **EditThisCookie** users: same flow — open the extension, click the
> import (brace `{ }`) button, paste the JSON, save.

## 3. CRITICAL — domain scope when replaying against the REAL provider

During capture the proxy rewrites every `Set-Cookie` `Domain` to the phishing
**site domain** (e.g. `.ms.test`) so the session survives the multi-host auth
chain. The exported JSON therefore carries `domain: ".ms.test"`.

- **Lab replay** (browser pointed at the phishing site): import as-is — the
  domains already match.
- **Real-provider replay** (impersonate the victim on the genuine site): the
  `.ms.test` domain will NOT match `microsoft.com`, so the cookies are ignored.
  Rewrite the domain back to the real parent origin before importing:

  ```bash
  # Microsoft consumer/enterprise realm examples
  sed -i '' 's/\.ms\.test/.microsoft.com/g' session.json
  # or, generically, swap the phishing base for the real apex:
  # sed -i '' 's/<SITE_DOMAIN>/<REAL_APEX>/g' session.json
  ```

  After rewriting, re-import. `httpOnly`/`secure` flags are preserved, so the
  session is fully replayable in the operator browser.

## 4. Notes

- The **whole-target** export de-duplicates by name but may contain cookies from
  multiple victims; prefer the single-session export for clean impersonation.
- `expirationDate` is set from the cookie's `Expires`/`Max-Age`; session cookies
  (no expiry) omit it and stay valid only while the browser is open.
- `sameSite` is normalized to the Cookie-Editor vocabulary
  (`no_restriction` / `lax` / `strict`).
