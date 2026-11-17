# Remember this device (persistent login) — design

Date: 2026-11-17. Status: approved by the owner 2026-11-17. Target: v1.6.0 (together with the needs-transcription filter; local HTR moves to a later version).

## Why

The owner has to log in (password + TOTP) far too often, worst in the iPhone PWA. Today a login ends after 30 min idle, after 12 h absolute, on every server restart/update (sessions are memory-only), and whenever iOS kills the PWA (the session cookie has no `Max-Age`, so it is a browser-session cookie).

## Goals / non-goals / anti-goals

- **Goal:** opening the app (PWA or browser) on a remembered device goes straight in, with no prompt, also after server restarts, for as long as the device keeps being used.
- **Goal:** the owner can see and revoke remembered devices.
- **Non-goal:** passkeys / Face ID unlock (option 2, rejected for now: bigger build, still a prompt each time).
- **Non-goal:** changing the in-memory session model or its idle/max timeouts. A remembered device simply re-creates an expired session.
- **Anti-goal:** a stolen device cookie must not be able to escalate: mint MCP tokens, approve OAuth apps, change the password, regenerate the recovery key, or extend itself beyond revocation.
- **Anti-goal:** no plaintext UMK or device secret at rest on the server.

## Approaches (owner picked 1)

1. **Remembered-device token (picked).** A long-lived, high-entropy cookie; the server stores the UMK wrapped under a key derived from the cookie secret, exactly like MCP tokens. Survives restarts, no prompt. Trade-off: whoever holds the cookie (e.g. an unlocked stolen phone) gets in until revoked.
2. Passkey (WebAuthn PRF) unlock: no bearer secret on the server, but a Face ID tap each time, larger build, uncertain iOS PWA support.
3. Longer timeouts only (`PM_SESSION_IDLE_MINUTES`/`PM_SESSION_MAX_HOURS`): no code, but doesn't survive restarts or iOS killing the PWA.

## Design

- **Login form:** a "Remember this device" checkbox, **checked by default** *(my call: the owner wants no re-logins; the label makes it visible on a shared computer)*. Also offered after recovery-key login completes the new-password flow.
- **Token:** `pmd_{id: 32 hex}_{secret: 64 hex}`, stored as a row in the existing system-DB `tokens` table with `kind = 'device'`, `umk_wrapped` = UMK wrapped under `secret_kek(secret, INFO_DEVICE)` (a new HKDF info string, distinct from MCP tokens), `expires_at` = now + 90 days. The `kind` column has no CHECK constraint, so **no system-DB migration** is expected; the builder confirms this.
- **Metadata** (label, created, last used) lives in the user's encrypted index DB, like MCP token metadata. Label is derived server-side from the User-Agent (e.g. "iPhone · Safari (app)", "Linux · Firefox"). If this needs a new table, it is **index migration v4** with a test from a real v3 DB (Ruling P); prefer reusing existing token-meta storage if it fits cleanly *(builder's call)*.
- **Cookie:** `__Host-pm_device`, `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=90 days`. Lax (not Strict) so a PWA launch / share-target / link from another app still sends it; CSRF tokens remain mandatory on every state-changing request.
- **Resume:** any request with no valid session but a valid, unexpired device cookie → unwrap the UMK, create a normal in-memory session (same as a fresh login, TOTP not asked), set the session cookie, continue the original request. Invalid/expired/revoked device cookie → clear it, normal login page. Device resumes share the login rate limiter on failures (an invalid device cookie counts like a failed login attempt per IP).
- **Sliding expiry:** on a resume, and at most once a day while in use, extend `expires_at` to now + 90 days and re-send the cookie with a fresh `Max-Age`. No secret rotation *(my call: rotation races with several open tabs/PWA and would cause surprise logouts; sliding expiry + revocation is enough here)*.
- **Revocation:**
  - Logout on a device deletes that device's token and cookie.
  - Settings → "Remembered devices": list (label, created, last used, "this device" marker), Revoke per device, and "Sign out all other devices".
  - **Password change and recovery-key login revoke all device tokens** of the user (unlike static MCP tokens, which keep working).
  - Admin disable/delete of a user removes them (cascade + cache eviction as for tokens).
  - Cap: at most 20 remembered devices per user; creating a 21st evicts the least recently used.
- **No escalation from a device-resumed session:** every sensitive action already asks for the password (MCP token creation, OAuth consent, password change); the builder verifies this and adds a password prompt to recovery-key regeneration and to TOTP disable if they don't have one.
- **Settings/help text and `docs/setup.md`:** explain what remembering does, the risk (anyone with the unlocked device gets in), and how to revoke.

## Tests the builder must include

- Remembered login survives a server restart (new `AppState` against the same data dir).
- Expired / revoked / tampered (wrong secret) device cookie → login page, cookie cleared, rate limiter counts it.
- Password change and recovery login revoke all devices; logout revokes only the current one.
- Sliding expiry extends `expires_at` at most once a day.
- 21st device evicts the LRU one.
- Unchecked "Remember" → no device cookie, behaviour as today.
- Sensitive actions still require the password in a device-resumed session.

## Left to the builder

Exact UA → label mapping, where the resume hook sits in the middleware, metadata storage (existing token meta vs. index migration v4), UI placement within Settings.
