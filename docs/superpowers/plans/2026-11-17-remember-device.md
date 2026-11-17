# Remember This Device Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A login with "Remember this device" sets a long-lived device cookie. Later requests without a live session silently re-create one, also after a server restart, until the device is revoked or unused for 90 days.

**Architecture:** Device tokens reuse the MCP-token pattern. Each one is a `tokens` row in system.db with `kind = 'device'` and the UMK wrapped under an HKDF key of the cookie secret. Its label and last-used time live in a new encrypted index-DB table (index migration v4). `session_layer` resumes a session from the device cookie when there is no live session. Settings lists and revokes devices.

**Tech Stack:** Rust, axum, rusqlite/SQLCipher, Askama, existing `crypto` (`secret_kek`, `wrap_key`, `unwrap_key`) and `keyring::Keyring::unlock`.

**Spec:** `docs/superpowers/specs/2026-11-17-remember-device-design.md` (approved). Read it first.

## Global Constraints

- **Token format.** Device token `pmd_{id: 32 hex}_{secret: 64 hex}`.
  - HKDF info: `INFO_DEVICE = "pm/v1/kek/device"`.
  - AAD: `aad::umk_device(id) = "pm/v1/umk/device/{id}"`.
  - system.db row: `kind = 'device'`, `grant_id = NULL`.
- **Cookie.** `__Host-pm_device=<token>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=7776000` (90 days). The cookie is cleared with `Max-Age=0`.
- **Expiry.** `expires_at = now + 90*24*3600`. Sliding: extend only when the stored `expires_at` is more than 1 day older than `now + 90 days`, so at most once a day.
- **Device cap.** At most 20 devices per user. Creating the 21st revokes the one with the oldest `COALESCE(last_used_at, created_at)`.
- **Schema.** system.db stays v3, because `kind` has no CHECK constraint. The index DB goes to **v4**, a numbered migration with a test from a real v3 DB (Ruling P).
- **Token kinds stay separate.**
  - A `pmd_` string must never authenticate at `/mcp`.
  - A `pm_`/`pma_`/`pmr_` string must never resume a web session.
- **No escalation from a resumed session.** TOTP disable must also require the account password. Token creation, OAuth consent, password change, recovery regeneration and export already do.
- **Test gate.** `PM_TEST_MODELS_DIR=$HOME/.cache/pms-test-models cargo test -j 2 --no-fail-fast -- --test-threads=2`, plus `cargo clippy -j 2 --all-targets -- -D warnings` and `cargo fmt`.
  - Never use full parallelism. Never put a target dir or other build output under `/tmp`, which is RAM-backed.
- **Commits.** Every commit message ends with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01XcTHoWb6TaX6gaRd9rBUPT
  ```

## Review Focus

1. **Parallel requests on resume.** A PWA launch fires several requests at once with only the device cookie. Expected: one session for the device, not one per request. Pinned by `concurrent_resumes_share_one_session`, Task 2.
2. **Stale device cookie after a password change on another device.** Expected: login page, cookie cleared, no 500. Pinned by `password_change_revokes_all_devices`, Task 3.
3. **POST with only a device cookie.** Example: a form left open past the session's idle timeout. Expected: the session resumes, then the normal CSRF check applies; the old form's token no longer matches, so the result is 403, never a bypass. The OS share-target POST (CSRF-exempt path) resumes and works. Pinned by `post_after_idle_resumes_but_needs_fresh_csrf`, Task 2.
4. **Disabled or deleted user with a remembered device.** Expected: resume fails and the cookie is cleared. Pinned by `disabled_user_cannot_resume`, Task 2.
5. **Logout on a remembered device.** Expected: this device's token is revoked and the next visit shows the login page; other devices are unaffected. Pinned by `logout_revokes_only_this_device`, Task 2.

---

### Task 1: Device token storage and core logic

**Files:**
- Create: `src/devices.rs`, registered in `src/lib.rs`
- Modify:
  - `src/crypto/kdf.rs`: add `INFO_DEVICE`
  - `src/crypto/keys.rs`: add `aad::umk_device`
  - `src/system_db.rs`: device token fns
  - `src/user_db/mod.rs`: `MIGRATION_V4`, `device_meta` fns, or a new `src/user_db/devices.rs` following the existing module pattern
- Test: `tests/devices.rs` (new). Add the migration test next to the existing index-DB migration tests (grep for `MIGRATION_V3` in `tests/`).

**Interfaces:**
- Produces in `src/system_db.rs`:
  - `SystemDb::insert_device_token(&self, token_id: &str, user_id: &str, umk_wrapped: &[u8], expires_at: i64) -> anyhow::Result<()>`
  - `SystemDb::set_token_expiry(&self, token_id: &str, expires_at: i64) -> anyhow::Result<()>`
  - `SystemDb::delete_device_tokens(&self, user_id: &str) -> anyhow::Result<Vec<String>>`, which returns the deleted ids
- Produces in the index DB:
  - Migration v4: `CREATE TABLE device_meta (id TEXT PRIMARY KEY, label TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER); PRAGMA user_version = 4;`
  - `DeviceMeta { id: String, label: String, created_at: i64, last_used_at: Option<i64> }`
  - `insert_device_meta(c, &DeviceMeta)`, `list_device_meta(c) -> Vec<DeviceMeta>`, ordered by last use, newest first
  - `touch_device_meta(c, id, now)`, `delete_device_meta(c, id)`, `delete_all_device_meta(c)`
  - `prune_device_meta(c, live_ids: &[String])`
- Produces in `src/devices.rs`:
  - `pub const DEVICE_TTL_SECS: i64 = 90 * 24 * 3600;`
  - `pub const MAX_DEVICES: usize = 20;`
  - `pub fn create_device(sys: &SystemDb, u: &Unlocked, label: &str, now: i64) -> anyhow::Result<String>`
    - Returns the full `pmd_…` token.
    - Evicts the least recently used device when the cap is exceeded.
    - Rolls back the system row if the meta insert fails, like `tokens::create_token`.
  - `pub struct Resumed { pub user: UserRow, pub unlocked: Arc<Unlocked>, pub device_id: String }`
  - `pub fn resume_device(state: &AppState, token: &str, now: i64) -> Result<Resumed, ResumeFail>`
    - Parses `pmd_`, requires `row.kind == "device"` and an unexpired row with a matching secret, and a user that exists and is not disabled.
    - Unlocks via `state.keyring.unlock` the same way `tokens::authenticate` does.
    - Applies the sliding expiry and `touch_device_meta`.
    - `ResumeFail { genuine: bool }`: the secret was right but the row is expired.
  - `pub fn revoke_device(sys: &SystemDb, u: &Unlocked, device_id: &str) -> anyhow::Result<bool>`, which returns false if the device is not `u`'s
  - `pub fn revoke_all_devices(sys: &SystemDb, u: &Unlocked) -> anyhow::Result<usize>`
  - `pub fn device_label(user_agent: &str) -> String`
    - Format: "{platform} · {browser}", using the first match.
    - Platform: iPhone, iPad, Android, Mac, Windows, Linux, else "Unknown device".
    - Browser: Firefox (`Firefox/` or `FxiOS`), Edge (`Edg/`), Chrome (`Chrome/` or `CriOS`), Safari, else "Browser".
    - Truncated to 60 chars.
- Unchanged: `tokens::authenticate` already rejects `kind = 'device'` rows; the test below pins that.

- [ ] **Step 1: Write failing tests** in `tests/devices.rs`:
  - `create_then_resume_returns_same_user_and_device_id`
  - `wrong_secret_fails_not_genuine`
  - `expired_token_fails_genuine`, with `now` past `expires_at`
  - `sliding_expiry_extends_at_most_once_a_day`: resuming at `now` and `now + 3600` leaves `expires_at` unchanged; resuming at `now + 2*86400` sets it to that time + `DEVICE_TTL_SECS`
  - `twenty_first_device_evicts_least_recently_used`
  - `revoke_all_devices_keeps_mcp_tokens`: create a static MCP token too; it still authenticates afterwards
  - `device_token_is_not_an_mcp_bearer`: `tokens::authenticate(state, &pmd_token)` returns `Err`
  - `mcp_token_does_not_resume`: `resume_device(state, &pm_token, now)` returns `Err`
  - `device_label` table test covering an iPhone Safari UA, an iPhone PWA UA (same as Safari), Android Chrome, Linux Firefox, macOS Safari, and an empty string giving "Unknown device · Browser"
- [ ] **Step 2: Write the failing migration test.** `index_migration_v3_to_v4_keeps_data`: build a v3 index DB with a document and a token_meta row using the existing v3 fixture approach, open it with the current code, and assert `user_version == 4`, that `device_meta` exists, and that the old rows are intact.
- [ ] **Step 3: Run the tests.**
  - Run: `cargo test -j 2 --test devices -- --test-threads=2`, plus the migration test.
  - Expected: FAIL; unresolved items.
- [ ] **Step 4: Implement everything** listed under Interfaces.
- [ ] **Step 5: Run the tests.** Expected: PASS. Then run the full test gate.
- [ ] **Step 6: Commit** with `feat(v1.6): device tokens for remembered logins (storage, resume, index v4)`.

### Task 2: Web wiring (login, resume, logout)

**Files:**
- Modify:
  - `src/web/session.rs`:
    - `DEVICE_COOKIE`, `device_cookie(token)`, `clear_device_cookie()`, `device_token(headers)`
    - `Session.device_id: Option<String>`
    - `SessionStore::create` takes `device_id: Option<String>`
    - `SessionStore::live_for_device(&self, device_id) -> Option<Session>`
    - resume in `session_layer`
  - `src/web/auth.rs`:
    - `LoginForm.remember: Option<String>` and the same field on the recovery form
    - `start_session`/`finish_login` take `remember: Option<&str /* label */>`
    - logout revokes the current device
  - `templates/login.html`, `templates/recover.html`: the checkbox `<label class="check"><input type="checkbox" name="remember" value="on" checked> Remember this device</label>`, with the hint "Stay logged in on this device for up to 90 days of inactivity. Don't use on shared computers."
- Test: `tests/web_devices.rs` (new). Use the existing `TestApp` helpers. For the restart test, build a second app on the same data dir; check how `TestApp` is constructed and add a `TestApp::restart(&self) -> TestApp` helper if there is none.

**Interfaces:**
- Consumes from Task 1: `devices::{create_device, resume_device, revoke_device, device_label, Resumed, ResumeFail}`.
- Produces:
  - `Session.device_id: Option<String>`
  - `session::device_token(headers: &HeaderMap) -> Option<&str>`
  - `session::device_cookie(token: &str) -> HeaderValue`
  - `session::clear_device_cookie() -> HeaderValue`

**Behaviour:**
- **Remember on login.** Successful login or recovery with `remember == Some("on")`:
  - Call `create_device(…, device_label(UA), now)`.
  - Append a second `Set-Cookie` with the device cookie. Use `headers_mut().append`, never `insert`, so the session cookie survives.
  - Create the session with that `device_id`.
- **Resume in `session_layer`.** It runs when there is no live session but there is a device cookie, for any method.
  1. If `live_for_device(id)` returns a session, use it (this covers parallel requests) and set its session cookie on the response.
  2. Otherwise call `resume_device` in `spawn_blocking`. It's HKDF, not Argon2, so no KDF semaphore is needed. Then call `sessions.create(…, Some(device_id))`, insert the session extension and append the session cookie to the response.
  3. A pending, unconfirmed recovery key still forces `/recovery-key`. Call `state.accounts.pending_recovery(&unlocked)`, as `finish_login` does.
  - After a resume, the normal CSRF branch below runs unchanged.
- **Failed resume.**
  - Append `clear_device_cookie()` and continue without a session.
  - If `!genuine`, record one failure on the IP limiter key: `state.limiter.begin(&[ip_key])`, then `.failure()`. If the limiter is already blocking, skip the resume attempt entirely.
- **Logout.** If `session.device_id` is set, call `revoke_device` and append `clear_device_cookie()`.

- [ ] **Step 1: Write failing tests** in `tests/web_devices.rs`:
  - `remembered_login_sets_device_cookie_and_survives_restart`: log in with remember=on, restart the app, then `GET /documents` with only the device cookie returns 200 and sets a new session cookie.
  - `unchecked_remember_sets_no_device_cookie`
  - `session_expiry_is_silently_renewed`: build the store with `idle = 1s`, sleep 1.1s, and the next request with both cookies still returns 200.
  - `concurrent_resumes_share_one_session`: 5 parallel `GET /documents` with only the device cookie all return the same session cookie value, and `state.sessions` holds 1 session for the user.
  - `tampered_device_cookie_clears_it_and_counts_failure`: the response is a 303 to /login with `__Host-pm_device=;…Max-Age=0`; after 10 tampered tries the IP is rate-limited.
  - `disabled_user_cannot_resume`
  - `logout_revokes_only_this_device`: two remembered logins; after logout on A, A's cookie gets the login page and B still resumes.
  - `post_after_idle_resumes_but_needs_fresh_csrf`: a POST to a settings form with the old CSRF token returns 403.
  - `device_cookie_rejected_at_mcp`: `Authorization: Bearer pmd_…` on `/mcp` returns 401.
- [ ] **Step 2: Run the tests.** Expected: FAIL.
- [ ] **Step 3: Implement** the behaviour above.
- [ ] **Step 4: Run the tests.** Expected: PASS. Then run the full test gate, which includes the existing auth, scan, share and OAuth tests.
- [ ] **Step 5: Commit** with `feat(v1.6): remember this device on login, resume sessions from the device cookie`.

### Task 3: Settings, revocation rules, docs

**Files:**
- Modify:
  - `src/web/settings.rs`:
    - devices section data
    - routes `POST /settings/devices/{id}/revoke` and `POST /settings/devices/revoke-others`
    - password change revokes all devices
    - TOTP disable requires the password
  - `src/web/auth.rs`: recovery-key login revokes all devices before an optional new remember
  - `templates/settings.html`: a "Remembered devices" section after "Two-factor"
  - `docs/setup.md`: a short "Remembered devices" paragraph in the security/login area, covering what it does, the risk and how to revoke
- Test: `tests/web_settings.rs`, `tests/web_devices.rs`

**Behaviour and copy:**
- **Settings section.**
  - Title "Remembered devices". Intro: "These devices stay logged in without your password. Anyone holding one of them unlocked can open your documents. Changing your password signs all of them out."
  - Each row shows the label, "added {date}", "last used {ago}" and a "this device" badge when `id == session.device_id`, plus a "Revoke" button (POST form with CSRF).
  - The button "Sign out all other devices" revokes every device except the current one.
  - Empty state: "No remembered devices."
- **Revoking the current device** from Settings also clears this browser's device cookie.
- **Password change.** Call `revoke_all_devices`, then end other sessions as today. The current session keeps working but is no longer remembered, and its device cookie is cleared. Update the notice to: "Password changed. Other sessions and all remembered devices were signed out. Existing MCP tokens keep working; revoke them in Settings if needed."
- **Recovery-key login.** Call `revoke_all_devices` once the new password is set.
- **TOTP disable.** Add a "Your password" field, with the hidden username include `{% include "_username_hint.html" %}` like the other password fields. Check it the same way token creation does (KDF semaphore plus limiter keys).

- [ ] **Step 1: Write failing tests:**
  - `settings_lists_devices_with_this_device_marker`
  - `revoke_device_from_settings`
  - `sign_out_other_devices_keeps_current`
  - `password_change_revokes_all_devices`: after the change, the old device cookie from another client gets 303 to /login with the cookie cleared
  - `recovery_login_revokes_all_devices`
  - `totp_disable_requires_password`: a wrong or missing password with a correct code leaves TOTP on
  - Update the existing `totp_enable_disable` test to send the password.
  - Extend `password_fields_carry_a_username_hint_for_password_managers` if its counts change.
- [ ] **Step 2: Run the tests.** Expected: FAIL.
- [ ] **Step 3: Implement** the behaviour above and update `docs/setup.md`.
- [ ] **Step 4: Run the full test gate.** Expected: PASS, with clippy clean.
- [ ] **Step 5: Commit** with `feat(v1.6): manage remembered devices; password change and recovery revoke them; TOTP disable needs password`.
