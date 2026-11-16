# Personal Media Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Implementer subagents run on **Sonnet** (`model: "sonnet"`), per the owner's instruction.

**Goal:** A self-hosted, per-user-encrypted document vault (Rust, single binary, one Docker container on a ZimaBoard) with web UI, OCR full-text search, and an MCP endpoint, followed by v1.1 (installable PWA + share target).

**Architecture:** One Rust binary (`personal-media`) with subcommands `serve`, `invite`, `recover`. Accounts and wrapped keys live in a plaintext `system.db`. Each user's content lives in their own SQLCipher `index.db` (with FTS5) and in chunk-encrypted blob files. A user's master key exists only in memory while they're unlocked (web session, MCP token cache, or running OCR job), held via `Arc<Unlocked>` in a `Keyring` of weak references. Server-rendered askama pages plus htmx; MCP via `rmcp` over Streamable HTTP; OCR via `pdftotext`/`pdftoppm`/`tesseract` subprocesses.

**Tech Stack:** Rust 1.98 (edition 2024), axum 0.8, tokio, askama 0.16, rusqlite 0.43 (`bundled-sqlcipher-vendored-openssl`), argon2, chacha20poly1305, hkdf + sha2, zeroize, totp-rs, rmcp, clap, tracing, zip, htmx 2.0.4 (vendored). Docker on Debian trixie.

**Spec:** `docs/superpowers/specs/2026-11-16-personal-media-design.md`. Read it before starting any task. Setup guide: `docs/setup.md`.

## Global Constraints

- **No plaintext at rest.** User content, filenames, titles, tags, extracted text, search queries and token names/scopes never touch disk unencrypted, except OCR scratch in `/data/tmp`, which is deleted at job end (also on error) and wiped at startup.
- **The admin can never decrypt user data.** No server-wide key may decrypt user data.
- **Logs never contain** filenames, titles, tags, search queries, document text, passwords, recovery keys or token secrets. Request logging records method, matched route template, status and latency only. It never logs the URI query string or path parameters.
- **Crypto:** RustCrypto crates only. All randomness comes from the OS CSPRNG (`rand::rngs::OsRng` or `getrandom`). Every secret type implements `Zeroize` + `ZeroizeOnDrop` and has no `Debug` that prints bytes.
- **Crate versions:** use the newest mutually compatible versions. `hkdf`, `sha2` and `argon2` must share one `digest` version; if the newest don't line up, pin to the newest set that does.
- **Config env vars and defaults:**
  - `PM_DATA_DIR=/data`
  - `PM_BIND=127.0.0.1:8080`
  - `PM_PUBLIC_URL` (required for `serve` and `invite`)
  - `PM_MAX_UPLOAD_MB=100`
  - `PM_SESSION_IDLE_MINUTES=30`
  - `PM_SESSION_MAX_HOURS=12`
  - `PM_TRUSTED_PROXY=127.0.0.1`
  - `PM_OCR_WORKERS=1`
- **Argon2id:** m = 65536 KiB, t = 3, p = 1, 16-byte random salt per user. Parameters are stored per user. Tests may use `Argon2Params { m_kib: 1024, t: 1, p: 1 }` via `Config`.
- **Wrapped/sealed format:** `[version u8 = 1][nonce 24 bytes][XChaCha20-Poly1305 ciphertext+tag]`.
- **AAD strings** (exact):
  - `pm/v1/umk/password/{user_id}`
  - `pm/v1/umk/recovery/{user_id}`
  - `pm/v1/umk/token/{token_id}`
  - `pm/v1/indexkey/{user_id}`
  - `pm/v1/totp/{user_id}`
  - `pm/v1/dek/{user_id}/{doc_id}`
  - `pm/v1/blob/{user_id}/{doc_id}`
- **HKDF-SHA256 info strings:** `pm/v1/kek/recovery` and `pm/v1/kek/token`, with no salt.
- **IDs and formats:**
  - User IDs and document IDs are UUID v4 strings. A document's ID is also its blob filename.
  - Tokens are `pm_{token_id: 32 lowercase hex}_{secret: 64 lowercase hex}`.
  - Invite tokens are 32 random bytes as 64 lowercase hex. Only their SHA-256 is stored.
  - Recovery keys are 32 random bytes encoded as RFC 4648 base32 (uppercase, no padding, 52 chars), shown as 13 groups of 4 joined by `-`. Parsing ignores case, spaces and dashes.
- **Usernames:** lowercase `^[a-z0-9_.-]{3,32}$` (input is lowercased first), unique.
- **Passwords:** at least 10 characters.
- **Cookies:**
  - `pm_session`: `HttpOnly; Secure; SameSite=Strict; Path=/`. v1.1 may relax this to `Lax` (Task 18).
  - `pm_continue`: used in Task 18.
- **Security headers on every response:**
  - `Content-Security-Policy: default-src 'self'; img-src 'self' data:; object-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `Strict-Transport-Security: max-age=31536000`
  - The raw/preview endpoint overrides `frame-ancestors 'self'` (Task 11).
- **No inline scripts or styles, and no `hx-on` attributes.** All JS lives in `static/app.js`. Set htmx config via `<meta name="htmx-config" content='{"includeIndicatorStyles":false,"allowEval":false}'>`.
- **CSRF:** every state-changing request (non-GET) authenticated by session must carry the session's CSRF token, either as form field `csrf` or header `X-CSRF-Token`. `static/app.js` sets the header for htmx and `fetch` from `<meta name="csrf-token">`.
- **Rate limiting:** keys are `ip:{ip}`, `user:{username}` and `mcp-ip:{ip}`. 10 failures within 15 minutes lock that key for 15 minutes; locked requests get HTTP 429. A success clears the `user:` key. Client IP is `X-Forwarded-For` (a single address) only when the TCP peer equals `PM_TRUSTED_PROXY`; otherwise it's the TCP peer address.
- **Extraction limits:** max 200 PDF pages, `pdftotext` timeout 60 s, `pdftoppm` timeout 600 s, `tesseract` timeout 120 s per page, whole job 30 min. Subprocesses are killed on timeout.
- **OCR language:** `-l deu+eng`. PDF render resolution: `-r 300`.
- **Every task** ends with `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` all passing.

## Review Focus

1. **Hostile search input.** A query such as `secret" OR content:geheim`, `content: x`, `NEAR(`, `*`, `-foo`, unbalanced quotes or an empty string must never error with 500. It must never escape the metadata-only column filter. Expected behavior: treat the input as plain words (Task 5 test `search_input_is_literal_and_cannot_escape_columns`).
2. **Hostile uploads served back.**
   - An uploaded `.html`, `.svg` or `.js` file, or one claiming `text/html`, must never render on our origin. Only PDF, PNG, JPEG, WebP and GIF are served `inline`; everything else is `attachment` with `application/octet-stream` (Task 11 test `html_and_svg_uploads_are_never_inline`).
   - Filenames containing quotes, CR/LF, umlauts, `../` or 300+ characters must produce a valid `Content-Disposition` header (RFC 6266 `filename*=UTF-8''…`). In ZIP export they must become safe, unique entry names (Task 11 `content_disposition_handles_hostile_names`, Task 12 `export_zip_entry_names_are_safe_and_unique`).
3. **Broken files in OCR.** A corrupt PDF, an encrypted PDF, a 0-byte file, or an image with no text → `failed` or `done` with empty text. The worker keeps processing the next job, and the per-job temp dir is gone (Task 8 `corrupt_and_empty_inputs_fail_cleanly`).
4. **Access after an account change.**
   - Disabling or deleting a user immediately invalidates their web sessions and MCP token cache.
   - Logging out on one device must not lock another device's session for the same user.
   - Tests: Task 6 `two_sessions_share_unlocked_and_survive_one_logout`, Task 13 `disable_and_delete_kill_sessions_and_tokens`.
5. **Search queries in logs and URLs.** Search uses `GET /documents?q=…`. The access log and any error log must not contain the query (Task 9 `access_log_omits_query_and_path_params`).

---

## File Structure

```
Cargo.toml
src/main.rs                 CLI (clap): serve | invite --admin | recover
src/lib.rs                  module declarations, re-exports
src/config.rs               Config::from_env, Config::for_tests
src/crypto/mod.rs           CryptoError, re-exports
src/crypto/keys.rs          Key32, seal/open, wrap_key/unwrap_key, aad helpers
src/crypto/kdf.rs           Argon2Params, password_kek, secret_kek
src/crypto/recovery.rs      RecoveryKey generate/display/parse
src/crypto/stream.rs        EncryptWriter, DecryptReader (blob format)
src/system_db.rs            SystemDb: users, invites, tokens (plaintext SQLite)
src/user_db/mod.rs          open_user_db (SQLCipher), migrations
src/user_db/documents.rs    documents, tags, text, FTS, search
src/user_db/meta.rs         token metadata, settings
src/keyring.rs              Unlocked, Keyring
src/accounts.rs             Accounts: invites, signup, login, recovery, password, TOTP, admin ops
src/documents.rs            Documents: store/read/delete/update blobs + metadata
src/extract.rs              extract_text (blocking) + ExtractQueue workers
src/tokens.rs               create/revoke/authenticate MCP tokens, TokenCache
src/export.rs               write_export (ZIP), used by web + CLI
src/web/mod.rs              AppState, build_app(), security headers, access log
src/web/session.rs          SessionStore, Session, extractors (CurrentUser, AdminUser), CSRF
src/web/ratelimit.rs        RateLimiter, client_ip()
src/web/auth.rs             signup/login/logout/recover/confirm-recovery handlers
src/web/docs.rs             list/search/upload/detail/raw/download/edit/delete/retry
src/web/settings.rs         password, recovery, TOTP, tokens, export
src/web/admin.rs            invites, users, disable, delete
src/web/pwa.rs              (v1.1) manifest, service worker, share target
src/mcp.rs                  rmcp server + tools + /mcp route
templates/*.html            askama templates
static/htmx.min.js          vendored htmx 2.0.4
static/app.css, static/app.js, static/icons/* (v1.1), static/sw.js (v1.1)
tests/common/mod.rs         TestApp harness
tests/*.rs                  integration tests per area
tests/fixtures/             text.pdf, scanned.pdf, scan.png, corrupt.pdf
Dockerfile, docker-compose.yml, .dockerignore, README.md
```

---

## Milestone 1: Core (crypto, storage, accounts)

### Task 1: Crate scaffold, config, SQLCipher+FTS5 smoke test

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/config.rs`, `.gitignore` (`/target`), `tests/sqlcipher_smoke.rs`

**Interfaces:**
- Produces:
  - `pub struct Config { pub data_dir: PathBuf, pub bind: SocketAddr, pub public_url: String, pub max_upload_bytes: u64, pub session_idle: Duration, pub session_max: Duration, pub trusted_proxy: IpAddr, pub ocr_workers: usize, pub argon2: crypto::kdf::Argon2Params }`
  - `Config::from_env() -> anyhow::Result<Config>`
  - `Config::for_tests(data_dir: PathBuf) -> Config`, which uses small Argon2 params and `public_url = "https://test.example"`.
  - CLI: `personal-media serve` (the default when no subcommand is given), `personal-media invite --admin`, and `personal-media recover --data <dir> --user <name> --out <dir>`. Each one is a stub that prints "not implemented" until later tasks fill it in.

- [ ] **Step 1: Write `tests/sqlcipher_smoke.rs::sqlcipher_encrypts_and_supports_fts5`**
  1. Open `tmp/x.db` with `PRAGMA key = "x'<64 hex>'"`.
  2. Create `CREATE VIRTUAL TABLE f USING fts5(a, tokenize='unicode61 remove_diacritics 2')`.
  3. Insert `'Kündigung Mietvertrag'`.
  4. Assert `SELECT count(*) FROM f WHERE f MATCH 'kundigung'` returns 1.
  5. Close the connection.
  6. Assert the raw file bytes don't contain `b"Mietvertrag"` and don't start with `b"SQLite format 3"`.
  7. Assert that reopening with a different key fails on the first query.
- [ ] **Step 2:** Run `cargo test --test sqlcipher_smoke`. Expected: FAIL (crate not set up yet).
- [ ] **Step 3:** Create the crate with all dependencies from the Tech Stack line, plus `anyhow`, `thiserror`, `serde`, `serde_json`, `uuid` (v4), `hex`, `data-encoding`, `rand`, `time`, `tracing`, `tracing-subscriber`, `tempfile` (dev), `tower` (dev, `util`) and `http-body-util`. Use rusqlite features `bundled-sqlcipher-vendored-openssl`. Implement `Config` and the clap CLI stubs.
- [ ] **Step 4:** Run `cargo test --test sqlcipher_smoke`. Expected: PASS. If FTS5 isn't compiled in, set `LIBSQLITE3_FLAGS="-DSQLITE_ENABLE_FTS5"` via `.cargo/config.toml` `[env]` and document it in the README.
- [ ] **Step 5:** Commit: `chore: scaffold crate, config, CLI; verify SQLCipher+FTS5`.

### Task 2: Key wrapping, KDFs, recovery keys

**Files:**
- Create: `src/crypto/mod.rs`, `src/crypto/keys.rs`, `src/crypto/kdf.rs`, `src/crypto/recovery.rs`. Unit tests go in each file.

**Interfaces:**
- Produces:
  - `#[derive(thiserror::Error)] pub enum CryptoError { Decrypt, Format, Kdf }`
  - `pub struct Key32([u8; 32])` (zeroize-on-drop) with `random()`, `from_bytes([u8;32])` and `as_bytes(&self) -> &[u8;32]`
  - `seal(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Vec<u8>`
  - `open(key: &Key32, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>`
  - `wrap_key(kek: &Key32, key: &Key32, aad: &[u8]) -> Vec<u8>`
  - `unwrap_key(kek: &Key32, wrapped: &[u8], aad: &[u8]) -> Result<Key32, CryptoError>`
  - `pub mod aad` with one fn per AAD string in Global Constraints: `umk_password(user_id: &str) -> String`, `umk_recovery`, `umk_token(token_id)`, `index_key`, `totp`, `dek(user_id, doc_id)`, `blob(user_id, doc_id)`
  - `#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)] pub struct Argon2Params { pub m_kib: u32, pub t: u32, pub p: u32 }`, with `Default` = 65536/3/1
  - `password_kek(password: &str, salt: &[u8;16], p: &Argon2Params) -> Result<Key32, CryptoError>`
  - `secret_kek(secret: &[u8;32], info: &str) -> Key32`
  - `pub const INFO_RECOVERY: &str = "pm/v1/kek/recovery"` and `pub const INFO_TOKEN: &str = "pm/v1/kek/token"`
  - `pub struct RecoveryKey([u8;32])` (zeroize) with `generate()`, `to_display(&self) -> String`, `parse(s: &str) -> Result<RecoveryKey, CryptoError>` and `secret(&self) -> &[u8;32]`

- [ ] **Step 1: Write the failing tests**
  - `wrap_roundtrip`
  - `unwrap_with_wrong_kek_fails` → `Err(CryptoError::Decrypt)`
  - `unwrap_with_other_aad_fails`, e.g. wrapping with `aad::umk_password("a")` and unwrapping with `aad::umk_password("b")` or `aad::umk_recovery("a")`
  - `tampered_ciphertext_fails` (flip the last byte)
  - `bad_version_byte_is_format_error` (first byte 2 → `Err(CryptoError::Format)`)
  - `seal_uses_fresh_nonce` (sealing the same input twice gives different outputs)
  - `password_kek_deterministic_and_salt_sensitive`
  - `secret_kek_info_separates` (`INFO_RECOVERY` and `INFO_TOKEN` produce different keys)
  - `recovery_display_format`: 64 chars, 13 groups of 4, charset `A-Z2-7`
  - `recovery_parse_is_lenient`: lowercase input with spaces/dashes parses back equal
  - `recovery_parse_rejects_bad_length`
- [ ] **Step 2:** Run `cargo test crypto::`. Expected: compile failure or FAIL.
- [ ] **Step 3:** Implement in the files listed. Wrap is `seal(kek, key.as_bytes(), aad)`.
- [ ] **Step 4:** Run `cargo test crypto::`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(crypto): key wrapping, KDFs, recovery keys`.

### Task 3: Chunked blob encryption (STREAM)

**Files:**
- Create: `src/crypto/stream.rs`. Unit tests go inside the file.

**Interfaces:**
- Produces:
  - `pub struct EncryptWriter<W: Write>` with `EncryptWriter::new(inner: W, key: &Key32, aad: &[u8]) -> io::Result<Self>`, `impl Write`, and `finish(self) -> io::Result<W>`
  - `pub struct DecryptReader<R: Read>` with `DecryptReader::new(inner: R, key: &Key32, aad: &[u8]) -> io::Result<Self>` and `impl Read`
  - Authentication failures surface as `io::ErrorKind::InvalidData`.
  - `pub const CHUNK: usize = 65536`

**Blob format:**
- Header: `b"PMB1"` followed by a 19-byte random nonce prefix.
- Body: a sequence of chunks, each holding `ciphertext(len(plain) + 16)`.
- Chunk nonce: `prefix(19) || counter u32 big-endian (4) || last_flag u8 (1)`, with the counter starting at 0.
- Every non-final chunk holds exactly `CHUNK` plaintext bytes. The final chunk holds 0..=`CHUNK` bytes and has `last_flag = 1`.
- `finish` always emits the final chunk, even when it's empty.
- The reader decides that a chunk is the final one when the underlying reader hits EOF after it, and then decrypts it with `last_flag = 1`.

- [ ] **Step 1: Write the failing tests** (each asserting round-trip equality)
  - `roundtrip_sizes` for plaintext lengths 0, 1, 65535, 65536, 65537, 3×65536 and 200_000
  - `truncated_final_chunk_detected`: drop the last 16+ bytes → read errors with `InvalidData`
  - `dropping_whole_last_chunk_detected`: for a 65536-byte input, drop the trailing empty-final chunk (16 bytes) → error
  - `reordered_chunks_detected`: swap the first two full chunks of a 3×CHUNK blob → error
  - `wrong_aad_detected`
  - `bad_magic_rejected`
  - `ciphertext_does_not_contain_plaintext`
- [ ] **Step 2:** Run `cargo test crypto::stream`. Expected: FAIL.
- [ ] **Step 3:** Implement using `XChaCha20Poly1305` with the AAD passed to each chunk.
- [ ] **Step 4:** Run `cargo test crypto::stream`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(crypto): chunked STREAM blob encryption`.

### Task 4: System database

**Files:**
- Create: `src/system_db.rs`. Unit tests go inside the file.

**Interfaces:**
- Consumes: `Argon2Params` (Task 2).
- Produces:
  - `pub struct SystemDb` (holds `Mutex<rusqlite::Connection>`) with `SystemDb::open(path: &Path) -> anyhow::Result<SystemDb>`. It sets WAL mode and `PRAGMA foreign_keys=ON`, and runs migrations via a `user_version` check.
  - `#[derive(Clone, Copy, PartialEq, Debug)] pub enum Role { Admin, User }`
  - `pub struct UserRow { pub id: String, pub username: String, pub role: Role, pub disabled: bool, pub created_at: i64, pub salt: [u8;16], pub argon2: Argon2Params, pub umk_by_password: Vec<u8>, pub umk_by_recovery: Vec<u8>, pub index_key_wrapped: Vec<u8>, pub totp_sealed: Option<Vec<u8>> }`
  - User methods:
    - `insert_user(&self, u: &UserRow) -> Result<(), SysError>`, where `SysError::UsernameTaken` is returned on a unique violation
    - `user_by_name(&self, name) -> Result<Option<UserRow>>`
    - `user_by_id(&self, id) -> Result<Option<UserRow>>`
    - `list_users(&self) -> Result<Vec<UserRow>>`
    - `set_password_wrap(&self, id, salt: [u8;16], argon2: Argon2Params, wrapped: &[u8])`
    - `set_recovery_wrap(&self, id, wrapped: &[u8])`
    - `set_totp(&self, id, sealed: Option<&[u8]>)`
    - `set_disabled(&self, id, bool)`
    - `delete_user(&self, id)`, which cascades to tokens
  - Invite methods:
    - `create_invite(&self, token_hash: [u8;32], role: Role, created_at: i64, expires_at: i64)`
    - `consume_invite(&self, token_hash: [u8;32], now: i64) -> Result<Role, InviteError>`, where `InviteError` is `NotFound`, `Expired` or `Used`. Check-and-mark-used happens in one transaction.
    - `list_open_invites(&self, now) -> Result<Vec<(String /*hash hex prefix 8*/, Role, i64 /*expires*/)>>`
    - `revoke_invite(&self, hash_prefix: &str)`
  - Token methods:
    - `insert_token(&self, token_id, user_id, umk_wrapped: &[u8])`
    - `token(&self, token_id) -> Result<Option<(String /*user_id*/, Vec<u8>)>>`
    - `delete_token(&self, token_id)`
    - `token_ids_for_user(&self, user_id) -> Result<Vec<String>>`
  - `pub const SYSTEM_DB_FILE: &str = "system.db"`

- [ ] **Step 1: Write the failing tests**
  - `user_crud_roundtrip`
  - `duplicate_username_rejected`
  - `invite_single_use`: second consume → `Used`
  - `invite_expiry`: consume at `expires_at + 1` → `Expired`
  - `delete_user_removes_tokens`
  - `schema_has_no_content_columns`: assert via `PRAGMA table_info` that no table has columns named `filename`, `title`, `tags`, `name` or `scope`
- [ ] **Step 2:** Run `cargo test system_db`. Expected: FAIL.
- [ ] **Step 3:** Implement. Store the Argon2 params as three INTEGER columns. Store `role` as TEXT, `'admin'` or `'user'`.
- [ ] **Step 4:** Run `cargo test system_db`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: system database (users, invites, token wraps)`.

### Task 5: Per-user encrypted index DB, search

**Files:**
- Create: `src/user_db/mod.rs`, `src/user_db/documents.rs`, `src/user_db/meta.rs`, `tests/user_db.rs`

**Interfaces:**
- Consumes: `Key32` (Task 2).
- Produces:
  - **Opening:** `pub fn open_user_db(path: &Path, key: &Key32) -> anyhow::Result<Connection>` uses a raw-key `PRAGMA key`, `PRAGMA foreign_keys=ON` and runs migrations.
  - **Text status:** `#[derive(Clone, Copy, PartialEq, Debug, Serialize)] pub enum TextStatus { Pending, Done, Failed, Unsupported }`, stored as lowercase text.
  - **Document types:**
    - `pub struct NewDocument { pub id: String, pub wrapped_dek: Vec<u8>, pub original_filename: String, pub title: String, pub mime: String, pub size: u64, pub sha256: [u8;32], pub document_date: Option<String> /* YYYY-MM-DD */, pub tags: Vec<String>, pub created_at: i64 }`
    - `#[derive(Clone, Debug, Serialize)] pub struct Document { pub id, pub wrapped_dek: Vec<u8> /* #[serde(skip)] */, pub original_filename, pub title, pub mime, pub size: u64, pub sha256_hex: String, pub document_date: Option<String>, pub created_at: i64, pub updated_at: i64, pub text_status: TextStatus, pub page_count: Option<u32>, pub tags: Vec<String> }`
  - **Filters and search types:**
    - `#[derive(Default, Clone)] pub struct ListFilter { pub tags_all: Vec<String>, pub tag_allow: Option<Vec<i64>> /* ANY of these tag ids */, pub date_from: Option<String>, pub date_to: Option<String>, pub limit: u32 /* 0 → 50 */, pub offset: u32 }`. Date filters apply to `document_date` (documents without one are excluded when a date filter is set).
    - `pub enum SearchMode { FullText, MetadataOnly }`
    - `pub struct SearchHit { pub doc: Document, pub snippet: Option<String> }`. Snippets mark matches with `\u{2}`…`\u{3}`, are always `None` in `MetadataOnly`, and are capped at 12 tokens using `…` as the ellipsis.
  - **Document functions** (in `documents.rs`, all take `conn: &Connection`):
    - `insert_document(conn, &NewDocument)`, which also indexes title/filename/tags in FTS
    - `get_document(conn, id) -> Result<Option<Document>>`
    - `find_by_sha256(conn, &[u8;32]) -> Result<Option<Document>>`
    - `list_documents(conn, &ListFilter) -> Result<Vec<Document>>`, newest `created_at` first
    - `update_document_meta(conn, id, title: Option<&str>, document_date: Option<Option<&str>>, tags: Option<&[String]>, now: i64)`
    - `delete_document(conn, id)`
    - `set_text(conn, id, status: TextStatus, text: Option<&str>, page_count: Option<u32>)`
    - `pending_document_ids(conn) -> Result<Vec<String>>`
    - `list_tags(conn) -> Result<Vec<(i64, String)>>`, sorted by name
    - `tag_ids(conn, names: &[String]) -> Result<Vec<i64>>`, which creates missing tags
    - `search(conn, text: &str, mode: SearchMode, filter: &ListFilter) -> Result<Vec<SearchHit>>`, ranked by bm25
  - **Token metadata and settings** (in `meta.rs`):
    - `#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)] pub struct TokenScope { pub access: Access, pub content: Content, pub tags: Option<Vec<i64>> }`
    - `pub enum Access { Read, ReadWrite }` and `pub enum Content { MetadataOnly, FullText }`, both serde `snake_case`
    - `pub struct TokenMeta { pub id: String, pub name: String, pub scope: TokenScope, pub created_at: i64, pub last_used_at: Option<i64> }`
    - `insert_token_meta`, `list_token_meta`, `get_token_meta(conn, id) -> Result<Option<TokenMeta>>`, `delete_token_meta`, `touch_token(conn, id, now)`
    - `get_setting(conn, key) -> Result<Option<String>>` and `set_setting`

**FTS:** use a contentless-style regular FTS5 table `documents_fts(doc_id UNINDEXED, title, filename, tags, content, tokenize='unicode61 remove_diacritics 2')`. It's maintained explicitly by a private `reindex(conn, id)` called from every mutation (delete the row, then insert a new one). Tags are joined by spaces.

**Query building:** this is the one algorithm the tests don't fully fix, so it's spelled out:

```rust
// split user text on whitespace; for each term strip every '"' char; drop empty terms;
// quote each as "term"; the LAST term additionally gets a trailing * (prefix match);
// join with ' ' (implicit AND). Empty after cleaning → return Ok(vec![]) without querying.
// MetadataOnly: wrap as  {title filename tags} : (<joined>)
```

- [ ] **Step 1: Write the failing tests in `tests/user_db.rs`**
  - `insert_get_list_roundtrip`
  - `search_finds_content_with_umlaut_folding`: content `"Kündigungsfrist drei Monate"`, query `kundigungsfrist` → hit, with a snippet containing `\u{2}`
  - `prefix_search_on_last_term`: query `kundig` → hit
  - `metadata_only_never_matches_content`: content contains `geheim` and the title doesn't; MetadataOnly query `geheim` → empty; FullText → 1 hit
  - `search_input_is_literal_and_cannot_escape_columns`:
    - For each of `geheim" OR content:geheim`, `content: geheim`, `NEAR(geheim`, `*`, `-geheim`, `"`, `""`, `(`, `title:x OR content:geheim` in MetadataOnly mode, the result is `Ok` and contains no doc whose only match is in content.
    - The same inputs in FullText mode return `Ok`.
  - `tag_filters`: `tags_all = ["a","b"]` returns only docs with both tags; `tag_allow = [id_a]` returns docs with tag a
  - `date_filters_inclusive`
  - `update_meta_reindexes`: rename title → the new title is searchable and the old one isn't
  - `delete_removes_from_fts`
  - `token_meta_roundtrip`
  - `db_file_has_no_plaintext`: after inserting a doc with filename `Steuerbescheid_2025.pdf`, a tag `finanzamt` and content `Einkommensteuer`, close the connection; the raw bytes of `index.db` and of any `-wal`/`-journal` file contain none of those strings
- [ ] **Step 2:** Run `cargo test --test user_db`. Expected: FAIL.
- [ ] **Step 3:** Implement. Use the schema columns from spec §10, plus `tags(id INTEGER PK, name TEXT UNIQUE)`, `document_tags(document_id, tag_id)`, `token_meta(id PK, name, scope_json, created_at, last_used_at)` and `settings(key PK, value)`.
- [ ] **Step 4:** Run `cargo test --test user_db`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: per-user SQLCipher index with FTS5 search`.

### Task 6: Keyring and accounts service

**Files:**
- Create: `src/keyring.rs`, `src/accounts.rs`, `tests/accounts.rs`

**Interfaces:**
- Consumes: Tasks 2, 4 and 5. `ExtractQueue` comes from Task 8. Until then, define `pub trait OnUnlock: Send + Sync { fn unlocked(&self, u: &Arc<Unlocked>); }` in `keyring.rs` and pass `Arc<dyn OnUnlock>`. Task 8 implements it for `ExtractQueue`.
- Produces:
  - **`Unlocked` and `Keyring`:**
    - `pub struct Unlocked { pub user_id: String, umk: Key32, db: Mutex<Connection> }` with `umk(&self) -> &Key32` and `with_db<T>(&self, f: impl FnOnce(&Connection) -> T) -> T`
    - `pub struct Keyring` with `Keyring::new(data_dir: PathBuf, on_unlock: Arc<dyn OnUnlock>)`
    - `unlock(&self, user_id: &str, umk: Key32, index_key_wrapped: &[u8]) -> anyhow::Result<Arc<Unlocked>>` returns the existing live `Arc` if one exists (via `Weak::upgrade`). Otherwise it unwraps the index key with `aad::index_key`, opens `users/{id}/index.db` and calls `on_unlock.unlocked`.
    - `get(&self, user_id) -> Option<Arc<Unlocked>>`
    - Paths: `pub fn user_dir(data_dir, user_id) -> PathBuf` and `pub fn index_db_path(data_dir, user_id) -> PathBuf`
  - **`Accounts`:** `pub struct Accounts { /* sys: Arc<SystemDb>, keyring: Arc<Keyring>, data_dir, argon2: Argon2Params, public_url */ }` with `Accounts::new(cfg: &Config, sys: Arc<SystemDb>, keyring: Arc<Keyring>) -> Accounts`. Methods:
    - `create_invite(&self, role: Role, now: i64) -> anyhow::Result<String /* full URL {public_url}/invite/{token} */>`, which expires after 7 days
    - `signup(&self, invite_token: &str, username: &str, password: &str, now: i64) -> Result<(Arc<Unlocked>, UserRow, RecoveryKey), AccountError>`. It creates the UMK, the index key, both wraps, `users/{id}/blobs/` and the index DB.
    - `login(&self, username, password, totp_code: Option<&str>) -> Result<(Arc<Unlocked>, UserRow), AccountError>`
    - `recover(&self, username, recovery_key: &str, new_password: &str) -> Result<(Arc<Unlocked>, UserRow, RecoveryKey /* new */), AccountError>`
    - `change_password(&self, user_id, current: &str, new: &str) -> Result<(), AccountError>`. It re-wraps with a fresh salt and the current default params.
    - `regenerate_recovery(&self, u: &Unlocked) -> Result<RecoveryKey, AccountError>`
    - `totp_begin(&self, username: &str) -> TotpSetup { pub secret_b32: String, pub otpauth_url: String, pub qr_png_base64: String }`, using issuer `Personal Media`, SHA1, 6 digits, 30 s step and a skew of 1
    - `totp_enable(&self, u: &Unlocked, secret_b32: &str, code: &str) -> Result<(), AccountError>`, which stores `seal(umk, secret, aad::totp)`
    - `totp_disable(&self, u: &Unlocked, code: &str) -> Result<(), AccountError>`
    - `totp_enabled(&self, user_id) -> bool`
    - `set_disabled(&self, user_id, bool)` and `delete_user(&self, user_id)`, which removes the system rows and `users/{id}` recursively
  - `#[derive(thiserror::Error, Debug)] pub enum AccountError { InvalidCredentials /* also wrong/missing TOTP */, Disabled, UsernameTaken, InvalidUsername, WeakPassword, Invite(InviteError), Internal(anyhow::Error) }`
  - A wrong password and an unknown username must both return `InvalidCredentials`. An unknown username still runs one dummy `password_kek` with default-test params so timing is similar.

- [ ] **Step 1: Write the failing tests in `tests/accounts.rs`** (using `Config::for_tests`)
  - `signup_then_login`
  - `wrong_password_and_unknown_user_are_same_error`
  - `invite_reuse_rejected`
  - `username_rules`: `"AB"` → `InvalidUsername`; `"Sebi"` is stored as `"sebi"`
  - `weak_password_rejected` (9 characters)
  - `password_change_keeps_data`: insert a doc row via `with_db`, change the password, drop all Arcs, log in with the new password and confirm the doc is still there; the old password → `InvalidCredentials`
  - `recover_sets_new_password_and_rotates_recovery_key`: the old recovery key no longer works afterwards and the new one does
  - `recover_skips_totp`
  - `totp_required_when_enabled`: no code → `InvalidCredentials`; correct code (generated with totp-rs from the secret) → Ok
  - `disabled_user_cannot_login`
  - `two_sessions_share_unlocked_and_survive_one_logout`: login twice → `Arc::ptr_eq`; drop one and the other still works with `with_db`; drop both → `keyring.get(id)` is `None`
  - `on_unlock_called_once_per_fresh_unlock`
  - `delete_user_removes_directory`
- [ ] **Step 2:** Run `cargo test --test accounts`. Expected: FAIL.
- [ ] **Step 3:** Implement. Run CPU-heavy Argon2 calls inside `tokio::task::spawn_blocking` at the web layer. `Accounts` methods themselves are sync.
- [ ] **Step 4:** Run `cargo test --test accounts`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: keyring and account lifecycle (signup, login, recovery, TOTP)`.

### Task 7: Document storage service

**Files:**
- Create: `src/documents.rs`, `tests/documents.rs`

**Interfaces:**
- Consumes: Tasks 3, 5 and 6, plus `OnUnlock`. Documents enqueue extraction via `Arc<dyn Enqueue>`, where `pub trait Enqueue: Send + Sync { fn enqueue(&self, u: Arc<Unlocked>, doc_id: String); }` is defined here and implemented by `ExtractQueue` in Task 8. Tests use a recording stub.
- Produces:
  - `pub struct Documents` with `Documents::new(data_dir: PathBuf, max_upload_bytes: u64, queue: Arc<dyn Enqueue>)`
  - `pub struct UploadMeta { pub filename: String, pub mime: Option<String>, pub title: Option<String>, pub tags: Vec<String>, pub document_date: Option<String> }`
  - `#[derive(Clone, Copy)] pub enum OnDuplicate { Skip, Keep }`
  - `#[derive(Debug, Serialize)] #[serde(tag = "status", rename_all = "snake_case")] pub enum StoreOutcome { Stored { id: String }, Duplicate { existing_id: String, existing_title: String } }`
  - `#[derive(thiserror::Error, Debug)] pub enum DocError { TooLarge, NotFound, InvalidDate, Internal(anyhow::Error) }`
  - `async fn store<S, E>(&self, u: &Arc<Unlocked>, meta: UploadMeta, body: S, on_dup: OnDuplicate, now: i64) -> Result<StoreOutcome, DocError> where S: Stream<Item = Result<Bytes, E>> + Unpin, E: Into<anyhow::Error>`
  - `fn open_plaintext(&self, u: &Unlocked, id: &str) -> Result<(Document, DecryptReader<File>), DocError>`
  - `fn decrypt_to_path(&self, u: &Unlocked, id: &str, dest: &Path) -> Result<Document, DocError>`, used by extraction
  - `fn delete(&self, u: &Unlocked, id: &str) -> Result<(), DocError>`
  - `fn update(&self, u: &Unlocked, id: &str, title: Option<&str>, date: Option<Option<&str>>, tags: Option<&[String]>, now: i64) -> Result<(), DocError>`
  - `fn retry_extraction(&self, u: &Arc<Unlocked>, id: &str) -> Result<(), DocError>`, which sets status to `pending` and enqueues
  - `pub fn blob_path(data_dir, user_id, doc_id) -> PathBuf` → `users/{user_id}/blobs/{doc_id}`
- **Storing a document:**
  1. Generate the doc id and DEK.
  2. Feed the stream through a `tokio::sync::mpsc` channel into a `spawn_blocking` task. That task writes `EncryptWriter` → `blobs/{id}.part` and computes SHA-256 and the byte count. If the count exceeds `max_upload_bytes`, abort with `TooLarge` and delete `.part`.
  3. Then run the duplicate check. On `Skip` with a duplicate, delete `.part` and return `Duplicate`.
  4. Rename `.part` to the final name and insert the row with `wrapped_dek = wrap_key(umk, dek, aad::dek)`.
  5. Determine the MIME type: the given one unless it's empty or `application/octet-stream`, otherwise `mime_guess` from the filename.
  6. Default title: the filename without its extension.
  7. Initial status: `pending` if the MIME is `application/pdf`, `image/{png,jpeg,tiff,webp}` or `text/plain`/`text/markdown`, otherwise `unsupported`.
  8. Enqueue extraction if `pending`.
- **Validation:** `document_date` must parse as `YYYY-MM-DD`, otherwise `InvalidDate`.

- [ ] **Step 1: Write the failing tests in `tests/documents.rs`**
  - `store_and_read_back_identical` (300 KB random bytes)
  - `duplicate_skip_and_keep`
  - `too_large_rejected_and_no_part_file_left`
  - `unsupported_type_not_enqueued`
  - `pdf_enqueued`
  - `delete_removes_blob_and_row`
  - `invalid_date_rejected`
  - `nothing_plaintext_at_rest`: store a file named `Arztbrief_Mueller.txt` with content `Diagnose vertraulich` and tag `gesundheit`, drop the Arc. A recursive scan of every file under `data_dir` must not find any of the strings `Arztbrief`, `Mueller`, `Diagnose`, `vertraulich` or `gesundheit`.
- [ ] **Step 2:** Run `cargo test --test documents`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test --test documents`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: encrypted document storage with duplicate detection`.

### Task 8: Text extraction and OCR worker

**Files:**
- Create: `src/extract.rs`, `tests/extract.rs`, `tests/fixtures/` (generate the fixtures with a script in `tests/fixtures/README.md`; commit the resulting small files):
  - `text.pdf` with the text "Mietvertrag Kündigungsfrist"
  - `scanned.pdf`: an image-only PDF of the words "Versicherungsnummer 12345"
  - `scan.png`
  - `corrupt.pdf` (random bytes with a `%PDF-` prefix)
  - `empty.pdf` (0 bytes)

**Interfaces:**
- Consumes: `Documents::decrypt_to_path`, `user_db::documents::{set_text, pending_document_ids}`, `Unlocked`, and the `Enqueue`/`OnUnlock` traits.
- Produces:
  - `pub struct ExtractConfig { pub tmp_dir: PathBuf, pub max_pages: u32 /*200*/, pub job_timeout: Duration /*30m*/ }`
  - `pub struct Extracted { pub text: String, pub page_count: Option<u32> }`
  - `#[derive(Debug)] pub enum ExtractError { Unsupported, Failed(String) }`
  - `pub fn extract_text(path: &Path, mime: &str, cfg: &ExtractConfig) -> Result<Extracted, ExtractError>` (blocking)
  - `pub fn wipe_tmp(tmp_dir: &Path) -> io::Result<()>`
  - `#[derive(Clone)] pub struct ExtractQueue` implementing `Enqueue` and `OnUnlock`. `on unlock` enqueues every `pending_document_ids`.
  - Wiring, in this order: `ExtractQueue::channel() -> (ExtractQueue, ExtractReceiver)`, then `Keyring::new(data_dir, Arc::new(queue.clone()))`, then `Documents::new(.., Arc::new(queue.clone()))`, then `pub fn start_workers(n: usize, cfg: ExtractConfig, docs: Arc<Documents>, rx: ExtractReceiver)`.
- **Text extraction (`extract_text`):**
  - **PDFs:**
    1. Run `pdfinfo` to get the page count, capped at `max_pages`.
    2. Run `pdftotext -l {max_pages} -enc UTF-8 in -`.
    3. If there are fewer than 50 non-whitespace chars × pages, run `pdftoppm -r 300 -l {max_pages} -png in {dir}/p` and then `tesseract {page} - -l deu+eng` for each page, in order.
  - **Images:** `tesseract in - -l deu+eng`.
  - **Text files:** `String::from_utf8_lossy`.
  - Use the timeouts from Global Constraints and kill children on timeout.
- **Each worker job:**
  1. Create the per-job dir `{tmp}/{random}` with mode 0700.
  2. Run `decrypt_to_path` and then `extract_text` in `spawn_blocking`.
  3. Call `set_text(Done|Failed|Unsupported)`.
  4. Remove the dir in all paths using a drop guard.
  5. Log only the doc id and the outcome.

- [ ] **Step 1: Write the failing tests in `tests/extract.rs`.** Gate each test with an early return when `which tesseract` fails, printing `SKIP`.
  - `text_pdf_uses_pdftotext`: contains `Kündigungsfrist`, `page_count == Some(1)`
  - `scanned_pdf_falls_back_to_ocr`: contains `Versicherungsnummer`
  - `png_ocr`
  - `corrupt_and_empty_inputs_fail_cleanly`: `corrupt.pdf` and `empty.pdf` → `Err(Failed(_))` or `Ok` with empty text, with no panic
  - `worker_end_to_end`: store `scanned.pdf` via `Documents` with a real `ExtractQueue`, poll up to 60 s for `text_status == Done`, then `search` finds `versicherungsnummer`; afterwards `tmp_dir` is empty
  - `worker_survives_failure`: enqueue `corrupt.pdf` and then `text.pdf`; the second reaches `Done` and the first `Failed`
  - `pending_resumed_on_unlock`: mark a doc `pending` while locked, drop all Arcs, unlock again → it reaches `Done`
- [ ] **Step 2:** Run `cargo test --test extract`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test --test extract`. Expected: PASS (with the tools installed locally; they are present on the dev machine).
- [ ] **Step 5:** Commit: `feat: text extraction and OCR worker`.

---

## Milestone 2: Web UI

### Task 9: Web foundation: state, sessions, CSRF, rate limiting, headers, logging, static assets

**Files:**
- Create: `src/web/mod.rs`, `src/web/session.rs`, `src/web/ratelimit.rs`, `templates/base.html`, `static/app.css`, `static/app.js`, `static/htmx.min.js` (download `https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js` and record its SHA-256 in `static/VENDORED.md`), `tests/common/mod.rs`, `tests/web_foundation.rs`
- Modify: `src/main.rs`. `serve` builds the state, calls `wipe_tmp`, starts the workers, and binds `cfg.bind` with `into_make_service_with_connect_info::<SocketAddr>()`.

**Interfaces:**
- Consumes: everything from Milestone 1.
- Produces:
  - `#[derive(Clone)] pub struct AppState { pub cfg: Arc<Config>, pub sys: Arc<SystemDb>, pub keyring: Arc<Keyring>, pub accounts: Arc<Accounts>, pub docs: Arc<Documents>, pub sessions: Arc<SessionStore>, pub limiter: Arc<RateLimiter>, pub tokens: Arc<TokenCache> }`. In this task, create `src/tokens.rs` with a stub `pub struct TokenCache` that has a no-op `evict(&self, token_id: &str)` and `evict_user(&self, user_id: &str)`. Task 14 fills it in.
  - `pub fn AppState::build(cfg: Config) -> anyhow::Result<AppState>`
  - `pub fn build_app(state: AppState) -> Router`
  - **Session store:**
    - `pub struct Session { pub id: String, pub user_id: String, pub username: String, pub role: Role, pub unlocked: Arc<Unlocked>, pub csrf: String, pub created: Instant, pub last_seen: Instant, pub must_confirm_recovery: Option<RecoveryKey>, pub pending_totp_secret: Option<String> }`. Add `set_pending_totp(&self, id, Option<String>)`.
    - `SessionStore::create(&self, user: &UserRow, unlocked: Arc<Unlocked>, must_confirm: Option<RecoveryKey>) -> (String /*cookie value*/, String /*csrf*/)`. Session ids are 32 random bytes in base64url.
    - `get(&self, id) -> Option<Session-ish clone>`, which applies idle/max expiry and refreshes `last_seen`
    - `confirm_recovery(&self, id)`, `remove(&self, id)` and `remove_user(&self, user_id)`
    - A `sweep()` called every 60 s by a background task
  - **Extractors:**
    - `CurrentUser` (a session without a pending recovery confirmation). If the recovery confirmation is still pending, redirect to `/recovery-key`. If there's no session, redirect to `/login`. For `HX-Request`, return 401 with `HX-Redirect: /login` instead.
    - `PendingUser` (any session)
    - `AdminUser`
  - **CSRF check:** `fn check_csrf(session: &Session, headers: &HeaderMap, form_value: Option<&str>) -> Result<(), StatusCode>`. Also provide a tower middleware that enforces it for all non-GET routes authenticated by cookie. Form bodies are read by handlers, so the middleware only checks the header, and handlers call `check_csrf` with the form field.
  - **Rate limiter:**
    - `pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trusted: IpAddr) -> IpAddr`
    - `RateLimiter::check(&self, keys: &[String]) -> Result<(), Duration /*retry after*/>`
    - `record_failure(&self, keys: &[String])` and `record_success(&self, key: &str)`
  - **Security headers** layer with the values from Global Constraints. Routes can override CSP via a response extension `CspOverride(&'static str)`.
  - **Access log:** a middleware logging `method`, `MatchedPath` (the template, e.g. `/documents/{id}`), status and ms only.
  - **Static files:** served at `/static/*` with `Cache-Control: public, max-age=86400`. All other responses get `Cache-Control: no-store`.
  - **Base template:** contains `<meta name="csrf-token">` and the htmx config meta. `app.js` reads the CSRF token from the meta tag and sets the `X-CSRF-Token` header on `htmx:configRequest` and in a `pmFetch` helper.
  - **Test harness:** `tests/common/mod.rs` provides `TestApp::new() -> TestApp` (a tempdir with `Config::for_tests`), `request(&self, req) -> Response` via `oneshot` with a `ConnectInfo` extension, `signup_and_login(&self, username) -> Client`, where `Client { cookie, csrf }`, and helpers `get(path, &Client)`, `post_form(path, &[(k,v)], &Client)` and `post_multipart(...)`.

- [ ] **Step 1: Write the failing tests in `tests/web_foundation.rs`**
  - `security_headers_present`
  - `unauthenticated_redirects_to_login`
  - `htmx_unauthenticated_gets_hx_redirect`
  - `post_without_csrf_is_403`
  - `session_idle_expiry` (`cfg.session_idle = 1s`, sleep 1.1 s → redirect)
  - `client_ip_trusts_xff_only_from_proxy`
  - `rate_limit_locks_after_10_failures_and_reports_retry_after`
  - `access_log_omits_query_and_path_params`: install a `tracing` capture subscriber, GET `/documents?q=Steuergeheimnis` and `/documents/{some-uuid}`; the captured output contains neither `Steuergeheimnis` nor the uuid
  - `static_assets_cached_pages_not`
- [ ] **Step 2:** Run `cargo test --test web_foundation`. Expected: FAIL.
- [ ] **Step 3:** Implement. A placeholder `/documents` page is fine until Task 11.
- [ ] **Step 4:** Run `cargo test --test web_foundation`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(web): app state, sessions, CSRF, rate limiting, security headers`.

### Task 10: Auth pages and first-admin CLI

**Files:**
- Create: `src/web/auth.rs`, `templates/login.html`, `templates/signup.html`, `templates/recovery_key.html`, `templates/recover.html`, `tests/web_auth.rs`
- Modify: `src/main.rs` (implement `invite --admin`: open the system DB from `PM_DATA_DIR` and print the invite URL)

**Routes:**
- `GET /invite/{token}` shows the signup form. An invalid, used or expired token gives a 404 page with no detail.
  - The form shows the threat-model note, verbatim: "Your files are encrypted with a key only your password or recovery key can unlock. The server operator cannot read them at rest. While you are logged in, the server holds your key in memory to search and OCR your documents. If you lose both your password and your recovery key, your documents are gone for good."
- `POST /invite/{token}`: fields `username`, `password`, `password_confirm`. On success it creates a session with `must_confirm_recovery = Some(key)` and redirects to `/recovery-key`.
- `GET /recovery-key` (`PendingUser`) shows the key once in a `<code>` element, plus a checkbox "I have saved my recovery key" and a submit button. `POST /recovery-key` with the checkbox calls `confirm_recovery` and redirects to `/documents`.
- `GET|POST /login`: fields `username`, `password`, `code` (optional).
  - Rate-limited with keys `ip:` and `user:`.
  - On failure, re-render with "Invalid username, password or code".
  - A disabled account gets "This account is disabled".
- `POST /logout` removes the session.
- `GET|POST /recover`: fields `username`, `recovery_key`, `new_password`, `new_password_confirm`. It's rate-limited like login. On success it gets a session with `must_confirm_recovery = Some(new_key)` and redirects to `/recovery-key`.
- `GET /` redirects to `/documents`.
- Login and signup `POST`s use no CSRF token (there's no session yet). They rely on `SameSite` plus `form-action 'self'`.

- [ ] **Step 1: Write the failing tests in `tests/web_auth.rs`**
  - `full_signup_flow_requires_recovery_confirmation`: after signup, `/documents` redirects to `/recovery-key`; after confirming, it's 200
  - `recovery_key_shown_only_once`: a second GET after confirming redirects
  - `login_logout`
  - `login_with_totp`
  - `recover_flow_then_old_key_invalid`
  - `invite_token_invalid_404`
  - `login_rate_limited_returns_429`
  - `cli_invite_prints_url`: run `cargo run -- invite --admin` via `assert_cmd` with `PM_DATA_DIR`/`PM_PUBLIC_URL`; stdout matches `^https://test.example/invite/[0-9a-f]{64}$`
- [ ] **Step 2:** Run `cargo test --test web_auth`. Expected: FAIL.
- [ ] **Step 3:** Implement. Run Argon2 work through `spawn_blocking`.
- [ ] **Step 4:** Run `cargo test --test web_auth`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(web): signup, login, recovery, logout, invite CLI`.

### Task 11: Documents UI and upload API

**Files:**
- Create: `src/web/docs.rs`, `templates/documents.html`, `templates/_results.html` (htmx partial), `templates/document.html`, `tests/web_docs.rs`
- Modify: `static/app.js` (drag & drop multi-upload), `static/app.css`

**Routes:**
- `GET /documents?q=&tag=&from=&to=&page=` shows the list or search.
  - Requests with an `HX-Request` header return only `_results.html`.
  - The search input uses `hx-get="/documents" hx-trigger="input changed delay:300ms, search" hx-target="#results" hx-push-url="false"`. The URL is never pushed, so queries don't land in history.
  - Snippets are HTML-escaped first, then `\u{2}`/`\u{3}` become `<mark>`/`</mark>`.
- `POST /api/upload` (multipart: `file` (required, one per request), `title`, `tags` (comma-separated), `date`, `on_duplicate=skip|keep`):
  - Auth is either a session plus the `X-CSRF-Token` header, or `Authorization: Bearer pm_…` with `read_write` access (wire the token path in Task 14; until then, session only).
  - Returns JSON `StoreOutcome`. `TooLarge` → 413 and `InvalidDate` → 422.
  - `DefaultBodyLimit` is `max_upload_bytes + 1 MiB`.
- `app.js` drag & drop:
  - Each file is POSTed separately to `/api/upload`, with a per-file status row ("uploading", "stored", "duplicate of {title}" with an "Upload anyway" button, or "error").
  - "Upload anyway" re-posts the same in-memory `File` with `on_duplicate=keep`.
  - When everything has finished, the results are refreshed via `htmx.ajax('GET', '/documents', '#results')`.
- `GET /documents/{id}` shows the detail page:
  - A preview: `<iframe src="/documents/{id}/raw">` for PDFs, `<img>` for images, nothing otherwise.
  - The metadata edit form, extraction status, a retry button if the status is `failed`, a download link and delete (a form with a confirm checkbox; no JS `confirm()` dialogs).
- `GET /documents/{id}/raw`:
  - Served `inline` only when the MIME is one of `application/pdf`, `image/png`, `image/jpeg`, `image/webp` or `image/gif`. Everything else redirects to `/download`.
  - Overrides the CSP to `default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; object-src 'self'; frame-ancestors 'self'` (style is needed by the browsers' built-in PDF viewers) and adds `X-Frame-Options: SAMEORIGIN`.
  - The body streams from `DecryptReader` via `spawn_blocking` and a channel.
- `GET /documents/{id}/download`: `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="{ascii fallback}"; filename*=UTF-8''{percent-encoded}`.
  - ASCII fallback: non-ASCII → `_`; `"`, `\`, `/`, CR and LF → `_`; truncate to 150 chars, keeping the extension.
- `POST /documents/{id}` (edit), `POST /documents/{id}/delete` (requires `confirm=on`) and `POST /documents/{id}/retry`.

- [ ] **Step 1: Write the failing tests in `tests/web_docs.rs`**
  - `upload_list_detail_download_roundtrip`
  - `search_partial_for_htmx`: `HX-Request` → the response contains no `<html`
  - `snippet_is_escaped`: content `<script>alert(1)</script> Vertrag`; the search result shows `&lt;script&gt;` and `<mark>Vertrag</mark>`
  - `html_and_svg_uploads_are_never_inline`:
    - Upload `x.html` with MIME `text/html` and `x.svg` with `image/svg+xml`.
    - `/raw` redirects to `/download`.
    - `/download` has `application/octet-stream` and `attachment`.
  - `content_disposition_handles_hostile_names`: filenames `a"b\r\nc.pdf`, `Prüfung.pdf`, `../../etc/passwd` and a 300-char name each produce a header that parses, contains no CR/LF, and has an ASCII fallback with no `"` inside the quotes
  - `upload_too_large_413` (`max_upload_bytes = 1024`)
  - `duplicate_upload_returns_duplicate_json`
  - `edit_tags_and_title`
  - `delete_requires_confirm`
  - `other_users_document_is_404`: user B requests user A's doc id → 404, because B's index doesn't have it
  - `end_to_end_ocr_search` (tesseract-gated): upload `scanned.pdf`, poll up to 60 s, then search `versicherungsnummer` → hit
- [ ] **Step 2:** Run `cargo test --test web_docs`. Expected: FAIL.
- [ ] **Step 3:** Implement. Keep the upload handler's core in a function `pub async fn handle_upload(state: &AppState, unlocked: Arc<Unlocked>, multipart: Multipart) -> Response` so Task 18 can reuse it. Check the PDF iframe manually in Chrome and Firefox after `cargo run`. If the CSP override blocks the built-in viewer, relax only the raw route's CSP and note why in a code comment.
- [ ] **Step 4:** Run `cargo test --test web_docs`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(web): documents list, search, upload, preview, edit, delete`.

### Task 12: Settings: password, recovery key, TOTP, tokens, export

**Files:**
- Create: `src/web/settings.rs`, `src/export.rs`
- Modify: `src/tokens.rs` (add `create_token` / `revoke_token` here; authentication comes in Task 14), `templates/settings.html`, `templates/token_created.html`, `tests/web_settings.rs`

**Interfaces:**
- Produces:
  - `tokens::create_token(sys: &SystemDb, u: &Unlocked, name: &str, scope: TokenScope, now: i64) -> anyhow::Result<String /* full pm_ token */>`. It writes the system row (`umk` wrapped with `secret_kek(secret, INFO_TOKEN)` and `aad::umk_token(id)`) and the index-DB `TokenMeta`.
  - `tokens::revoke_token(sys: &SystemDb, u: &Unlocked, token_id: &str, cache: &TokenCache) -> anyhow::Result<()>`. It deletes both rows and calls `cache.evict`.
  - `export::write_export<W: Write>(docs: &Documents, u: &Unlocked, out: W) -> anyhow::Result<W>`. It writes a ZIP of stored (uncompressed) entries `files/{safe_name}` plus `metadata.json` (an array of `{id, title, original_filename, zip_path, mime, document_date, tags, created_at}`).
  - **Safe ZIP names:** sanitize as in the Task 11 ASCII rule, but keep UTF-8. Strip every leading `.`, `/` and `\` and all path separators. If the name collides, append ` ({n})` before the extension.
- **Routes:**
  - `GET /settings`
  - `POST /settings/password` (`current`, `new`, `new_confirm`)
  - `POST /settings/recovery` (requires `password`; stores the new key in the session's `must_confirm_recovery` and redirects to `/recovery-key`)
  - `POST /settings/totp/begin`: renders the QR as `<img src="data:image/png;base64,…">` plus the secret text, and keeps the secret in the session
  - `POST /settings/totp/enable` (`code`)
  - `POST /settings/totp/disable` (`code`)
  - `POST /settings/tokens`: `name`, `access`, `content`, plus tag checkboxes `tags[]`. Renders `token_created.html`, which shows the token once along with the Hermes YAML snippet from `docs/setup.md` §7 filled in with `PM_PUBLIC_URL`.
  - `POST /settings/tokens/{id}/revoke`
  - `GET /settings/export.zip`: streamed via `spawn_blocking` writing to a channel-backed `Write`, served as `attachment; filename="personal-media-export.zip"`
- The settings page shows this text verbatim next to "change password": "Changing your password does not protect against someone who already copied a backup of the server."

- [ ] **Step 1: Write the failing tests in `tests/web_settings.rs`**
  - `change_password_flow`
  - `regenerate_recovery_requires_password_and_confirmation`
  - `totp_enable_disable`
  - `create_token_shows_once_and_lists_without_secret`: the settings page contains the token name but not the secret
  - `revoke_token_removes_rows`
  - `export_zip_contains_all_files_and_metadata`
  - `export_zip_entry_names_are_safe_and_unique`: two docs named `../a.pdf` and `a.pdf` → entries `files/a.pdf` and `files/a (2).pdf`, and no entry contains `..` or starts with `/`
  - `token_rows_have_no_plaintext_name_in_system_db`: create a token named `HermesMedical`; the `system.db` bytes don't contain it
- [ ] **Step 2:** Run `cargo test --test web_settings`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test --test web_settings`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(web): settings, TOTP, token management, ZIP export`.

### Task 13: Admin pages

**Files:**
- Create: `src/web/admin.rs`, `templates/admin.html`, `tests/web_admin.rs`

**Routes** (all `AdminUser`):
- `GET /admin`: open invites (hash prefix, role, expiry), and users (username, role, created, disabled, storage used = the sum of file sizes under `users/{id}/`, shown human-readable).
- `POST /admin/invites` (`role`): shows the invite URL once.
- `POST /admin/invites/{prefix}/revoke`
- `POST /admin/users/{id}/disable` and `/enable`
- `POST /admin/users/{id}/delete`: requires the field `confirm_username` to equal the username. An admin can't delete or disable themselves (→ 400).
- Disable and delete call `sessions.remove_user(id)` and `tokens.evict_user(id)`.
- Nav shows "Admin" only for admins.

- [ ] **Step 1: Write the failing tests in `tests/web_admin.rs`**
  - `non_admin_gets_403`
  - `admin_page_never_shows_titles_or_filenames`: user B uploads `Geheimakte.pdf`; the admin page HTML doesn't contain `Geheimakte`
  - `invite_create_and_revoke`
  - `disable_and_delete_kill_sessions_and_tokens`: user B has a live session and a token (create via `tokens::create_token`); after disable, B's cookie redirects to `/login` and (once Task 14 exists) `/mcp` with B's token → 401; after delete, `users/{id}` is gone
  - `admin_cannot_delete_self`
  - `delete_requires_username_confirmation`
- [ ] **Step 2:** Run `cargo test --test web_admin`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test --test web_admin`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(web): admin invites and user management`.

---

## Milestone 3: MCP

### Task 14: Token authentication and MCP server

**Files:**
- Create: `src/mcp.rs`, `tests/mcp.rs`
- Modify: `src/tokens.rs` (`TokenCache`, `authenticate`), `src/web/docs.rs` (bearer auth path for `/api/upload`), `src/web/mod.rs` (mount `/mcp`)

**Interfaces:**
- Produces:
  - `pub struct TokenCache`:
    - It's a map from `token_id` to `(Arc<Unlocked>, last_used: Instant)`, with 5 minutes idle eviction. A background task sweeps it every 60 s.
    - `evict(&self, token_id)` and `evict_user(&self, user_id)`.
  - `pub struct Principal { pub unlocked: Arc<Unlocked>, pub token_id: String, pub scope: TokenScope }`
  - `pub fn authenticate(state: &AppState, bearer: &str) -> Result<Principal, AuthFail>`:
    1. Parse the token format.
    2. Use the cache, or call `sys.token(id)`. On a miss or a disabled user, return `AuthFail`.
    3. Unwrap with `secret_kek` and call `keyring.unlock`.
    4. Load the `TokenMeta` from the index DB. A missing meta → `AuthFail`.
    5. Touch `last_used_at` at most once per 60 s.
  - Rate-limit failures with key `mcp-ip:{ip}`; locked requests get 429. Every failure returns 401 with no detail.
- **MCP:** `rmcp` Streamable HTTP server mounted at `/mcp`, in stateless JSON-response mode if the SDK offers it.
  - An axum middleware authenticates the bearer and inserts `Principal` into the request extensions. Tool handlers read it from rmcp's request context; rmcp exposes the HTTP `Parts` there. Check this against the docs.rs page for the version you install.
  - If rmcp can't pass per-request extensions through, implement a minimal stateless JSON-RPC 2.0 handler for `initialize`, `notifications/initialized`, `tools/list` and `tools/call` with protocol version `2025-06-18`. Note the deviation in the README.
  - Server name: `personal-media`.
- **Tools** (JSON in/out, schemas via `schemars`):
  - `search_documents { query: string, tags?: string[], date_from?: string, date_to?: string, limit?: int ≤ 50 }` → `[{id, title, document_date, tags, filename, snippet?}]`
  - `list_documents { tags?, date_from?, date_to?, limit? ≤ 100, offset? }`
  - `get_document { id }` → metadata plus `text` (only with `full_text`, and the text is truncated to 100 000 chars with `truncated: true`)
  - `list_tags {}`
  - `upload_document { filename, content_base64, title?, tags?, date? }` (`read_write` only; decoded size ≤ `max_upload_bytes`)
  - `update_document { id, title?, tags?, date? }` (`read_write` only)
- **Scope enforcement** (exactly spec §13):
  - `content = MetadataOnly` → `SearchMode::MetadataOnly`, no snippets and no `text`.
  - `scope.tags = Some(ids)` → `ListFilter.tag_allow = Some(ids)` on every read. `get_document` of a doc outside the allow-list → "not found".
  - `list_tags` returns only the allowed tags.
  - `upload_document` attaches the first allowed tag if none of the given tags is allowed.
  - `update_document` rejects a tag set without an allowed tag.
  - Write tools with `Read` access → a tool error "token is read-only".

- [ ] **Step 1: Write the failing tests in `tests/mcp.rs`** (drive the endpoint over HTTP with JSON-RPC bodies)
  - `no_or_bad_token_401`
  - `revoked_token_rejected_immediately` (even though it's cached)
  - `tools_list_has_six_tools`
  - `metadata_only_token_never_returns_text_or_snippets`: the doc content contains `geheim`; `search_documents{query:"geheim"}` → empty; `get_document` → no `text` key
  - `full_text_token_gets_snippets_and_text`
  - `tag_restricted_token_cannot_see_other_documents`: also covers `list_tags` filtering and `get_document` of a hidden doc → not found
  - `read_only_token_cannot_upload`
  - `restricted_upload_gets_allowed_tag`
  - `update_cannot_remove_last_allowed_tag`
  - `bearer_upload_via_api_upload` (`read_write` token)
  - `mcp_auth_failures_rate_limited`
  - `disabled_user_token_401`
- [ ] **Step 2:** Run `cargo test --test mcp`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test --test mcp`. Also re-run `cargo test --test web_admin` (the disable test now covers MCP). Expected: PASS.
- [ ] **Step 5:** Commit: `feat: MCP endpoint with scoped tokens`.

---

## Milestone 4: Recovery CLI and deployment (v1 complete)

### Task 15: `recover` CLI

**Files:**
- Modify: `src/main.rs`
- Create: `tests/cli_recover.rs`

**Behavior:**
- `personal-media recover --data <dir> --user <name> --out <dir> [--recovery-key]` prompts on the TTY (via `rpassword`) for the password, or for the recovery key when `--recovery-key` is set. For tests, it reads the secret from the env var `PM_RECOVER_SECRET` if set.
- It unwraps the UMK directly (it must not need a running server, and it doesn't go through `Accounts` rate limiting). It opens the index DB and writes the same layout as the ZIP export (`files/…` and `metadata.json`) into `--out` by reusing the `export.rs` naming logic.
- It refuses to write if `--out` exists and isn't empty.

- [ ] **Step 1: Write the failing tests**
  - `recover_with_password_writes_all_files`
  - `recover_with_recovery_key`
  - `wrong_secret_exits_nonzero_and_writes_nothing`
  - `refuses_non_empty_out_dir`
- [ ] **Step 2:** Run `cargo test --test cli_recover`. Expected: FAIL.
- [ ] **Step 3:** Implement. Factor the naming logic so `export.rs` exposes `pub fn plan_entries(docs: &[Document]) -> Vec<(String /*doc id*/, String /*relative path*/)>`, used by both.
- [ ] **Step 4:** Run `cargo test --test cli_recover`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(cli): offline recovery`.

### Task 16: Docker, compose, docs

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `README.md`
- Modify: `docs/setup.md` (remove the 🚧 markers for what now exists, fix commands to match reality, add `chown -R 10001:10001 /DATA/personal-media`)

**Dockerfile:**
- **Stage 1:** `rust:1.98-trixie`, which installs `tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng poppler-utils` so `cargo test` runs the OCR tests. Build with `cargo build --release --locked` and run `cargo test --release --locked`.
- **Stage 2:** `debian:trixie-slim` with the same runtime packages plus `ca-certificates`, and user `pm` (uid/gid 10001). The binary goes to `/usr/local/bin/personal-media`, with `ENTRYPOINT ["personal-media"]`, `CMD ["serve"]` and `ENV PM_DATA_DIR=/data`.
- Use a cargo dependency-caching layer: copy the manifests and build dummy sources first.
- **Compose:** exactly the block in `docs/setup.md` §3 (host network, `127.0.0.1:8080`, `tmpfs /data/tmp`), plus `user: "10001:10001"`.
- **README:** what the project is, a link to the spec and setup guide, the threat model in 5 bullet points, and dev commands.

- [ ] **Step 1:** Run `docker build -t personal-media .`. Expected: success, including the test stage with the OCR tests not skipped (grep the build log for `SKIP` → none).
- [ ] **Step 2:** Smoke test:
  1. `docker run -d --name pm-smoke --network host -e PM_PUBLIC_URL=https://test.example -e PM_BIND=127.0.0.1:18080 -v $(mktemp -d):/data --tmpfs /data/tmp personal-media`
  2. `curl -sI http://127.0.0.1:18080/login` → `200` with the CSP header.
  3. `docker exec pm-smoke personal-media invite --admin` prints a URL.
  4. Check `docker stats --no-stream pm-smoke`: memory is under 60 MiB idle.
  5. `docker rm -f pm-smoke`.
- [ ] **Step 3:** Commit: `build: Dockerfile, compose, README; update setup guide`.

**v1 checkpoint:** run `cargo test` and the Docker build. Report to the owner that v1 is ready for deployment before starting Milestone 5.

---

## Milestone 5: v1.1 (installable PWA + share target)

### Task 17: Installable PWA (manifest, icons, app-shell service worker)

**Files:**
- Create: `src/web/pwa.rs`, `static/sw.js`, `static/icons/icon-192.png`, `icon-512.png`, `icon-maskable-512.png` (generate a simple monogram "PM" icon with ImageMagick; commit the PNGs), `templates/offline.html` (a static file copy goes to `static/offline.html`), `tests/web_pwa.rs`
- Modify: `templates/base.html` (`<link rel="manifest">`, `theme-color`, apple-touch-icon; `app.js` registers `/sw.js`)

**Behavior:**
- `GET /manifest.webmanifest` (`application/manifest+json`): `name` "Personal Media", `short_name` "Media", `start_url` "/documents", `scope` "/", `display` "standalone", theme and background colors from `app.css`, and the three icons.
- `GET /sw.js`: served from root scope with `Cache-Control: no-cache` and `Service-Worker-Allowed: /`.
  - It precaches exactly `/static/app.css`, `/static/app.js`, `/static/htmx.min.js`, `/static/icons/*` and `/static/offline.html`.
  - Fetch handler: cache-first for those precached URLs only. Every other request goes to the network with no caching at all. Navigation failures fall back to `/static/offline.html`.
  - The cache name includes a version constant. Old caches are deleted on activate.

- [ ] **Step 1: Write the failing tests in `tests/web_pwa.rs`**
  - `manifest_valid_json_with_required_fields`
  - `sw_served_with_scope_header`
  - `sw_precache_list_contains_only_static_paths`: parse the `PRECACHE` array literal in `sw.js`; every entry starts with `/static/`
  - `sw_has_no_cache_put_outside_precache`: `cache.put` / `cache.add` only appear in the install handler (a string check)
  - `authenticated_pages_are_no_store`
- [ ] **Step 2:** Run `cargo test --test web_pwa`. Expected: FAIL.
- [ ] **Step 3:** Implement. Verify manually with Chrome DevTools → Application: the app is installable and the Cache Storage holds only static assets after browsing documents.
- [ ] **Step 4:** Run `cargo test --test web_pwa`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(pwa): installable app with app-shell-only service worker`.

### Task 18: Share target with review page, iOS Shortcut docs

**Files:**
- Modify: `src/web/pwa.rs`, `src/web/session.rs` (`SharedStaging`), `src/web/docs.rs` (reuse `handle_upload` logic), the manifest
- Create: `templates/share_review.html`, `docs/ios-shortcut.md`, `tests/web_share.rs`

**Behavior:**
- **Manifest:** `"share_target": { "action": "/share", "method": "POST", "enctype": "multipart/form-data", "params": { "title": "title", "text": "text", "files": [{ "name": "files", "accept": ["application/pdf", "image/*", "text/plain"] }] } }`.
- **`POST /share`** (no CSRF, because the OS posts it):
  - It parses the multipart into `SharedStaging`: an in-memory map `staging_id → { user_id: Option<String>, files: Vec<(filename, mime, Bytes)>, title, created: Instant }`.
  - Limits: total ≤ `max_upload_bytes`, otherwise 413. Expiry is 15 minutes, swept every 60 s, and a global cap is 4 × `max_upload_bytes`.
  - It never writes to disk.
  - With a valid session it redirects 303 to `/share/{staging_id}`. Without one, it sets the cookie `pm_continue={staging_id}` (`HttpOnly; Secure; SameSite=Lax; Max-Age=900`) and redirects to `/login`. After login, `pm_continue` redirects to `/share/{id}` and the cookie is cleared.
- **`GET /share/{id}`** (`CurrentUser`; the staging entry is bound to the first user who opens it and is 404 for anyone else): lists the files with title and tag inputs and a CSRF form. `POST /share/{id}` stores each file through the same `Documents::store` path as `/api/upload` and redirects to `/documents`. `POST /share/{id}/discard` drops it.
- **Session cookie:** if the manual test in Step 3 shows Android Chrome doesn't send `pm_session` on the share POST, switch `pm_session` to `SameSite=Lax`. CSRF tokens stay mandatory. Record the outcome in a code comment and in `docs/setup.md`.
- **`docs/ios-shortcut.md`:** step-by-step instructions for an iOS Shortcut "Share to Personal Media":
  - It receives Files/Images from the share sheet.
  - It sends "Get Contents of URL" `POST {PM_PUBLIC_URL}/api/upload` with `Authorization: Bearer pm_…` (a `read_write` token, ideally tag-restricted to a tag such as `inbox`) and a multipart field `file`.
  - It shows the result.
  - It also notes that the token sits on the phone, and how to revoke it.

- [ ] **Step 1: Write the failing tests in `tests/web_share.rs`**
  - `share_with_session_redirects_to_review_and_saves`
  - `share_without_session_continues_after_login`
  - `share_post_cannot_store_without_review`: after `POST /share` the user's doc count is unchanged
  - `staged_share_is_bound_to_one_user`
  - `staged_share_expires`: set an injectable clock or a 1 s TTL in test config → 404
  - `share_too_large_413`
  - `share_never_touches_disk`: during staging, a recursive scan of `data_dir` finds no new files
- [ ] **Step 2:** Run `cargo test --test web_share`. Expected: FAIL.
- [ ] **Step 3:** Implement. Then test manually on an Android phone through the Funnel URL: install the PWA, share a PDF from the Files app, review and save. Record the `SameSite` result.
- [ ] **Step 4:** Run `cargo test`. Expected: all PASS.
- [ ] **Step 5:** Commit: `feat(pwa): share target with review page; iOS Shortcut guide`.
