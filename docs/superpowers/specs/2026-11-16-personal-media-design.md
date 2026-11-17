# Personal Media — Design

Date: 2026-11-16
Status: approved 2026-11-16

## 1. Intent

A small, self-hosted vault for important personal documents (contracts, IDs, invoices, letters) for the owner and a few friends. Documents are easy to upload, searchable by their text (including OCR), and reachable by AI agents such as Hermes through MCP.

The defining requirement: **the person running the server must not be able to read other users' documents.** Each user's data is encrypted with keys only they can unlock.

Existing tools fall short. Paperless-ngx stores documents unencrypted, and EveryDocs has per-user encryption but no search for encrypted users. Papra, Teedy and Docspell each cover part of this. None combines per-user encryption with full-text search and MCP.

## 2. Goals (v1)

- Invite-only multi-user accounts with per-user encryption. The admin manages accounts but cannot decrypt user data.
- A simple web UI: upload (multi-file, drag & drop), list, view/download, edit title/tags/date, delete, and search.
- Automatic text extraction and OCR (German + English) for PDFs and images.
- Full-text keyword search with snippets, filterable by tag and date.
- An MCP endpoint for agents (Hermes etc.), authenticated by per-user tokens.
- Per-token privacy settings that control what each agent may see (this is v1's form of "what info is sent to which plugin").
- Public access via Tailscale Funnel, with TLS terminated on the ZimaBoard.
- Users can export all their documents decrypted, and a CLI can recover data with a recovery key if the web app is unavailable.

## 3. Non-goals (v1)

- Local AI (Ollama, auto-tagging). Semantic search comes in v1.2 (§17a).
- Sharing documents between users.
- Email ingestion, watched/scanner folders, WebDAV.
- Native mobile app, versioning, collaborative editing. (Installable PWA and share target come in v1.1, see §17.)
- In-app backup. Backups are done externally (e.g. restic) on the already-encrypted data directory.

## 4. Anti-goals (failure even if it "works")

- Any plaintext user content, filename, tag or extracted text on disk. This includes temp files that outlive processing and search indexes.
- Any server-side key, config or admin feature that lets the admin decrypt a user's data.
- Traffic decrypted by a third party in transit (hence no Cloudflare Tunnel for this app).
- A heavy stack. The target is a single small binary in one container, idling at tens of MB of RAM on an Intel N150.
- Open registration on a public URL.

## 5. Threat model (be explicit with users)

The design protects against:
- Someone with the disks, the data directory or a backup, including the admin. They see only ciphertext plus coarse metadata: number of documents, ciphertext sizes, file timestamps, usernames.
- The admin browsing via the admin UI. It never shows content.
- Tailscale's relays, which only see TLS-encrypted traffic.

The design does **not** protect against:
- An admin who modifies the server code or reads process memory while a user is logged in. OCR and search run server-side, so keys must be in server memory while unlocked. This is accepted and must be stated in the UI (e.g. on the signup page).

A forgotten password **plus** a lost recovery key means the data is unrecoverable. Signup must make the user acknowledge this.

## 6. Deployment

- **Host:** ZimaBoard (ZimaOS, Docker, Intel N150), with data on the 6 TB redundant pool.
- **Container:** one `personal-media` container from a multi-stage Dockerfile: Rust build stage, then a slim Debian runtime with `tesseract-ocr`, `tesseract-ocr-deu`, `tesseract-ocr-eng` and `poppler-utils` (pdftotext, pdftoppm).
- **Networking (decided):** the owner's Tailscale container runs with `network_mode: host` (ZimaBoard LAN is 10.5.1.1/8). The app container also uses `network_mode: host` and binds `PM_BIND=127.0.0.1:8080`, so only local processes (Tailscale) can reach it. Nothing on the LAN can reach it directly. Tailscale connects from 127.0.0.1, which matches the default `PM_TRUSTED_PROXY`.
- **Client IP (verified in Tailscale source `ipn/ipnlocal/serve.go`):** Funnel overwrites `X-Forwarded-For` with the real public client IP (a single address, not a list) and sets `Tailscale-Funnel-Request: ?1`. Trust `X-Forwarded-For` only when the TCP peer is `PM_TRUSTED_PROXY`. Funnel's proxy target must be `http://127.0.0.1:<port>`, which is another reason for host networking. Setup steps are in `docs/setup.md`.
- **Compose:** the provided `docker-compose.yml` uses `build:` so `docker compose up -d --build` works directly on the ZimaBoard. A registry/CI image is optional later.
- **Volume:** `/data` maps to a directory on the 6 TB pool.
- **Public access:** the owner's existing Tailscale container runs `tailscale funnel --bg --https=443 http://<target>:8080` (or the `TS_SERVE_CONFIG` equivalent; `--https=8443` if 443 is already used on that node). The public URL is `https://<node>.<tailnet>.ts.net`, given to the app as `PM_PUBLIC_URL`.
- **Other services:** Cloudflare Tunnel stays in place for other services and is not used for this app.
- **Configuration (env):**
  - `PM_DATA_DIR` (default `/data`)
  - `PM_BIND` (default `127.0.0.1:8080`)
  - `PM_PUBLIC_URL`
  - `PM_MAX_UPLOAD_MB` (default 100)
  - `PM_SESSION_IDLE_MINUTES` (default 30)
  - `PM_SESSION_MAX_HOURS` (default 12)
  - `PM_TRUSTED_PROXY` (default `127.0.0.1`; source of `X-Forwarded-For` for rate limiting)

## 7. Technology (decided: Rust)

| Concern | Choice |
|---|---|
| Web/HTTP | `axum` + `tokio` |
| HTML | `askama` templates compiled in, `htmx` (vendored, served locally), minimal hand-written CSS, no JS build step |
| System DB | SQLite via `rusqlite` |
| Per-user DB | SQLCipher via `rusqlite` feature `bundled-sqlcipher-vendored-openssl`, with FTS5 for search |
| KDF | `argon2` (Argon2id) |
| File/key encryption | `chacha20poly1305` (XChaCha20-Poly1305), chunked STREAM construction for files |
| Token key derivation | `hkdf` + `sha2` |
| TOTP | `totp-rs` |
| MCP | `rmcp` (official Rust SDK), Streamable HTTP transport at `/mcp` |
| OCR / text | `pdftotext`, `pdftoppm` and `tesseract` CLIs invoked as subprocesses |
| Randomness | OS CSPRNG (`rand::rngs::OsRng` / `getrandom`) |

The builder may substitute equivalent crates if one turns out unsuitable. The constraints are: no unencrypted search index, and RustCrypto (or equally audited) primitives only.

## 8. Encryption hierarchy

```
Password ──Argon2id(salt)──► PasswordKEK ─┐
Recovery key (random 256-bit) ──HKDF────► RecoveryKEK ─┤  each wraps (XChaCha20-Poly1305)
MCP token secret (random 256-bit) ─HKDF─► TokenKEK ────┘  the same:
                                                  ▼
                                   User Master Key (UMK, random 256-bit)
                                   ┌──────────────┴───────────────┐
                                   ▼                              ▼
                       Document Data Key (DEK)          Index DB key
                       random per document,             random, wrapped by UMK;
                       wrapped by UMK, stored in        opens users/<id>/index.db
                       the user's index DB              (SQLCipher)
```

- **Argon2id parameters:** m = 64 MiB, t = 3, p = 1, with a 16-byte random salt per user. Store the parameters with each wrap so they can be raised later.
- **Wrapping:** every wrapped key stores `{version, nonce, ciphertext}`. Use associated data that binds the wrap to its purpose and owner (e.g. `"pm/v1/umk/password/<user_id>"`) so wraps can't be swapped between users or slots.
- **Stored in the system DB** (plaintext SQLite): user id, username, role, Argon2 salt/params, the UMK wrapped by the password, the UMK wrapped by the recovery key, the index-DB key wrapped by the UMK, TOTP secret (wrapped by the UMK; see §9), and for each token only `token_id → user_id` plus the UMK wrapped by that token.
- **Stored in the encrypted index DB, not the system DB:** token name, scope (access, content level, tag allow-list by tag id), created and last-used timestamps. The server checks a token's scope after unlocking. Because the index DB is authenticated, the scope can't be edited at rest. *(Builder-check decision, my call.)*
- **Password verification** is done by successfully unwrapping the UMK. No separate password hash is stored.
- **No master-key rotation in v1** *(my call)*. Changing the password re-wraps the UMK only. Limitation: someone who already holds an old `system.db` backup and later learns the old password or recovery key can still unwrap the UMK. Settings must say this plainly ("changing your password does not protect against someone who already copied a backup"). A "rotate keys" action is listed under Later: it creates a new UMK, re-wraps the index key and all DEKs, rekeys SQLCipher, and revokes all tokens, since token wraps can't be rebuilt without the token secrets.
- **Changing the password** re-wraps the UMK only. **Regenerating the recovery key** creates a new key and replaces that wrap. **Revoking a token** deletes its row and its wrap.
- **Recovery key format:** shown once at signup (and on regeneration) as a base32 or BIP39-style string, e.g. 24 words or grouped base32. Signup can't finish until the user confirms they saved it.
- **Index DB key:** a separate random key wrapped by the UMK, so the UMK itself is never handed to SQLCipher.
- **Files:**
  - Each document gets a random DEK. The file is encrypted with the XChaCha20-Poly1305 STREAM construction (64 KiB chunks, last-chunk flag) so large files never need to fit in memory.
  - Blobs are stored at `users/<user_id>/blobs/<random_uuid>`. Filenames, MIME type, size, hash, tags and text live only inside the encrypted index DB.
- **Duplicate detection:** the SHA-256 of the plaintext is stored inside the encrypted index DB and checked per user on upload. On a duplicate, warn the user and let them choose to keep both or skip.
- **Room for later:**
  - A per-user X25519 key pair (private key wrapped by the UMK) to support sharing and "inbox" ingestion without an unlocked session. Not built in v1. It can be generated lazily at a later login.
  - WebAuthn PRF as another UMK wrap.

## 9. Key lifetime and sessions

- **Recovery-key login** *(my call)*: the recovery key works like a 2FA backup code and skips TOTP. It only allows setting a new password. The user then gets a new recovery key, which replaces the old one, and must confirm saving it before a normal session starts. It shares the login rate limits.
- **Login:**
  1. Unwrap the UMK with the password.
  2. If TOTP is enabled, also verify the TOTP code. The TOTP secret is wrapped by the UMK, so it can only be checked after the password step. That's fine, because a wrong password already fails.
  3. Create a server-side session in an in-memory store, holding the UMK and the open index-DB handle, and set an opaque session cookie (`HttpOnly`, `Secure`, `SameSite=Strict`).
- **Keyring:** an in-memory map `user_id → unlocked state {UMK, index DB connection}`, reference-counted by active sessions, MCP requests and running processing jobs. When the count reaches zero, the key material is zeroized (`zeroize` crate) and the DB connection is closed.
- **Sessions:**
  - Idle timeout and absolute maximum come from config.
  - Logout drops the session immediately.
  - A server restart drops all sessions, so users log in again. This is acceptable.
- **MCP requests:**
  - The bearer token is `pm_<token_id>_<secret>`. The server looks up `token_id`, derives the TokenKEK from the secret via HKDF and unwraps the UMK.
  - The keyring entry is cached for a short time (e.g. 5 minutes idle) so consecutive agent calls don't re-derive keys.
  - The secret is high-entropy, so no Argon2 is needed.
- **Processing jobs** (text extraction/OCR) hold a keyring reference while they run, so a job finishes even if the user logs out mid-processing. Jobs that couldn't run (e.g. after a restart) stay marked `pending` in the index DB and resume the next time that user is unlocked.

## 10. Data layout

```
/data/
  system.db                 # accounts, wrapped keys, invites, tokens (plaintext SQLite, no user content)
  users/<user_id>/
    index.db                # SQLCipher: documents, tags, extracted text, FTS5, settings
    blobs/<uuid>            # encrypted document files
  tmp/                      # processing scratch (see below)
```

Index DB schema (indicative, refine during planning):
- `documents`: id, blob_id, wrapped_dek, original_filename, title, mime, size, sha256, document_date, created_at, updated_at, text_status (`pending|done|failed|unsupported`), page_count
- `document_text`: document_id, content
- `documents_fts`: FTS5 over title, filename, tags, content, using the `unicode61 remove_diacritics 2` tokenizer so German umlauts work
- `tags`, `document_tags`
- `settings`: key/value per user

**Temp files during OCR:** the external tools need files. Decrypted content is written to a per-job directory under `/data/tmp`, created with mode 0700 and deleted when the job ends, including on error. At startup the server wipes any leftover `/data/tmp`. Prefer a tmpfs mount for `/data/tmp` in compose (e.g. `tmpfs: /data/tmp:size=512m`) so plaintext never reaches the disk. This is the one place plaintext briefly exists outside process memory, and it should be documented.

## 11. Text extraction pipeline

Runs as a background task in the same process, using a bounded worker pool (default 1–2 concurrent jobs to fit the N150).

- **PDF:** run `pdftotext`. If the result is roughly empty (scanned PDF), render pages with `pdftoppm -r 300` and OCR each page with `tesseract -l deu+eng`.
- **Images** (PNG, JPEG, TIFF, WebP): `tesseract -l deu+eng`.
- **Plain text / Markdown:** store as is (UTF-8, lossy).
- **Anything else:** store it encrypted, mark it `unsupported`, and keep it searchable by filename, title and tags only.

Each job updates `text_status` and writes the text into `document_text` and FTS. Timeouts and page limits (e.g. 200 pages) stop pathological files from tying up the box.

## 12. Web UI

Server-rendered pages enhanced with htmx and kept minimal:

- **Login**, including TOTP when enabled and a "use recovery key" link that leads to setting a new password.
- **Signup via invite link:** choose username and password, read the threat-model note, save the recovery key and confirm.
- **Documents:** list (newest first), search box with live results and snippets, filters for tag and date range, drag & drop multi-upload with per-file status.
- **Document detail:** inline preview for PDFs and images, served decrypted with `Content-Disposition: inline`; download; edit title, tags and document date; delete with confirmation; extraction status with a "retry" button.
- **Settings:** change password, regenerate recovery key, enable/disable TOTP, manage MCP tokens (create, name, set scope, see last used, revoke), export all documents as a ZIP.
- **Admin** (role `admin`): create invite links (single-use, expiring after 7 days), list users (username, role, created, storage used), delete a user (removes their whole directory), disable a user. No access to content.
- **Bootstrapping the first admin:** run `docker exec personal-media personal-media invite --admin`, which prints an invite URL.

## 13. MCP interface

Streamable HTTP endpoint at `POST /mcp`, using a bearer token from the user's settings. Example Hermes config:

```yaml
mcp_servers:
  personal-media:
    url: https://<node>.<tailnet>.ts.net/mcp
    headers:
      Authorization: "Bearer pm_..."
```

**Tools in v1:**
- `search_documents(query, tags?, date_from?, date_to?, limit?)` → id, title, date, tags, snippet
- `list_documents(tags?, date_from?, date_to?, limit?, offset?)`
- `get_document(id)` → metadata, plus extracted text if the scope allows
- `list_tags()`
- With write scope only: `upload_document(filename, content_base64, title?, tags?, date?)` and `update_document(id, title?, tags?, date?)`

**Token scope (the per-plugin privacy settings), set when creating a token in the UI:**
- `access`: `read` (default) or `read_write`
- `content`: `metadata_only` (title, tags, date, filename) or `full_text` (also snippets and extracted text). The default is `metadata_only`.
- `tags`: optional allow-list. If set, the token only sees documents carrying at least one of these tags.

**Scope rules** *(my calls)*:
- With a `metadata_only` token, `search_documents` matches only title, filename and tags (an FTS5 column filter), never the extracted text. That way the search can't reveal content.
- With a tag-restricted token:
  - `list_tags` returns only the allowed tags.
  - `upload_document` must carry at least one allowed tag. If none is given, the first allowed tag is attached automatically.
  - `update_document` can't remove a document's last allowed tag.
  - New tags may be created.
- File downloads via MCP are not offered in v1. Agents get text, never the original binaries.

## 13a. Access switchboard (v1)

Each user decides, per **access channel**, how much of a document that channel may reveal. There's a per-user default, and each document can override it.

- **Channels:**
  - v1: `web` and `mcp`
  - v1.2: `semantic_index` (whether a document's content is embedded for meaning-based search, §17a)
  - Future channels (WebDAV, sharing, external AI) are added to the same table and default to `off` until the user enables them.
- **Levels:** `off`, `metadata` (title, tags, date, filename, type, size) and `full` (also content: extracted text, snippets, preview/download, and later semantic matches).
- **User defaults** live in Settings, shown as one row per channel with three options. Initial defaults *(my call)*: `web = full`, `mcp = metadata`, `semantic_index = off`. Opting in to new kinds of processing is a deliberate step.
- **Per-document overrides** appear on the document detail page, where each channel can be `default`, `off`, `metadata` or `full`. Upload accepts the same overrides as optional fields.
- **Effective access** for a request = `min(document level for that channel, the caller's own limit)`, where the caller's limit is the token scope for MCP and `full` for the owner's web session. Example: a `full_text` token reading a document set to `mcp = metadata` gets metadata only.
- **Search follows the effective level per document:**
  - Documents at `metadata` match only on title, filename and tags, with no snippet.
  - Documents at `off` are invisible to that channel (list, search, get, tags).
  - These are filters inside the query, not post-filters, so counts and ranks don't leak hidden content.
- **Storage:** defaults go in `settings` and overrides in a `document_access(document_id, channel, level)` table, both inside the encrypted index DB.
- **`web = off` semantics:** **OPEN, owner to decide**: hidden from the web UI entirely, or listed but locked behind re-entering the password, or `off` not allowed for `web`.

## 13b. OAuth for MCP (v1.4, approved by owner 2026-11-17)

Clients: **claude.ai custom connectors** and **Hermes** (`auth: oauth`). Static `pm_…` tokens keep working.

**User flow**
- The user adds `{PM_PUBLIC_URL}/mcp` as a connector.
- The client opens PMS's `/oauth/authorize` in the browser. The user logs in if needed.
- A consent page shows "{client name} wants access to your documents" and the redirect URI's host, prominently. The user picks:
  - read or read+write
  - metadata only or full text
  - an optional tag restriction (existing or new tag)
- On approval, the client is connected. Settings → **Connected apps** lists each grant (client name, scope, created, last used) with a Revoke button.

**Protocol** (Claude connector requirements + MCP authorization spec)
- An unauthenticated or invalid request to `/mcp` gets `401` with `WWW-Authenticate: Bearer resource_metadata="{PM_PUBLIC_URL}/.well-known/oauth-protected-resource"`.
- Protected resource metadata (RFC 9728): `resource` = `{PM_PUBLIC_URL}/mcp` exactly; `authorization_servers` = [`{PM_PUBLIC_URL}`]; `scopes_supported`.
- Authorization server metadata (RFC 8414) at `/.well-known/oauth-authorization-server`:
  - `registration_endpoint`
  - `code_challenge_methods_supported: ["S256"]`
  - `token_endpoint_auth_methods_supported: ["none"]`
  - grant types `authorization_code` and `refresh_token`
  - `scopes_supported` including `offline_access`
  - `client_id_metadata_document_supported` **not** advertised (see below)
- Dynamic Client Registration (RFC 7591) for public clients only.
- Authorization code + PKCE S256 is mandatory; `state` is passed through.
- `/oauth/token` accepts `application/x-www-form-urlencoded`. Refresh tokens rotate; an invalid one returns `invalid_grant`.
- Revocation endpoint (RFC 7009).
- Discovery, registration and token responses must be fast (< 1 s server-side); Anthropic gives them 10 s end to end.

**No outbound requests:** only DCR is supported, not Client ID Metadata Documents. CIMD would make PMS fetch client metadata from the internet, and both Claude and Hermes fall back to DCR.

**Redirect URIs allowed at registration**
- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`
- loopback `http://127.0.0.1:{any}/…` and `http://localhost:{any}/…` (Hermes, Claude Code)
- any HTTPS host listed in `PM_OAUTH_EXTRA_REDIRECT_HOSTS` (comma-separated)

Everything else is rejected at registration and again at authorize.

**Key handling (keeps §5's promise)**
- At consent the user is unlocked. PMS generates a refresh secret and an access secret and wraps the UMK under each, exactly like `pm_` tokens (`secret_kek`, AAD bound to the token id).
- Access tokens live 1 hour. Refresh tokens live 30 days and are single-use: refreshing unlocks with the refresh secret, issues a new pair, and deletes the old rows.
- The authorization code maps, in memory only, to the freshly minted pair for 60 s. It's single-use and bound to `client_id`, `redirect_uri` and the PKCE challenge.
- Grant metadata (client id and name, scope, tag allow-list, timestamps) lives in the user's encrypted index DB, next to `pm_` token metadata.
- `system.db` holds only token id → user id, the wrap, expiry, kind and grant id.

**Abuse limits**
- DCR is rate-limited per IP: 10 per hour.
- At most 200 registered clients; clients without a grant are pruned after 24 h.
- The authorize and consent pages require a session and CSRF, and cannot be framed.

## 14. Security hardening (required because the app is public)

- Invite-only registration, with no other signup path.
- Rate limiting per client IP and per username on login, recovery and the MCP auth failure path, e.g. exponential backoff and a temporary lock after 10 failures. Client IP comes from `X-Forwarded-For` only when the request is from `PM_TRUSTED_PROXY`.
- CSRF protection: `SameSite=Strict` cookies plus a per-session CSRF token on all state-changing form/htmx requests.
- Security headers: strict CSP (`default-src 'self'`, no inline scripts), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`, HSTS.
- The upload size limit is enforced while streaming.
- Usernames are the only user-identifying data in the system DB. Logs must never contain filenames, titles, tags, search queries, document text or token secrets.
- The admin cannot change another user's password. That would be pointless, because it can't re-wrap the UMK.

## 15. Recovery and export

- **Web export:** "Download all" streams a ZIP of every decrypted original plus a `metadata.json` (titles, tags, dates).
- **CLI recovery:** `personal-media recover --data /data --user <name> --out <dir>` asks for the password or recovery key and writes all decrypted files and metadata. It works without the web server running and serves as the disaster-recovery path and proof that backups are usable.

## 16. Testing expectations

- Unit tests for every crypto path: wrap/unwrap for each slot, wrong-key failure, AAD mismatch failure, STREAM encryption round trip including empty files and exact chunk-boundary sizes, and truncation/reorder detection.
- Integration tests through the HTTP layer:
  - invite → signup → login → upload → search finds OCR'd text → logout
  - password change keeps data accessible
  - recovery-key login works
  - a revoked token is rejected
  - a `metadata_only` token never returns text or snippets
  - tag-restricted tokens can't see other documents
- An "at rest" test that scans the data directory after uploads and asserts that known plaintext strings (filename, text) appear nowhere.
- OCR tests may be gated on the presence of `tesseract`. The Docker build runs them.

## 17. Next update (v1.1): installable app + "Share to Personal Media"

This is the first milestone after v1 and is planned as part of the same plan, right after v1 is working. Owner's reasoning: sharing straight from the phone "improves usability dramatically".

**Goals:**
- **Installable (PWA):**
  - A web app manifest (name, icons, `display: standalone`, theme colors) so the site installs to the home screen on Android, iOS and desktop.
  - A service worker that caches **only the app shell** (CSS, JS, icons, offline notice). It must never cache document content, previews, search results or any authenticated response, because decrypted data must not persist on devices. Authenticated responses also carry `Cache-Control: no-store`.
- **Share target:**
  - The manifest declares `share_target` (`POST`, `multipart/form-data`, accepting `application/pdf`, `image/*`, `text/plain`), so "Share → Personal Media" on a phone hands files to the app.
  - The shared files go to a **review page**, not straight into the vault. There the user sees the files, can set a title and tags, and presses Save. Saving uses the normal CSRF-protected upload. This also stops cross-site POSTs from silently adding files to the vault.
  - Shared files waiting for review are held only in server memory (bounded size, e.g. the max upload size, and a 15-minute expiry), never on disk unencrypted.
  - If the session has expired, the user logs in and then lands on the review page with the files still waiting.
  - The session cookie must be sent when the OS launches the share target. If `SameSite=Strict` blocks that, the builder may relax the session cookie to `SameSite=Lax`. CSRF tokens stay mandatory on all state-changing requests, and the share POST itself only stages files.
- **iPhone caveat:** iOS Safari doesn't support Web Share Target, so the share-sheet entry only appears on Android (Chrome/Edge) and desktop Chromium. For iPhone, the fallback is a documented **iOS Shortcut** ("Share to Personal Media") that posts the shared file to an upload API using a write-scoped token, plus normal upload in the installed PWA.

**v1 must keep this cheap to add:** same-origin static assets, no inline scripts (already required by the CSP), responsive layouts, and an upload code path that the review page can reuse.

## 17a. Near-future update (v1.2): semantic search via MCP

Meaning-based search over each user's documents, exposed through MCP so that **each user brings their own agent** (Hermes, Claude, anything MCP-capable). The vault provides retrieval; the user's chosen agent does the reasoning. No chat or LLM is built into the app.

- **Embeddings are computed inside the app on the ZimaBoard** *(my call)*. No document text leaves the box, so there is no new party to trust. Ollama on Proxmox would let the Proxmox admin see friends' plaintext.
- **The model** must be:
  - small, multilingual (German + English), CPU-only, run in-process (e.g. ONNX via `ort`/`fastembed`, or `candle`)
  - at most ~150 MB quantized
  - stored in `/data/models` (not user data), downloaded once from a pinned URL and verified against a pinned SHA-256; not baked into the image (GHCR free private storage is 500 MB) *(Ruling U, 2026-11-17)*
  - loaded lazily and unloaded after 10 minutes idle, so the idle footprint stays small; memory while embedding of a few hundred MB is acceptable
  - Exact model choice is left to the builder, after a short benchmark on the N150.
- **Indexing:**
  - After text extraction, documents whose effective `semantic_index` level is `full` are split into chunks of about 300 tokens with overlap, embedded in the background worker (same keyring rules as OCR) and stored as `chunk_vectors(document_id, chunk_no, text_offset, vector BLOB)` in the encrypted index DB.
  - Changing the switchboard to below `full` deletes that document's vectors immediately.
  - Changing the model triggers a background re-embed.
- **Search:** brute-force cosine similarity over the user's vectors. That's thousands of vectors per user, so it takes milliseconds and needs no vector-database server. It can be combined with FTS (hybrid ranking) for the web UI later.
- **Privacy:**
  - Embeddings can be partially inverted back to text, so they get exactly the same protection as text: encrypted at rest and only usable while unlocked.
  - Semantic matching reveals content, so it is only used for documents whose effective `mcp` level is `full` **and** only for tokens with `full_text` scope. `metadata` access never touches vectors.
- **MCP tool:** `semantic_search { query, tags?, date_from?, date_to?, limit? ≤ 20 }` → `[{id, title, document_date, tags, score, passage}]`. `passage` is the matching chunk text, subject to the switchboard and token scope as above.

## 18. Later

- Ollama/external AI (auto-tagging, summaries) as a new switchboard channel, off by default and opted into per user and per document.
- Sharing between users via X25519.
- Email/scanner inbox using the public key.
- Outgoing email (e.g. invite links, notifications), if ever needed: use the owner's existing Resend setup for `mail.sebis.net`. Emails must never contain document content or metadata.
- WebDAV, passkeys (WebAuthn PRF), and a separate `docs.` Tailscale node name.
- Key rotation (see §8).
- **Custom domain** (instead of `*.ts.net`). Options are in `docs/setup.md` §10. The preferred route is Tailscale Funnel's own custom-domain support once it ships; until then, a small VPS that forwards the still-encrypted connection to the ZimaBoard.

## 19. Process

Implementation is delegated to Sonnet subagents (subagent-driven development) following a written plan.
