# Personal Media

A document vault with per-user encryption, written in Rust. Users upload scans and PDFs, the server
OCRs them (German and English) and makes them searchable, and everything is stored encrypted with
a key derived from each user's password. It runs as a single Docker container on a ZimaBoard and
is published through Tailscale Funnel. An MCP endpoint lets an assistant such as Hermes search
documents with scoped tokens, by keyword or, optionally, by meaning (semantic search, v1.2).

- Design: [docs/superpowers/specs/2026-11-16-personal-media-design.md](docs/superpowers/specs/2026-11-16-personal-media-design.md)
- Deploy: [docs/setup.md](docs/setup.md)

## Threat model

See spec section 5.

- Protected: someone with the disks, the data directory or a backup, including the admin. They see
  only ciphertext plus coarse metadata (document count, ciphertext sizes, file timestamps, usernames).
- Protected: the admin using the admin UI. It never shows content, and no server-wide key can
  decrypt user data.
- Protected: Tailscale's relays, which only see TLS-encrypted traffic (TLS ends on the ZimaBoard).
- Not protected: an admin who modifies the server code or reads process memory while a user is
  logged in. OCR and search run server-side, so keys are in memory while a user is unlocked.
- A forgotten password plus a lost recovery key means the data is unrecoverable.

## Development

```bash
cargo test            # OCR tests need tesseract (deu+eng) and poppler-utils; otherwise they print SKIP
cargo run -- serve    # needs PM_PUBLIC_URL, e.g.:
PM_PUBLIC_URL=http://127.0.0.1:8080 PM_DATA_DIR=/tmp/pm-data cargo run -- serve
PM_PUBLIC_URL=http://127.0.0.1:8080 PM_DATA_DIR=/tmp/pm-data cargo run -- invite --admin
docker build -t personal-media .   # runs the full test suite and fails if an OCR test was skipped
```

Configuration is by environment variables (`PM_DATA_DIR`, `PM_BIND`, `PM_PUBLIC_URL`,
`PM_MAX_UPLOAD_MB`, `PM_SESSION_IDLE_MINUTES`, `PM_SESSION_MAX_HOURS`, `PM_TRUSTED_PROXY`,
`PM_OCR_WORKERS`).

## MCP endpoint

`POST /mcp` speaks MCP (protocol `2025-11-25`; `2025-06-18` and `2024-11-05` are also
negotiated, `2025-03-26` is not because it requires JSON-RPC batches) over stateless Streamable
HTTP with plain JSON responses. Authenticate with
`Authorization: Bearer pm_...` (a token created under Settings). Tools: `search_documents`,
`list_documents`, `get_document`, `list_tags`, `upload_document`, `update_document` (the
two write tools are only listed for `read_write` tokens), and `semantic_search` (only for
`full_text` tokens, see below).

Deviation from the plan: this is a small hand-written JSON-RPC 2.0 handler (`src/mcp.rs`),
not the `rmcp` SDK. The endpoint is stateless and each request needs its own authenticated
principal; a minimal handler keeps that auditable and avoids the SDK's session handling and
host allow-list. There is no SSE stream: `GET /mcp` is 405.

## Features

- Per-user encryption, OCR (German and English), full-text search, tags, sharing from phones.
- Scoped MCP tokens with a per-channel access switchboard (web, MCP, semantic index). Since
  2026-11-17 (owner ruling AJ) a token's or app's own scope governs what MCP sees (`full_text`
  sees content); only a document's own MCP setting limits it further. Web and semantic index
  still use your Settings defaults.
- OAuth for MCP (v1.4): claude.ai custom connectors and Hermes connect with authorization code +
  PKCE and dynamic client registration; grants are listed and revocable under Settings →
  Connected apps. Static `pm_` tokens still work. See [docs/setup.md](docs/setup.md) section 7d.
- Semantic search (v1.2): an in-process multilingual embedding model (multilingual-e5-small, int8)
  downloaded on first use. Off by default; enable it in Settings. See
  [docs/setup.md](docs/setup.md) section 7c, including `fetch-model` and `embed-selftest`.

## Security notes

- OAuth access and refresh tokens unlock the user key exactly like static tokens (the UMK is
  wrapped under a key derived from the token secret). Refresh tokens are single-use and rotate; reuse
  of a consumed refresh token revokes the grant. That detection is memory-only, so it is lost on a
  restart (a replay after a restart is rejected but does not revoke). PMS makes no outbound
  requests for OAuth: client metadata documents (CIMD) are not supported, only dynamic
  registration.

- MCP access (2026-11-17, owner ruling AJ): a document without a per-document `mcp` setting is
  visible at the token's or app's own scope (`full_text` = content, `metadata_only` = metadata).
  A per-document `mcp` setting still limits every token (`min(setting, scope)`), so use it for
  documents no assistant should read. The user-wide MCP default no longer exists; Web and
  semantic index defaults are unchanged. Tag allow-lists are unchanged.
- Semantic vectors are encrypted like the text (SQLCipher index database) and are only created for
  documents whose `semantic_index` level is `full`. `semantic_search` is only available to
  `full_text` tokens and only returns fully MCP-visible documents, within the token's tag allow-list.
  The model is public and holds no user data; queries and passages never leave the process.
- Supply chain of the embedding runtime: `ort` is pinned to `=2.0.0-rc.15`; its `ort-sys` build step downloads a static ONNX Runtime from `cdn.pyke.io` and checks it against a hash pinned in `ort-sys`. That download happens at image build time only; the runtime image contains just the binary. The model files are fetched from a revision-pinned URL and verified against SHA-256 values pinned in the source (see docs/setup.md section 7c).
- Tag-restricted MCP tokens never see tag names outside their allow-list: not in `list_tags`, not
  on documents (the `tags` of every returned document are filtered), not through search or tag
  filters. `update_document` keeps tags the token cannot see on the document.
- Duplicate oracle for `metadata_only` write tokens: an upload that matches a visible
  document's bytes is answered with that document's id and title, so a `metadata_only` write token
  can confirm that a visible document has exactly the bytes it uploads. It needs the exact file and
  reveals nothing about documents the token cannot see, so it is documented rather than closed.
- Offline recovery (`personal-media recover`) opens both databases read-only and reads the secret
  from stdin or a prompt (the `PM_RECOVER_SECRET` variable only exists in debug builds). See
  [docs/setup.md](docs/setup.md) section 8.
