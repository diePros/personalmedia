# Personal Media

A document vault with per-user encryption, written in Rust. Users upload scans and PDFs, the server
OCRs them (German and English) and makes them searchable, and everything is stored encrypted with
a key derived from each user's password. It runs as a single Docker container on a ZimaBoard and
is published through Tailscale Funnel. An MCP endpoint lets an assistant such as Hermes search
documents with scoped tokens.

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
two write tools are only listed for `read_write` tokens).

Deviation from the plan: this is a small hand-written JSON-RPC 2.0 handler (`src/mcp.rs`),
not the `rmcp` SDK. The endpoint is stateless and each request needs its own authenticated
principal; a minimal handler keeps that auditable and avoids the SDK's session handling and
host allow-list. There is no SSE stream: `GET /mcp` is 405.

## Security notes

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
