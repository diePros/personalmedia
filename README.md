# Personal Media

A Rust document vault with per-user encryption.

## MCP endpoint

`POST /mcp` speaks MCP (protocol `2025-06-18`, older `2025-03-26` and `2024-11-05` are
negotiated) over stateless Streamable HTTP with plain JSON responses. Authenticate with
`Authorization: Bearer pm_...` (a token created under Settings). Tools: `search_documents`,
`list_documents`, `get_document`, `list_tags`, `upload_document`, `update_document`.

Deviation from the plan: this is a small hand-written JSON-RPC 2.0 handler (`src/mcp.rs`),
not the `rmcp` SDK. The endpoint is stateless and each request needs its own authenticated
principal; a minimal handler keeps that auditable and avoids the SDK's session handling and
host allow-list. There is no SSE stream: `GET /mcp` is 405.
