# Vendored assets

| File | Source | SHA-256 |
| --- | --- | --- |
| `htmx.min.js` | https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |

Verify with `sha256sum static/htmx.min.js`. Vendored files are compiled into
the binary (`include_bytes!` in `src/web/mod.rs`) and must not be edited.
