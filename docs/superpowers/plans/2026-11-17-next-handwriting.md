# Next session: handwriting (BYO-AI follow-ups + local HTR)

> **Start here in a fresh session.** This file is the handoff. Read it, then `docs/superpowers/specs/2026-11-16-personal-media-design.md` (§5, §13, §13a, §17a, §18), then the code it points to. Use superpowers:brainstorming before building anything new (local HTR has open design questions), then superpowers:writing-plans → superpowers:subagent-driven-development.

## Where things stand (2026-11-17)

- **Released:** `v1.5.0` on `main` (5902b01), pushed to `github.com/diePros/personalmedia` (private). GHCR image `ghcr.io/diepros/personalmedia:latest` = 1.5.0 (built by `.github/workflows/image.yml` on tags).
- **Deployment:** ZimaBoard 2 (Intel N150, ZimaOS). Source in `~/AppData/personal-media`, data at `/media/Tank/PMS`, public via Tailscale Funnel `https://zeema.basilisk-pollux.ts.net`. Updates: `git pull && sudo DOCKER_CONFIG=/DATA/.docker docker compose pull && … up -d`. The owner decided against ZimaOS custom-app installs and Watchtower.
- **Process rules (owner):**
  - Sonnet implements, Opus does all reviews, never Fable.
  - Merge, tag and push after each version bump.
  - Auto-resume after rate limits.
  - Owner-facing changes go through brainstorming first.
- **Test gate (machine has ~15 GB RAM and a RAM-backed `/tmp`):**
  - `cargo test -j 2 --no-fail-fast -- --test-threads=2` with `PM_TEST_MODELS_DIR=$HOME/.cache/pms-test-models`
  - **plus** `cargo test --release …` before tagging, because CI runs release
  - Never full parallelism.
- **Schema freeze (Ruling P):** system.db is v3 and the index DB is v3. Changes only via numbered migrations, with a test from a real previous-version DB.

## Part A — BYO-AI handwriting (shipped in v1.5, needs real-world follow-up)

**What exists:**
- MCP tools in `src/mcp.rs`:
  - `get_page_image {id, page?}`: JPEG of a PDF page via `pdftoppm -r 150 -scale-to 1568`, or the stored image if ≤ 4 MiB
  - `set_transcription {id, text, mode?}`
  - `set_notes {id, notes}`
- **Gating:** `full_text` scope, effective `mcp` level `Full` (documents without an override follow the token/app scope, a change of 2026-11-17), and the tag allow-list. Page images are rate-limited to 20/min per grant/token, in memory.
- **Storage and search:** a transcription sets `documents.text_source = 'transcription'`, reindexes FTS and re-embeds. `documents.notes` is metadata-level searchable (index migration v3).
- **UI and docs:** the document page shows the text source, and the scan save sheet has Notes. `docs/setup.md` "Handwritten notes" has the example claude.ai prompt.

**Follow-ups to do first (small; verify, don't rebuild):**
1. **Owner test with real claude.ai and Hermes:** tag a handwritten scan `handwritten`, run the prompt, and confirm that `get_page_image` images render in Claude, the transcription lands, and search finds it. Collect any client-side errors (image content shape, size limits).
2. **"Transcribed on" date** uses `updated_at`, which moves on later edits. Decide whether a dedicated `transcribed_at` is worth an index migration v4. Batch it with Part B's schema needs.
3. **The page-image rate limit is memory-only.** It resets on restart; that's acceptable, but document it.
4. **Optional UX:** a "Needs transcription" filter (documents whose text is empty or very short after OCR plus the tag `handwritten`) so the AI or user can find candidates. Expose it as an MCP `list_documents` filter `needs_transcription: true`.

## Part B — Local handwriting recognition (HTR), roadmap spec §18

**Goal:** handwritten pages become searchable **without anything leaving the box**. It runs in-process, CPU-only, on the N150 inside the 1.5 GiB container, using the same pattern as the embedding engine (`src/embed/`: lazy load, idle unload, pinned model download with SHA-256, `fetch-model` CLI, the build stage fetches the model for tests only, the runtime image stays model-free).

**Constraints from the spec and the owner:**
- German + English handwriting.
- A new switchboard channel `handwriting`, **off by default**. Default and per-document levels: `off|full`.
- Writes `text_source = 'htr'` and **never overwrites** a user or AI transcription (`text_source = 'transcription'`) without explicit confirmation.
- Runs in the existing worker queue, **after** OCR and embedding priority rules (OCR first, Ruling Z), one job at a time, with time limits.
- Only ship if accuracy is actually useful; the spike decides.

**Step 1 — Spike (measure, don't build), like `docs/superpowers/specs/2026-11-17-embedding-spike.md`:**
- **Candidates to evaluate** (verify that each exists and check its licence at spike time; don't trust memory):
  - TrOCR handwritten (base/small) exported to ONNX via `ort` (the crate already uses `ort =2.0.0-rc.15`)
  - a smaller CRNN/CTC line-recogniser
  - any current multilingual HTR model with a German line-level checkpoint
- **Segmentation:** TrOCR-style models read **one text line** at a time, so pages need line segmentation first. Options:
  - projection-profile segmentation on the binarised page (cheap; good for neat notes)
  - Tesseract's layout analysis (`tesseract --psm` with `hocr`/`tsv` output gives line boxes even when recognition fails), which is already in the image
  - a small layout model
- **Measure on the dev machine and estimate for the N150:**
  - character error rate on ~10 real German and ~5 English handwritten pages (the owner can provide samples; don't commit personal ones, keep them in `$HOME/.cache`)
  - seconds per page
  - peak RSS
  - model size
- **Write the findings and a go/no-go recommendation** in `docs/superpowers/specs/<date>-htr-spike.md`.

**Step 2 — If go:** brainstorm with the owner, then plan. Expected tasks:
1. HTR engine module (`src/htr/`) + model management (reuse the `embed::model` fetch and verify code).
2. Line segmentation.
3. A pipeline stage, plus switchboard channel `handwriting` (access defaults, document override UI, settings help text), plus an index migration v4 if needed (e.g. `transcribed_at`, or HTR confidence).
4. UI: text source "recognised locally (handwriting)", a "re-run" button, a confidence hint.
5. Docs, then release `v1.6.0`.

Review focus for the milestone: memory bound on the N150, no plaintext page crops on disk outside tmpfs, never clobbering AI or user transcriptions, the switchboard off by default, and quality gating (don't index garbage: a minimum confidence, otherwise keep `text_source = 'none'`).

## Update after v1.6.0 (2026-11-17)

- **Released v1.6.0:** the needs-transcription filter (A4, MCP + web), page-image rate-limit docs (A3), "Remember this device" (spec/plan `2026-11-17-remember-device*`), `.env` deploy settings, and a password-manager username hint. Index DB is now **v4** (`device_meta`), and system.db is still v3. Part B (local HTR) moves to **v1.7**; its index migration becomes v5.
- **HTR spike done:** `docs/superpowers/specs/2026-11-17-htr-spike.md` recommends go with conditions (German CRNN `naeyn/de-htr-web-v2`). Owner decisions are pending: test on own pages, English engine, ruled-paper photos, fuzzy search.
- **Mobile layout pass released in v1.6.1:** no sideways scrolling, 44 px targets, safe areas, `dvh`, and the bottom tab bar in phone browsers (`width < 40rem`). Left open: the app.css:465 comment says "up to 40rem"; there is no real-iPhone check yet (owner); `svg.check` should be renamed.
- **Remember-device follow-ups (parked in final review):**
  - Multiple open tabs with a stale CSRF token on logout still return 403. Fix: on a CSRF mismatch in logout, fall through to the device-cookie path.
  - `start_session` calls `remove_device` for an unverified cookie id. Only do it when `revoke_device` returned true.
  - The no-session logout path skips the limiter.
  - The resume gate entry leaks on a cancelled future (needs an RAII guard).
  - Edge on iOS is labelled Safari. iPadOS with a desktop user agent is labelled Mac.
  - setup.md:250 still says `mem_limit: 1536m`; it is now `${MEM_LIMIT:-1536m}`.

## Open deferred minors (from earlier reviews; optional cleanup batch)

- Per-token MCP rate limit (v1.2 M3) and the user-DB mutex held during the vector scan (v1.2 M4).
- No TOTP replay protection within the window. Consent approval asks for the password only, not TOTP.
- Refresh-token reuse detection is memory-only (it resets on restart; Ruling AE).
- Tags are case-sensitive.
- An OCR failure on one page stops at that page, with no "partial" marker.
- A KDF-busy 503 counts as a failed login attempt.
- The duplicate check near the quota limit reports "quota exceeded" (the hash is only known after streaming).
- The Firefox PDF preview was never manually verified.
