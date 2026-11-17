# Automatic Document Date Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill an empty `document_date` automatically from the extracted or OCR text, record where every date came from (`user | detected | ai`), never overwrite a date the user or an AI set, and let the AI assistant set dates for handwriting.

**Architecture:**
- A pure date finder `src/dates.rs` that is fully table-tested.
- An index-DB migration v5 that adds `documents.date_source`.
- A hook in `extract.rs` after `set_extracted_text`.
- A one-time backfill per user DB on unlock.
- Source tagging on web edits, scan/upload, and MCP `update_document`/`upload_document`.
- A small hint on the document page.

**Tech Stack:** Rust, rusqlite/SQLCipher, the `time` crate (already a dependency), the `regex` crate if already a dependency (otherwise hand-written scanning; don't add a dependency without noting it), Askama.

**Spec:** `docs/superpowers/specs/2026-11-17-date-detection-design.md`. Read it; its "Ranking when there are several dates" list is binding.

## Global Constraints

- **`date_source` values:** `'user'`, `'detected'`, `'ai'`, or `NULL` (unknown or legacy).
- **Index migration v5:**
  ```sql
  ALTER TABLE documents ADD COLUMN date_source TEXT
      CHECK (date_source IN ('user','detected','ai'));
  PRAGMA user_version = 5;
  ```
  It needs a test from a real v4 DB (Ruling P). Read-only opens of a v4 DB (the recover CLI) must keep working without the column.
- **Existing dates at migration:** legacy rows that already have a date keep `date_source = NULL`. They are treated like `user` for overwrite purposes, because the date was set by someone. Detection only fills rows where `document_date IS NULL` and `date_source` is NULL or `detected`.
- **Page boundaries:** the stored text separates pages with form feed `\f`.
  - pdftotext already emits it.
  - The OCR loop in `src/extract.rs` (~line 430) must join pages with `'\f'` instead of `'\n'`.
  - Text without `\f` counts as one page.
- **"Top third of page 1":** the first third of page 1's lines, at least the first 3 lines.
- **Future limit:** dates more than 2 days after `today` are excluded. `today` is passed in, never read inside the finder.
- **Year limits:** years before 1900 are excluded.
- **Two-digit years:** use `20yy` unless that is more than 2 days in the future, otherwise `19yy`.
- **Tie or no clear winner:** take the earliest remaining date (owner's decision).
- **Who sets which source:**
  - Web edit and the scan/upload form with a date set `user`.
  - A web edit that clears the date sets `user` with `NULL` date, so detection never refills it.
  - Any MCP `update_document`/`upload_document` that sets a date sets `ai`.
  - The detector sets `detected`.
- **UI hint text** after the date on the document page: `found in text` (detected) or `set by AI` (ai). Nothing for `user` or `NULL`.
- **Backfill:** runs once per user DB, guarded by the user-DB `settings` key `date_backfill = 'v1'`, in the background after unlock, never blocking login.
- **Test gate:**
  - `PM_TEST_MODELS_DIR=$HOME/.cache/pms-test-models cargo test -j 2 --no-fail-fast -- --test-threads=2`
  - clippy `-D warnings`
  - fmt
  - Never use full parallelism, and never put build output under `/tmp`.
- **Commit trailer:**
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01XcTHoWb6TaX6gaRd9rBUPT
  ```

## Review Focus

1. **A late OCR result for a document the user has dated meanwhile.** Expected: the user's date stays. Pinned by `detection_never_overwrites_user_or_ai_date` (Task 2).
2. **Garbage OCR full of digit runs** (phone numbers, IBANs, invoice numbers like `2026.11.17.004`, times `12.30`). Expected: no false date from non-date digit groups; word boundaries are required around a match. Pinned by `ignores_numbers_that_are_not_dates` (Task 1).
3. **Invalid calendar dates** (`31.02.2026`, `00.13.2026`). Expected: skipped, never panic. Pinned by `invalid_calendar_dates_are_skipped` (Task 1).
4. **US vs European order** (`03/04/2026`). Expected: the European reading `DD/MM` is used for `/` and `.`. ISO is `YYYY-MM-DD` only. Pinned by `slash_dates_are_day_first` (Task 1).
5. **A huge text** (a 200-page PDF). Expected: the detector looks only at page 1, then the following pages one at a time until a page yields a date, with no quadratic blowup. Pinned by `large_text_is_fast` (Task 1, < 50 ms in debug for 200 pages of 3 KB).

---

### Task 1: The date finder

**Files:**
- Create: `src/dates.rs`, registered in `src/lib.rs`
- Modify: `src/extract.rs`, only the OCR page join (`'\n'` → `'\f'`)
- Test: unit tests inside `src/dates.rs` (`#[cfg(test)]`), plus a test in `tests/` for the OCR join only if one is easy to write. Otherwise state in the report how the join was verified.

**Interfaces:**
- Produces: `pub fn detect_date(text: &str, today: time::Date) -> Option<time::Date>`.

- [ ] **Step 1: Write the failing table tests.** Use `today = 2026-11-17`:
  - **Formats:**
    - `"17.11.2026"` → 2026-11-17
    - `"17.11.26"` → 2026-11-17
    - `"17/11/2026"` → same
    - `"2026-11-17"` → same
    - `"17. November 2026"` → same
    - `"17. Nov. 2026"` → same
    - `"November 17, 2026"` → same
    - `"17 November 2026"` → same
    - `"Nov 17, 2026"` → same
    - `"3. März 2025"` → 2025-03-03
    - `"1. Mai 2025"` → 2025-05-01
  - **Labels win:** `"Kundennr 01.01.2020\nRechnungsdatum: 05.10.2026"` → 2026-10-05.
  - **Place line counts as a label:** `"Max Muster\nHamburg, 12.09.2026\nSehr geehrte"` → 2026-09-12.
  - **Excluded kinds:**
    - due: `"Datum 01.10.2026\nZahlbar bis 15.10.2026"` → 2026-10-01; `"fällig am 20.11.2026"` alone → None.
    - period: `"Zeitraum 01.10.2026 – 31.10.2026"` → None. `"vom 01.10.2026 bis 31.10.2026"` → None.
    - birth: `"geb. 03.04.1980"` → None. `"DOB 03/04/1980"` → None.
    - future: `"25.12.2026"` → None. `"19.11.2026"` → 2026-11-19, inside the 2-day limit.
    - old: `"01.01.1850"` → None.
  - **Top third, then the earliest:**
    - A page-1 date in the first line beats a later date further down: the top-third date wins.
    - Two unlabelled dates both in the top third → the earlier one.
  - **Pages:** `"no date here\fRechnung 03.03.2026"` → 2026-03-03 (page 2 used because page 1 has none). `"Brief 01.02.2026\fDatum 05.05.2026"` → 2026-02-01 (page 1 wins).
  - **`ignores_numbers_that_are_not_dates`:**
    - `"Tel 040 123 456 78"` → None
    - `"IBAN DE12 3456 7890 1234 5678 90"` → None
    - `"Belegnr 2026.11.17.004"` → None
    - `"Termin 12.30 Uhr"` → None
  - **`invalid_calendar_dates_are_skipped`:**
    - `"31.02.2026"` → None
    - `"00.13.2026"` → None
    - `"29.02.2024"` → 2024-02-29
  - **`slash_dates_are_day_first`:** `"03/04/2026"` → 2026-04-03.
  - **Two-digit year:** `"05.06.99"` → 1999-06-05. `"05.06.25"` → 2025-06-05.
  - **`large_text_is_fast`:** 200 pages × 3 KB with one date on page 150 → finds it in under 50 ms.
- [ ] **Step 2: Run the tests.** Run `cargo test -j 2 --lib dates -- --test-threads=2`. Expected: FAIL.
- [ ] **Step 3: Implement `detect_date`.**
  - Approach: tokenise candidates with their line index and page index.
  - Classify each candidate by the words on its own line before it: label, due, period, birth, or place.
  - Filter out the excluded kinds.
  - Rank: label first, then place line, then top third of page 1, then the rest of page 1. Within the winning tier, pick the earliest date.
  - Use later pages only when page 1 has no candidate left, one page at a time.
  - Match labels and exclusion words case-insensitively, as whole words.
  - Change the OCR join to `'\f'`.
- [ ] **Step 4: Run the tests again,** then the full test gate. Expected: PASS.
- [ ] **Step 5: Commit:** `feat(dates): local document date finder (de/en)`.

### Task 2: Schema, pipeline, sources, UI, backfill, docs

**Files:**
- Modify:
  - `src/user_db/mod.rs`: migration v5 and readonly handling
  - `src/user_db/documents.rs`: `date_source` column in `Document`, `doc_cols`, update functions
  - `src/extract.rs`: hook after a successful `set_extracted_text`
  - `src/mcp.rs`: `update_document`/`upload_document` set `ai`
  - `src/web/docs.rs`: edit sets `user`; detail page hint
  - `src/web/scan.rs` and upload paths: a date given sets `user`
  - `src/keyring.rs` or the existing unlock hook (`on_unlock`): start the backfill
  - `templates/document.html`
  - `docs/setup.md` §7e: prompt adds "If the page shows a date, also set it with update_document."
  - `src/mcp.rs`: the `set_transcription` tool description gets the same sentence
- Test: `tests/user_db.rs` (migration), `tests/dates_pipeline.rs` (new), `tests/web_docs.rs`, `tests/mcp_handwriting.rs`

**Interfaces:**
- Consumes: `dates::detect_date(text, today)` from Task 1.
- Produces:
  - `pub enum DateSource { User, Detected, Ai }` with `as_str()`
  - `Document.date_source: Option<DateSource>`
  - `pub fn apply_detected_date(conn, id: &str, text: &str, today: time::Date, now: i64) -> Result<bool>`. In one statement it sets the date only when `document_date IS NULL AND (date_source IS NULL OR date_source = 'detected')`, and returns whether it set one.
  - `pub fn backfill_detected_dates(conn, today, now) -> Result<usize>`

- [ ] **Step 1: Write the failing tests.**
  - `index_migration_v4_to_v5_keeps_data`: a real v4 DB built from `SCHEMA_V1` + V2 + V3 + V4 with a dated document. After opening: `user_version == 5`, the date is intact, and `date_source` is NULL.
  - `readonly_open_of_v4_still_works`
  - `detected_date_fills_empty_date`: an upload whose text has `"Rechnungsdatum 05.10.2026"` → after extraction the date is 2026-10-05 and the source is `detected`.
  - `detection_never_overwrites_user_or_ai_date`: covers a user-set date, an ai-set date, a legacy dated row with NULL source, and a user-cleared row (NULL date, source user). All stay unchanged after `apply_detected_date`.
  - `web_edit_sets_user_source` and `web_clear_date_blocks_detection`
  - `mcp_update_date_sets_ai_source`
  - `document_page_shows_date_hint`: `found in text` and `set by AI`
  - `backfill_runs_once`: two documents without dates; the backfill fills them and sets `date_backfill=v1`; a second run touches nothing.
- [ ] **Step 2: Run the tests.** Expected: FAIL.
- [ ] **Step 3: Implement the Interfaces and the Global Constraints.**
  - The extraction hook runs only when the text status is done and text exists.
  - Detection failures are logged and never fail the extraction job.
  - Re-embedding is not needed, because the date is metadata. Do call `reindex` if dates are part of FTS; check this.
- [ ] **Step 4: Run the full test gate.** Expected: PASS.
- [ ] **Step 5: Commit:** `feat(dates): fill empty dates from text, record date source, AI sets dates`.
