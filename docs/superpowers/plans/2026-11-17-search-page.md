# Search Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move search into its own `/search` page, sorted by best match by default with a switch to newest. `/documents` becomes the newest-first list grouped by day.

**Architecture:** The route handlers live in `src/web/docs.rs`. The query and filter parsing and the results partial (`templates/_results.html`) are shared by both pages. The documents template is split into `documents.html` (list) and a new `search.html`. Words search gets a `newest` ordering option in `src/user_db/documents.rs::search`.

**Tech Stack:** Rust, axum, Askama, htmx, SQLite FTS5, and `static/app.js`.

**Spec:** `docs/superpowers/specs/2026-11-17-search-page-design.md`

## Global Constraints

- Routes: `GET /search` (new) and `GET /documents`.
- Query params: `q`, `mode=words|meaning`, `tag`, `from`, `to`, `needs_transcription=1`, `sort=best|newest` (default `best`), `page`.
- Redirect: `/documents` with any of `q`, `tag`, `from`, `to`, `needs_transcription`, `mode` or `sort` returns 303 to `/search?<same query>`.
- Day headings: `Today`, `Yesterday`, `This week`, then `<Month> <YYYY>` in English.
- Time zone cookie: `pm_tz`, the minutes east of UTC as an integer. Set it with `Path=/; SameSite=Lax; Max-Age=31536000` and clamp it to ±840. Fall back to UTC.
- Empty-search hint: "Search your documents by words or meaning."
- No MCP or schema changes.
- Test gate:
  - `PM_TEST_MODELS_DIR=$HOME/.cache/pms-test-models cargo test -j 2 --no-fail-fast -- --test-threads=2`
  - clippy `-D warnings`
  - fmt
  - Never use full parallelism, and put no build output under `/tmp`.
- Commit trailer:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01XcTHoWb6TaX6gaRd9rBUPT
  ```

## Review Focus

1. **Meaning search on `/search` keeps its limits.** That covers the per-session busy slot, "still indexing" notices and `MEANING_NO_MATCH`. Covered by an existing meaning test ported to `/search` (Task 1).
2. **htmx partial requests** (`HX-Request`) to `/search` return only the results partial, as `/documents` did. Covered by `search_htmx_returns_partial` (Task 1).
3. **Hidden-from-web documents** never appear on `/search`, and `/documents` keeps the access filter. Covered by an existing access test ported to `/search` (Task 1).
4. **A malformed `pm_tz` cookie** (non-number, huge value) falls back to UTC without an error. Covered by `day_groups_ignore_bad_tz_cookie` (Task 2).
5. **A bookmark of the old `/documents?q=` URL** lands on the same results. Covered by `old_documents_search_url_redirects` (Task 1).

---

### Task 1: The `/search` page, sorting and redirects

**Files**
- Create: `templates/search.html`.
- Modify:
  - `src/web/docs.rs` (route, handler, redirect, `page_url`)
  - `src/user_db/documents.rs` (`search` ordering option)
  - `templates/base.html` (nav link and tab href)
  - `static/app.js` (tab and focus logic for `/search`)
- Test: `tests/web_docs.rs` and `tests/user_db.rs`.

**Interfaces**
- Produces:
  - `enum SearchSort { Best, Newest }` with `Default = Best`.
  - Words search takes it: `search(conn, text, &filter)` reads a new field `ListFilter.sort_newest: bool`, or takes an extra param. That choice is the implementer's, but keep `search`'s other callers (MCP) unchanged in behaviour.
  - The shared function that turns query params into a filter and a `ResultsView` is used by both pages.

- [ ] **Step 1: Write the failing tests**
  - `search_page_shows_form_and_hint`
  - `search_words_best_match_then_newest`: two docs, the older one a stronger match. Default order is older first; `sort=newest` puts the newer one first.
  - `search_filters_without_query_list_newest_and_hide_sort`
  - `search_htmx_returns_partial`
  - `old_documents_search_url_redirects`: `/documents?q=x&tag=y` returns 303 with Location `/search?q=x&tag=y`.
  - `search_pagination_keeps_sort_and_filters`
  - In `user_db`: `search_newest_orders_by_created_at`.
  - Port the existing `/documents` search, meaning and needs-transcription web tests to `/search`. Keep their assertions and change only the URL.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Add the `/search` route and handler.
  - Write `search.html` per the spec: a `<details>` Filters block, open when any filter is set; the sort switch as radio buttons in `.check` rows; the hint.
  - Add the sort to words search.
  - For meaning search, re-sort the selected results when `sort=newest`.
  - Add the redirect.
  - Add the nav link and change the tab href to `/search`.
  - Retarget the app.js `#q` tab and focus logic to `/search`.
- [ ] **Step 4: Run the test gate.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(search): separate Search page with best-match/newest sorting`.

### Task 2: Documents list grouped by day

**Files**
- Modify:
  - `src/web/docs.rs` (list handler: group rows)
  - `templates/documents.html` (remove the search form, render groups)
  - `templates/_results.html`, only if grouping needs it there (grouping is for the list page only)
  - `static/app.js` (set the `pm_tz` cookie)
  - `static/app.css` (group heading style)
- Test: `tests/web_docs.rs`

**Interfaces**
- Consumes: the Task 1 redirect, so `/documents` with search params no longer reaches the list.
- Produces: `fn day_group(created_at: i64, now: i64, tz_offset_min: i32) -> String`, which returns the heading label. Unit-test it.

- [ ] **Step 1: Write the failing tests**
  - `day_group` table test, with `now` fixed and offset +60:
    - same local day gives "Today"
    - previous local day gives "Yesterday"
    - 3 days ago gives "This week"
    - 40 days ago gives "October 2026"
    - one test where the UTC day differs from the local day
  - `documents_page_has_no_search_form`
  - `documents_list_grouped_by_day`: one doc gets `created_at` now, another 40 days ago (insert through the db helper). Both headings appear, in order.
  - `day_groups_ignore_bad_tz_cookie`: `pm_tz=abc` and `pm_tz=999999` both return 200 and use UTC.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Add `day_group` and grouping in the list handler.
  - In the template, render each heading as `<h2 class="day-group">` before the first row of its group.
  - Remove the search form from `documents.html`.
  - Set `pm_tz` in app.js on every page load.
  - Add the heading CSS.
- [ ] **Step 4: Visual check.**
  - Render `/documents` and `/search`, with filters open and with results, at 375 and 1280 px using the srcdoc method from the mobile pass. Use a local server with `PM_DATA_DIR=$HOME/.cache/pms-mobile-recon/data` and the Claude-in-Chrome tools.
  - Check for no overflow and tap targets ≥ 44 px.
  - Record a table in the report.
- [ ] **Step 5: Run the test gate.** Expected: PASS.
- [ ] **Step 6: Commit** `feat(documents): newest-first list grouped by day`.
