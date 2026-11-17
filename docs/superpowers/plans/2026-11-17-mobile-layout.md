# Mobile Layout Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** At 375 px and 768 px, no page scrolls sideways and every control is at least 44 px tall. The installed iPhone app keeps clear of the notch and home bar, and phone browsers get the bottom tab bar.

**Architecture:** The work is CSS changes in `static/app.css` and `static/scan.css` plus small template edits in `templates/`. The tab bar rules are consolidated so the standalone mode and the phone-browser mode share one rule set.

**Tech Stack:** Askama templates, plain CSS, existing `static/app.js` (which adds the `standalone` class on iOS).

**Spec:** `docs/superpowers/specs/2026-11-17-mobile-layout-design.md`

## Global Constraints

- Phone breakpoint: `max-width: 40rem`, the same value as the existing `min-width: 40rem` queries.
- Tap target minimum: 44 px (`2.75rem`) height for interactive controls.
- Long text wrapping: `overflow-wrap: anywhere`.
- Viewport meta: `width=device-width, initial-scale=1, viewport-fit=cover`.
- Viewport heights: `dvh`, with the previous `vh` declaration kept as a fallback line just before it.
- Desktop above 40rem in a browser: header nav unchanged, no tab bar.
- No third copy of the tab bar rules.
- Test gate:
  - `PM_TEST_MODELS_DIR=$HOME/.cache/pms-test-models cargo test -j 2 --no-fail-fast -- --test-threads=2`
  - clippy `-D warnings`
  - fmt
  - Never full parallelism. No build output under `/tmp`.
- Commit trailer:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01XcTHoWb6TaX6gaRd9rBUPT
  ```

## Review Focus

1. **Desktop regression:** at 1280 px in a browser, the header nav with Documents, Settings, Admin and Logout must look as before and the tab bar must not show. Checked by the visual audit at 1280 px (Task 2).
2. **Installed app on Android:** the `display-mode: standalone` media query matches without the `.standalone` class. The header must stay hidden and the tab bar visible. Checked by emulating the media query in the audit (Task 2).
3. **Logout reachable on a phone browser:** with the header nav hidden, Settings must show the Logout button. Checked by `settings_shows_account_actions_markup` (Task 2) plus the visual audit.
4. **Content behind the tab bar:** the last element of long pages (the Settings export form, the documents pager) must stay scrollable into view above the fixed tab bar. Checked in the visual audit.
5. **Scan screen:** it has its own fixed save bar and sheet (scan.css). In the phone-browser mode it must not overlap the tab bar. Checked in the visual audit of `/scan` at 375 px.

---

### Task 1: Overflow, tap targets, iOS viewport

**Files:**
- Modify: `static/app.css`, `static/scan.css`, `templates/base.html` (viewport meta)
- Modify, where a label row is needed: `templates/documents.html`, `templates/login.html`, `templates/recover.html`, `templates/signup.html`, `templates/admin.html`, `templates/settings.html`, `templates/oauth_consent.html`
- Test: `tests/web_docs.rs`, or whichever existing test renders base.html

**Interfaces:**
- Produces: a reusable class `.check` for a checkbox or radio label row with `min-height: 2.75rem`, `display: flex`, `align-items: center` and `input { flex: none }`. Reuse the existing `.check` if present and extend it.

- [ ] **Step 1: Write the failing test.** Add `viewport_allows_safe_area_insets`: GET `/login` and assert the HTML contains `viewport-fit=cover`.
- [ ] **Step 2: Run it.** `cargo test -j 2 --test web_auth viewport -- --test-threads=2` (or the file you put it in). Expected: FAIL.
- [ ] **Step 3: Implement the spec's "Long text", "Tap targets" and "iOS" bullets.** That covers the viewport meta, overflow-wrap rules, `pre`, 44 px targets and `dvh` fallbacks.
- [ ] **Step 4: Run the test gate.** Expected: PASS, clippy clean.
- [ ] **Step 5: Commit** `fix(mobile): no sideways scrolling, 44px tap targets, iOS safe areas`.

### Task 2: Tab bar in phone browsers, plus the visual audit

**Files:**
- Modify: `static/app.css` (consolidate the tab bar rules), `templates/base.html` (only if a class hook is needed)
- Test: `tests/web_settings.rs`

**Interfaces:**
- Consumes: the markup of `.tabbar`, `.site-header` and `.account-standalone` as it exists today.

- [ ] **Step 1: Write the failing test.** Add `settings_shows_account_actions_markup`: the signed-in `/settings` HTML contains the `account-standalone` block with a Logout form, and an admin also sees the Admin link. If this already passes because the markup exists, keep it as a regression guard and note that in the report.
- [ ] **Step 2: Implement the spec's "Phone browser shell" bullet.**
  - At ≤ 40rem the browser shows the tab bar and `.account-standalone`, and the header shows only the brand.
  - One shared rule set covers standalone (class and media query) and the phone browser.
  - The bottom padding of `main` accounts for the tab bar.
  - Scan's fixed bars sit above the tab bar.
- [ ] **Step 3: Visual audit.**
  - Run the app locally with `PM_PUBLIC_URL=http://127.0.0.1:8080 PM_DATA_DIR=$HOME/.cache/pms-mobile-recon/data …` (that data dir already has an admin and documents; create one if it's missing).
  - Render every page at 375, 768 and 1280 px with the srcdoc-iframe method, because Chrome can't go below about 616 px.
  - Check `scrollWidth <= innerWidth` and tap targets of at least 44 px, plus Review Focus items 1–5.
  - To emulate standalone, add the `standalone` class to `<html>` in the srcdoc copy.
  - Fix whatever the audit finds.
  - Record a table of pages × widths with the results in the report.
  - Stop the server afterwards.
- [ ] **Step 4: Run the test gate.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(mobile): bottom tab bar in phone browsers`.
