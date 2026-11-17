# Mobile layout pass — design (short)

Date: 2026-11-17. Status: approved by the owner ("go ahead with the mobile fixes and tab bar"). Target: v1.6.1.

## Why
The owner uses PMS mostly on the phone. An audit at 375 px and 768 px found:
- pages that scroll sideways because of long text;
- tap targets under 44 px;
- iPhone notch and home-bar padding that has no effect;
- a two-row header that takes about 100 px.

## Goals / non-goals
- **Goals:**
  - No page scrolls sideways at 375 px or 768 px with realistic content: 140-character titles and file names, MCP tokens and invite URLs.
  - Every interactive control is at least 44 px tall.
  - Safe areas work in the installed iPhone app.
  - In a phone browser (≤ 40rem) the app uses the same bottom tab bar as the installed app.
- **Non-goals:**
  - Redesigning any page.
  - New features or a new layout for tablets or desktops beyond the fixes.
- **Anti-goal:** changing the desktop layout, beyond long-text wrapping and touch-target sizing that also apply there.

## Approaches
1. **Targeted CSS pass plus tab bar in phone browsers (picked).** It fixes the audit's findings in place and reuses the existing tab bar.
2. **Mobile-first rewrite of app.css (rejected):** it is a large diff with regression risk and was not asked for.
3. **Only fix overflow (rejected):** it leaves the header problem the owner agreed to fix.

## Design
- **Long text:** `overflow-wrap: anywhere` on `h1, h2, .doc-title, .doc-meta, .tag, .upload-name, code`. `pre` gets `white-space: pre-wrap; overflow-wrap: anywhere`. This covers the token page, the admin invite URL and the document detail title.
- **Tap targets:**
  - **Links:** text links in `main` used as actions or navigation get at least 44 px of height via padding or `min-height` (e.g. "Back to …", "Lost your password?", pager links, `.doc-title` links in the list). So do `.button` links (Download).
  - **Brand, file input:** the `.brand` link and the file input also get at least 44 px.
  - **Checkboxes and radios:** each sits in a label row at least 44 px tall. This applies to the Words/Meaning radios, "Needs transcription", "Remember this device", the admin "Unlimited" and delete-confirm boxes, the token and consent tag boxes, and the signup "I understand" box. `.check input` gets `flex: none` so it never shrinks.
- **iOS:**
  - **Viewport:** `viewport-fit=cover` goes in the viewport meta, so the existing `env(safe-area-inset-*)` padding takes effect. Content must not end up under the notch in a normal browser tab. Check that `main` and the header pad with safe-area insets where needed.
  - **Heights:** `.preview` / `iframe.preview` / `.sheet` heights use `dvh`, with the old `vh` value as the fallback line before it.
- **Phone browser shell (≤ 40rem, not standalone):**
  - **Tab bar:** the existing bottom tab bar shows, the same as standalone.
  - **Header:** the top header keeps only the brand; nav links and Logout are hidden.
  - **Settings:** the `.account-standalone` block (Admin link and Logout on the Settings page) shows, so Logout and Admin stay reachable.
  - **Bottom padding:** `main` gets bottom padding for the tab bar.
  - **CSS rules:** the tab bar rules currently exist twice (the `.standalone` class for iOS and the `display-mode: standalone` media query). The builder must not add a third full copy. Share one rule set, e.g. a single selector list or a custom property switch, *(builder's call how)*.
  - **Wide screens:** above 40rem in a browser, nothing changes: the header nav stays and there is no tab bar.
- **Filters row:** at ≤ 40rem the filters stack (today's behaviour). The "Needs transcription" checkbox row gets the 44 px treatment. No further layout change.

## Verification
- **Automated tests:** template and CSS changes are covered where the existing web tests can assert markup, e.g. viewport meta, the tab bar present for signed-in pages and the `account-standalone` block present on Settings.
- **Visual check:** the builder renders every page at 375 px and 768 px with long content and checks `scrollWidth <= innerWidth` plus tap-target sizes. Use the same srcdoc-iframe method as the audit, because the browser window can't go below about 616 px. The results go in the report.
- **Not testable here:** a real iPhone (notch and installed app). The owner checks this after deploy.
