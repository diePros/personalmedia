# Separate Search page, grouped Documents list — design (short)

Date: 2026-11-17. Status: approved by the owner ("yes, go ahead"). Target: v1.6.2.

## Why
The owner uses PMS as a place to "just save this now" and later find documents again by searching. Today the Search tab only jumps to the search box on the Documents page, so the tabs feel like the same page. Results also look unsorted, because search sits on top of the newest-first list. Documents and Search do different jobs and should be separate screens.

## Goals and non-goals
**Goals**
- Documents shows "what I saved", newest first, grouped by day.
- Search is its own page with the box at the top, filters tucked away, and results by best match. A Best match / Newest switch is available.

**Non-goals**
- Topic or tag browsing.
- Saved searches.
- Changes to search ranking itself, to MCP, or to the index.

**Anti-goal**
- Losing any existing filter or search capability. This includes the tag filter, the date range, Needs transcription, meaning search and pagination.

## Approaches
1. **Two pages on shared handler code (picked).** `/documents` lists and `/search` searches. Both reuse the same results partial and the same query and filter code.
2. **One page with two modes behind a toggle (rejected).** This is what the owner finds confusing today.
3. **Client-side tabs on one page (rejected).** It needs more JS and gives no real URL for Search.

## Design
- **`GET /search`** is a new page titled "Search".
  - The search form sits at the top: the `q` box, with the Words/Meaning radios next to or below it.
  - A `<details>` "Filters" disclosure holds tag, from, to and Needs transcription. It is open when any filter is active.
  - A sort switch offers **Best match** (default) and **Newest**. Its query param is `sort=best|newest`.
  - With no `q` and no filter, the page shows a short hint ("Search your documents by words or meaning.") and no list.
  - With filters but no `q`, it shows the matching documents newest first. In that case the sort switch is hidden, since there is nothing to rank.
  - Live search (htmx, 300 ms) works as it does today.
  - Pagination keeps every param.
  - On phones the search box gets focus when the page is opened through the tab. Reuse app.js's existing `#q` focus logic, retargeted to `/search`.
- **Sorting.**
  - **Best match:** words search keeps `bm25` ordering, and meaning search keeps its score ordering.
  - **Newest:** the same matches, ordered by `created_at DESC, id`.
    - For words search, apply this in SQL in `search()`, with a `ListFilter`/search option.
    - For meaning search, re-sort the already-selected top results.
- **`GET /documents`** keeps the upload area, the heading and the list, newest first, with no search form and no filters.
  - The list is grouped under day headings: *Today*, *Yesterday*, *This week*, then month names ("November 2026").
  - Day boundaries use the browser's time zone. `app.js` sets a non-sensitive cookie `pm_tz` holding the browser's offset in minutes east of UTC; the server reads it and falls back to UTC.
  - Grouping applies per page of results. A page may start in the middle of a group, which repeats the heading. That is fine.
- **Redirects.**
  - `GET /documents?q=…` and `/documents` with any filter param return 303 to `/search` with the same query string. This keeps old links and bookmarks working.
  - A plain `/documents` is not redirected.
- **Navigation.**
  - The Search tab links to `/search`.
  - The desktop header gets "Search" between Documents and Settings.
  - `aria-current` is correct on both pages.
- **MCP:** no change.

## Verification
- Web tests:
  - `/search` renders the form and the hint.
  - `q` gives results.
  - `sort=newest` changes the order.
  - Filters without `q` work, and the sort switch is hidden in that case.
  - Old `/documents?q=x&tag=y` returns 303 to `/search?q=x&tag=y`.
  - `/documents` has no search form and shows day headings, including with `pm_tz`.
  - Pagination keeps `sort` and the filters.
- The visual check at 375 px and 1280 px for both pages goes in the report. Use the same srcdoc method as the mobile pass.
