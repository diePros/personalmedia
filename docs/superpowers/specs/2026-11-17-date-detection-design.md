# Automatic document date — design (short)

Date: 2026-11-17. Status: approved by the owner. Target: v1.6.3, after the Search page (v1.6.2).

## Why
The owner usually doesn't set dates. Without a date, date filters and "when was that letter" searches miss documents. Dates should be filled in automatically: locally from OCR or extracted text, and by the user's AI assistant for handwritten notes.

## Goals, non-goals and anti-goals
**Goals**
- Fill `document_date` automatically when it is empty.
- Show where the date came from.
- Let the user correct it with one tap.

**Non-goals**
- Detecting the date from handwriting locally. That waits for local handwriting recognition (HTR, v1.7).
- Splitting multi-letter scans.
- Locales other than German and English.

**Anti-goals**
- Never overwrite a date the user set.
- Never send text off the box for this.

## Approaches
1. **Local rule-based extraction after text extraction, plus the AI prompt for handwriting (picked).** It's deterministic, private and cheap on the N150.
2. **Use the embedding model or a small LLM locally (rejected).** It's heavy, and rules fit this narrow job better.
3. **AI assistant only (rejected).** Printed documents would get no date unless the AI was asked.

## Design
- **Where it runs.**
  - In the processing pipeline, right after text extraction or OCR finishes, and only when `document_date` is empty and `date_source` isn't `user`.
  - The same function also runs once over existing documents, through the pending-job mechanism or a one-off backfill on unlock (the builder decides which).
- **Formats it understands.**
  - Numeric: `17.11.2026`, `17.11.26`, `17/11/2026`, `2026-11-17`.
  - German month names: `17. November 2026`, `17. Nov. 2026`.
  - English month names: `November 17, 2026`, `17 November 2026`, `Nov 17, 2026`.
  - Validate the calendar date, and expand two-digit years to 20xx when the result isn't in the future, otherwise 19xx.
- **Ranking when there are several dates:**
  1. A labelled issue date wins: `Datum`, `Rechnungsdatum`, `Ausstellungsdatum`, `Belegdatum`, `Date`, `Invoice date`, `Issue date`, or a `<Place>, <date>` line, where a place is a capitalised word followed by a comma.
  2. Exclude:
     - due dates: `fällig`, `zahlbar bis`, `due`, `payable by`;
     - periods and ranges: `Zeitraum`, `vom … bis`, `–` between two dates, `period`;
     - birth dates: `geb.`, `geboren`, `born`, `DOB`;
     - dates more than 2 days in the future;
     - dates before 1900.
  3. Otherwise take the first date in the top third of page 1. Pages after the first are used only when page 1 has no date.
  4. **Tie or no clear winner: take the earliest remaining date (owner's decision).** It makes the document findable by date filters, and full-text search still finds the other dates.
- **Recording where a date came from.**
  - Add a new column `documents.date_source` with the values `user | detected | ai | NULL`. This is index migration v5, with a test that starts from a real v4 DB (Ruling P).
  - User edits in the web UI and through MCP `update_document` set `date_source`:
    - a web edit sets `user`;
    - MCP with a full-text token sets `ai`.
  - A detected date never overwrites `user` or `ai`.
- **Interface.**
  - The document page shows the date with a hint: "found in text" or "set by AI".
  - The date field is already editable; saving it sets `user`.
  - No other UI changes.
- **Handwriting.**
  - Extend the example prompt in `docs/setup.md` §7e and the `set_transcription` tool description: "If the page shows a date, also set it with update_document."
- **Tests:**
  - a table test of ranking cases, covering label vs. unlabelled, a due date, a period, a birth date, the future, a tie that picks the earliest, the two-digit year, and page 2 used only as a fallback;
  - a pipeline test showing a user date is never overwritten;
  - the migration test.
