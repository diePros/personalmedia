//! Local document-date finder for German and English text.
//!
//! `detect_date` scans extracted or OCR text for calendar dates, drops the
//! kinds that are not an issue date (due dates, periods, birth dates, future
//! and pre-1900 dates), then ranks what is left:
//!
//! 1. a labelled issue date (`Datum`, `Rechnungsdatum`, `Date`, ...) or a
//!    `<Place>, <date>` line,
//! 2. a date in the top third of the page,
//! 3. any other date on the page.
//!
//! Inside the winning tier the earliest date wins. Pages are separated by
//! form feed (`\u{c}`); page 1 is tried first, then each later page one at a
//! time until one yields a date, so cost stays linear and stops early.
//! Scanning is hand written (no regex), and the clock is never read: the
//! caller passes `today`.

use time::{Date, Duration, Month};

/// Page separator used in stored text.
pub const PAGE_SEP: char = '\u{c}';

/// Finds the most plausible issue date in `text`, or `None`.
pub fn detect_date(text: &str, today: Date) -> Option<Date> {
    let limit = today.checked_add(Duration::days(2)).unwrap_or(Date::MAX);
    text.split(PAGE_SEP)
        .find_map(|page| detect_on_page(page, limit))
}

/// Rank of a candidate; lower wins. Within a tier the earliest date wins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Label,
    Place,
    Top,
    Rest,
}

/// What the words in front of a date say about it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Label,
    /// Due date, birth date or period: never an issue date.
    Excluded,
}

fn detect_on_page(page: &str, limit: Date) -> Option<Date> {
    let lines: Vec<&str> = page.lines().filter(|l| !l.trim().is_empty()).collect();
    let top_lines = (lines.len() / 3).max(3);
    let mut best: Option<(Tier, Date)> = None;
    // A label or exclusion word that ends a date-less line applies to the
    // date starting the next line.
    let mut pending: Option<Kind> = None;
    for (idx, line) in lines.iter().enumerate() {
        let in_top = idx < top_lines;
        let (cands, any_dates) = line_candidates(line, limit, pending);
        pending = if any_dates { None } else { trailing_kind(line) };
        for (date, tier) in cands {
            let tier = tier.unwrap_or(if in_top { Tier::Top } else { Tier::Rest });
            if best.is_none_or(|b| (tier, date) < b) {
                best = Some((tier, date));
            }
        }
    }
    best.map(|(_, d)| d)
}

const LABELS: &[&str] = &[
    "datum",
    "rechnungsdatum",
    "ausstellungsdatum",
    "belegdatum",
    "briefdatum",
    "date",
    "ausgestellt",
    "erstellt",
];
const DUE: &[&str] = &["zahlbar", "due", "payable", "spätestens", "expires"];
const BIRTH: &[&str] = &[
    "geb",
    "geboren",
    "geburtsdatum",
    "born",
    "dob",
    "birth",
    "birthday",
];
const JOINER_WORDS: &[&str] = &["bis", "zum", "to", "until", "through"];
const PLACE_STOP: &[&str] = &[
    "rechnung",
    "betrag",
    "gutschrift",
    "lastschrift",
    "überweisung",
    "invoice",
    "lieferung",
    "bestellung",
    "kontoauszug",
    "buchung",
    "zahlung",
    "auftrag",
    "order",
    "payment",
];

fn is_period(w: &str) -> bool {
    w == "period" || w.ends_with("zeitraum")
}

fn is_excluded_word(w: &str) -> bool {
    is_period(w)
        || DUE.contains(&w)
        || BIRTH.contains(&w)
        || w.contains("fällig")
        || w.contains("faellig")
        || w.starts_with("zahlungsziel")
        || w.starts_with("zahlungsfrist")
}

fn classify(words: &[String]) -> Option<Kind> {
    let pair = |a: &str, b: &str| words.windows(2).any(|p| p[0] == a && p[1] == b);
    if words.iter().any(|w| is_excluded_word(w))
        || pair("gültig", "bis")
        || pair("gueltig", "bis")
        || pair("valid", "until")
    {
        Some(Kind::Excluded)
    } else if words.iter().any(|w| LABELS.contains(&w.as_str())) {
        Some(Kind::Label)
    } else {
        None
    }
}

/// Kind carried by the end of a line (`Rechnungsdatum:`, `Fällig am`).
/// Exclusions look at the last 3 words. A label only counts when it is the
/// last word and the line is short (at most 4 words) or ends with `:`, so
/// table headers and prose mentioning a label do not leak into the next line.
fn trailing_kind(line: &str) -> Option<Kind> {
    let words = words_of(line);
    match classify(&words[words.len().saturating_sub(3)..])? {
        Kind::Excluded => Some(Kind::Excluded),
        Kind::Label => {
            let last_is_label = words.last().is_some_and(|w| LABELS.contains(&w.as_str()));
            (last_is_label && (words.len() <= 4 || line.trim_end().ends_with(':')))
                .then_some(Kind::Label)
        }
    }
}

struct Found {
    start: usize,
    end: usize,
    date: Date,
}

/// Dates on one line that survive the exclusion rules, each with the tier a
/// label or place prefix gives it (`None`: decided by position), and whether
/// the line holds any date at all.
///
/// Classification is scoped to the segment: only the text between the
/// previous date (or line start) and this date is looked at, so
/// `Datum 01.10.2026, fällig 15.10.2026` keeps the first and drops the second.
fn line_candidates(
    line: &str,
    limit: Date,
    pending: Option<Kind>,
) -> (Vec<(Date, Option<Tier>)>, bool) {
    let c = line.as_bytes();
    let found = scan_line(line, limit);
    let mut out = Vec::new();
    let mut prev_end = 0;
    let mut period_seen = false;
    for (i, f) in found.iter().enumerate() {
        let seg = String::from_utf8_lossy(&c[prev_end..f.start]);
        let words = words_of(&seg);
        let mut kind = classify(&words);
        if i == 0 && seg.chars().all(|ch| !ch.is_alphanumeric()) {
            // The date starts the line: the previous line's label applies.
            kind = match (kind, pending) {
                (Some(Kind::Excluded), _) | (_, Some(Kind::Excluded)) => Some(Kind::Excluded),
                (k, p) => k.or(p),
            };
        }
        period_seen |= words.iter().any(|w| is_period(w));
        let before = i > 0 && joiner(&c[found[i - 1].end..f.start]);
        let after = found.get(i + 1).is_some_and(|n| joiner(&c[f.end..n.start]));
        // `vom/von/from ... bis/to/until <date>`: this date ends an open range.
        // The end word must sit right before the date.
        let open_range = words.last().is_some_and(|last| {
            ["bis", "to", "until"].contains(&last.as_str())
                && seg.trim_end().to_lowercase().ends_with(last.as_str())
                && words[..words.len() - 1]
                    .iter()
                    .any(|w| ["vom", "von", "from"].contains(&w.as_str()))
        });
        prev_end = f.end;
        if period_seen || before || after || open_range || kind == Some(Kind::Excluded) {
            continue;
        }
        let tier = if kind == Some(Kind::Label) {
            Some(Tier::Label)
        } else if i == 0 && is_place(&seg, &line[f.end..]) {
            Some(Tier::Place)
        } else {
            None
        };
        out.push((f.date, tier));
    }
    (out, !found.is_empty())
}

/// The gap between two dates is only dashes and range words.
fn joiner(between: &[u8]) -> bool {
    let s = String::from_utf8_lossy(between).to_lowercase();
    let dash = s.contains(['–', '—', '-']);
    let s = s.replace(['–', '—', '-'], " ");
    let mut words = s.split_whitespace().peekable();
    // No words: only a dash joins (whitespace such as NBSP does not).
    if words.peek().is_none() {
        return dash;
    }
    words.all(|w| JOINER_WORDS.contains(&w))
}

/// `Hamburg, 12.09.2026`, `Frankfurt am Main, den 12.09.2026`: the whole
/// text before the date is 1 to 3 words (first capitalised) and a comma,
/// optionally followed by `den` / `am`, and the date ends the line.
fn is_place(seg: &str, rest: &str) -> bool {
    if rest.chars().any(|c| c.is_alphanumeric()) {
        return false;
    }
    let Some((place, after)) = seg.rsplit_once(',') else {
        return false;
    };
    if !matches!(after.trim().to_lowercase().as_str(), "" | "den" | "am") {
        return false;
    }
    let tokens: Vec<&str> = place.split_whitespace().collect();
    if !(1..=3).contains(&tokens.len())
        || !tokens.iter().all(|t| {
            t.chars()
                .all(|c| c.is_alphabetic() || matches!(c, '-' | '.'))
        })
    {
        return false;
    }
    let first = tokens[0];
    first.chars().next().is_some_and(|c| c.is_uppercase())
        && first.chars().count() >= 2
        && !tokens
            .iter()
            .any(|t| PLACE_STOP.contains(&t.to_lowercase().as_str()))
}

fn words_of(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphabetic())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect()
}

/// Cheap pre-filter: every month name starts with one of these letters.
fn is_month_initial(b: u8) -> bool {
    matches!(
        b.to_ascii_lowercase(),
        b'j' | b'f' | b'm' | b'a' | b's' | b'o' | b'n' | b'd'
    )
}

/// Scans bytes, but decides word boundaries on decoded neighbouring chars so
/// `€`, `„`, NBSP and the like next to a date do not block it. Match starts
/// are always ASCII bytes, so slicing at them is safe.
fn scan_line(s: &str, limit: Date) -> Vec<Found> {
    let c = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let b = c[i];
        let digit = b.is_ascii_digit();
        if !digit && !is_month_initial(b) {
            i += 1;
            continue;
        }
        let start_ok = i == 0 || {
            let p = s[..i].chars().next_back().unwrap_or(' ');
            !p.is_alphanumeric()
                && !(matches!(p, '.' | '/' | '-') && i >= 2 && c[i - 2].is_ascii_digit())
        };
        if start_ok {
            let hit = if digit {
                numeric(s, i).or_else(|| day_first(s, i))
            } else {
                month_first(s, i)
            };
            if let Some(h) = hit
                && let Some(date) = make_date(h, limit)
            {
                out.push(Found {
                    start: i,
                    end: h.end,
                    date,
                });
                i = h.end;
                continue;
            }
        }
        i += 1;
    }
    out
}

#[derive(Clone, Copy)]
struct Hit {
    end: usize,
    year: i32,
    month: u8,
    day: u8,
    /// The year was written with exactly two digits.
    short: bool,
}

/// Builds a valid date, expanding literal 2-digit years and applying the
/// year and future limits.
fn make_date(h: Hit, limit: Date) -> Option<Date> {
    let month = Month::try_from(h.month).ok()?;
    let year = if h.short {
        match Date::from_calendar_date(2000 + h.year, month, h.day) {
            Ok(dt) if dt <= limit => 2000 + h.year,
            _ => 1900 + h.year,
        }
    } else {
        h.year
    };
    if year < 1900 {
        return None;
    }
    let date = Date::from_calendar_date(year, month, h.day).ok()?;
    (date <= limit).then_some(date)
}

/// Reads a run of ASCII digits at `i`, returning (value, length, end).
/// Runs longer than 6 digits are rejected (phone numbers, IBANs).
fn digits(c: &[u8], i: usize) -> Option<(i32, usize, usize)> {
    let mut j = i;
    let mut v = 0i32;
    while j < c.len() && c[j].is_ascii_digit() {
        if j - i >= 6 {
            return None;
        }
        v = v * 10 + i32::from(c[j] - b'0');
        j += 1;
    }
    (j > i).then_some((v, j - i, j))
}

/// No letter or digit, and no `./-` joined to a following digit, may
/// continue a match.
fn end_ok(s: &str, end: usize) -> bool {
    let mut it = s[end..].chars();
    match it.next() {
        None => true,
        Some(ch) if ch.is_alphanumeric() => false,
        Some('.' | '/' | '-') => !it.next().is_some_and(|n| n.is_ascii_digit()),
        Some(_) => true,
    }
}

/// `17.11.2026`, `17.11.26`, `17/11/2026` (day first) and `2026-11-17`
/// (optionally followed by `T<digit>`, an ISO timestamp).
fn numeric(s: &str, i: usize) -> Option<Hit> {
    let c = s.as_bytes();
    let (a, alen, p) = digits(c, i)?;
    let sep = *c.get(p)?;
    if alen == 4 && sep == b'-' {
        let (m, mlen, p2) = digits(c, p + 1)?;
        if !(1..=2).contains(&mlen) || *c.get(p2)? != b'-' {
            return None;
        }
        let (d, dlen, p3) = digits(c, p2 + 1)?;
        let timestamp = c.get(p3) == Some(&b'T') && c.get(p3 + 1).is_some_and(u8::is_ascii_digit);
        if !(1..=2).contains(&dlen) || !(timestamp || end_ok(s, p3)) {
            return None;
        }
        return Some(Hit {
            end: p3,
            year: a,
            month: m as u8,
            day: d as u8,
            short: false,
        });
    }
    if !(1..=2).contains(&alen) || !matches!(sep, b'.' | b'/') {
        return None;
    }
    let (m, mlen, p2) = digits(c, p + 1)?;
    if !(1..=2).contains(&mlen) || *c.get(p2)? != sep {
        return None;
    }
    let (y, ylen, p3) = digits(c, p2 + 1)?;
    if !matches!(ylen, 2 | 4) || !end_ok(s, p3) {
        return None;
    }
    Some(Hit {
        end: p3,
        year: y,
        month: m as u8,
        day: a as u8,
        short: ylen == 2,
    })
}

fn month_of(word: &str) -> Option<u8> {
    Some(match word {
        "januar" | "january" | "jan" => 1,
        "februar" | "february" | "feb" => 2,
        "märz" | "maerz" | "marz" | "mär" | "march" | "mar" => 3,
        "april" | "apr" => 4,
        "mai" | "may" => 5,
        "juni" | "june" | "jun" => 6,
        "juli" | "july" | "jul" => 7,
        "august" | "aug" => 8,
        "september" | "sep" | "sept" => 9,
        "oktober" | "october" | "okt" | "oct" => 10,
        "november" | "nov" => 11,
        "dezember" | "december" | "dez" | "dec" => 12,
        _ => return None,
    })
}

/// Reads a month name at `i` plus an optional `.`; returns (month, end).
fn month_word(s: &str, i: usize) -> Option<(u8, usize)> {
    let len = s[i..]
        .char_indices()
        .find(|(_, ch)| !ch.is_alphabetic())
        .map_or(s.len() - i, |(k, _)| k);
    if len == 0 || len > 12 {
        return None;
    }
    let j = i + len;
    let w = &s[i..j];
    let m = if w.is_ascii() {
        let mut buf = [0u8; 12];
        let b = &mut buf[..w.len()];
        b.copy_from_slice(w.as_bytes());
        b.make_ascii_lowercase();
        month_of(std::str::from_utf8(b).ok()?)?
    } else {
        month_of(&w.to_lowercase())?
    };
    Some((
        m,
        if s.as_bytes().get(j) == Some(&b'.') {
            j + 1
        } else {
            j
        },
    ))
}

/// Skips whitespace, including NBSP (U+00A0) and narrow NBSP (U+202F).
fn skip_ws(s: &str, i: usize) -> usize {
    let rest = &s[i..];
    i + (rest.len() - rest.trim_start().len())
}

fn year4(s: &str, i: usize) -> Option<(i32, usize)> {
    let (y, len, end) = digits(s.as_bytes(), i)?;
    (len == 4 && end_ok(s, end)).then_some((y, end))
}

/// `17. November 2026`, `17 Nov. 2026`.
fn day_first(s: &str, i: usize) -> Option<Hit> {
    let c = s.as_bytes();
    let (d, len, mut p) = digits(c, i)?;
    if !(1..=2).contains(&len) {
        return None;
    }
    if c.get(p) == Some(&b'.') {
        p += 1;
    }
    let (m, p2) = month_word(s, skip_ws(s, p))?;
    let (y, end) = year4(s, skip_ws(s, p2))?;
    Some(Hit {
        end,
        year: y,
        month: m,
        day: d as u8,
        short: false,
    })
}

/// `November 17, 2026`, `Nov 17th 2026`.
fn month_first(s: &str, i: usize) -> Option<Hit> {
    let c = s.as_bytes();
    let (m, p) = month_word(s, i)?;
    let (d, len, mut p2) = digits(c, skip_ws(s, p))?;
    if !(1..=2).contains(&len) {
        return None;
    }
    if c.get(p2).is_some_and(u8::is_ascii_alphabetic) {
        let suffix = c.get(p2..p2 + 2)?.to_ascii_lowercase();
        if matches!(suffix.as_slice(), b"st" | b"nd" | b"rd" | b"th") {
            p2 += 2;
        } else {
            return None;
        }
    }
    if c.get(p2) == Some(&b',') {
        p2 += 1;
    }
    let (y, end) = year4(s, skip_ws(s, p2))?;
    Some(Hit {
        end,
        year: y,
        month: m,
        day: d as u8,
        short: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! date {
        ($y:literal - $m:literal - $d:literal) => {
            Date::from_calendar_date($y, Month::try_from($m as u8).unwrap(), $d).unwrap()
        };
    }

    fn today() -> Date {
        date!(2026 - 11 - 17)
    }

    fn d(s: &str) -> Option<Date> {
        detect_date(s, today())
    }

    #[test]
    fn formats() {
        let want = Some(date!(2026 - 11 - 17));
        for s in [
            "17.11.2026",
            "17.11.26",
            "17/11/2026",
            "2026-11-17",
            "17. November 2026",
            "17. Nov. 2026",
            "November 17, 2026",
            "17 November 2026",
            "Nov 17, 2026",
        ] {
            assert_eq!(d(s), want, "{s}");
        }
        assert_eq!(d("3. März 2025"), Some(date!(2025 - 3 - 3)));
        assert_eq!(d("1. Mai 2025"), Some(date!(2025 - 5 - 1)));
    }

    #[test]
    fn labels_win() {
        assert_eq!(
            d("Kundennr 01.01.2020\nRechnungsdatum: 05.10.2026"),
            Some(date!(2026 - 10 - 5))
        );
    }

    #[test]
    fn place_line_counts_as_label() {
        assert_eq!(
            d("Max Muster\nHamburg, 12.09.2026\nSehr geehrte"),
            Some(date!(2026 - 9 - 12))
        );
    }

    #[test]
    fn excluded_kinds() {
        assert_eq!(
            d("Datum 01.10.2026\nZahlbar bis 15.10.2026"),
            Some(date!(2026 - 10 - 1))
        );
        assert_eq!(d("fällig am 20.11.2026"), None);
        assert_eq!(d("Zeitraum 01.10.2026 – 31.10.2026"), None);
        assert_eq!(d("vom 01.10.2026 bis 31.10.2026"), None);
        assert_eq!(d("geb. 03.04.1980"), None);
        assert_eq!(d("DOB 03/04/1980"), None);
        assert_eq!(d("25.12.2026"), None);
        assert_eq!(d("19.11.2026"), Some(date!(2026 - 11 - 19)));
        assert_eq!(d("01.01.1850"), None);
    }

    #[test]
    fn top_third_then_earliest() {
        let mut text = String::from("Brief 10.03.2026\n");
        for _ in 0..20 {
            text.push_str("Zeile ohne Datum\n");
        }
        text.push_str("Anhang 01.01.2025\n");
        assert_eq!(d(&text), Some(date!(2026 - 3 - 10)));
        assert_eq!(
            d("Eingang 20.05.2026\nBrief 10.03.2026\nText"),
            Some(date!(2026 - 3 - 10))
        );
    }

    #[test]
    fn pages() {
        assert_eq!(
            d("no date here\u{c}Rechnung 03.03.2026"),
            Some(date!(2026 - 3 - 3))
        );
        assert_eq!(
            d("Brief 01.02.2026\u{c}Datum 05.05.2026"),
            Some(date!(2026 - 2 - 1))
        );
    }

    #[test]
    fn ignores_numbers_that_are_not_dates() {
        for s in [
            "Tel 040 123 456 78",
            "IBAN DE12 3456 7890 1234 5678 90",
            "Belegnr 2026.11.17.004",
            "Termin 12.30 Uhr",
        ] {
            assert_eq!(d(s), None, "{s}");
        }
    }

    #[test]
    fn invalid_calendar_dates_are_skipped() {
        assert_eq!(d("31.02.2026"), None);
        assert_eq!(d("00.13.2026"), None);
        assert_eq!(d("29.02.2024"), Some(date!(2024 - 2 - 29)));
    }

    #[test]
    fn slash_dates_are_day_first() {
        assert_eq!(d("03/04/2026"), Some(date!(2026 - 4 - 3)));
    }

    #[test]
    fn two_digit_years() {
        assert_eq!(d("05.06.99"), Some(date!(1999 - 6 - 5)));
        assert_eq!(d("05.06.25"), Some(date!(2025 - 6 - 5)));
    }

    #[test]
    fn label_on_previous_line() {
        assert_eq!(
            d("Kundennr 01.01.2020\nRechnungsdatum\n05.10.2026"),
            Some(date!(2026 - 10 - 5))
        );
        assert_eq!(
            d("Geburtsdatum:\n03.04.1980\nBrief 10.03.2026"),
            Some(date!(2026 - 3 - 10))
        );
        assert_eq!(
            d("Fällig am\n01.10.2025\nDatum 05.09.2025"),
            Some(date!(2025 - 9 - 5))
        );
    }

    #[test]
    fn non_ascii_neighbours() {
        let want = Some(date!(2026 - 11 - 17));
        for s in [
            "Datum:\u{a0}17.11.2026",
            "„17.11.2026“",
            "17.\u{a0}November 2026",
            "17.11.2026€",
        ] {
            assert_eq!(d(s), want, "{s}");
        }
        assert_eq!(d("17. MÄRZ 2026"), Some(date!(2026 - 3 - 17)));
    }

    #[test]
    fn place_rules() {
        assert_eq!(
            d("Max\nHamburg, den 12.09.2026"),
            Some(date!(2026 - 9 - 12))
        );
        assert_eq!(
            d("Zeile\nLastschrift, 03.10.2025\nDatum: 05.10.2025"),
            Some(date!(2025 - 10 - 5))
        );
        // Stoplisted words are no place; a real place outranks the top third.
        assert_eq!(
            d("Brief 02.10.2025\nLastschrift, 03.10.2025"),
            Some(date!(2025 - 10 - 2))
        );
        assert_eq!(
            d("Brief 02.10.2025\nHamburg, den 12.09.2026"),
            Some(date!(2026 - 9 - 12))
        );
        // Date must end the line.
        assert_eq!(
            d("Brief 02.10.2025\nHamburg, 12.09.2026 Seite 1"),
            Some(date!(2025 - 10 - 2))
        );
    }

    #[test]
    fn german_compounds_and_new_words() {
        assert_eq!(d("Abrechnungszeitraum 01.10.2026"), None);
        assert_eq!(d("Zahlungsziel 14.11.2026"), None);
        assert_eq!(d("Fälligkeitsdatum 14.11.2026"), None);
        assert_eq!(d("spätestens 14.11.2026"), None);
        assert_eq!(d("gültig bis 14.11.2026"), None);
        assert_eq!(d("valid until 14.11.2026"), None);
        assert_eq!(d("expires 14.11.2026"), None);
        assert_eq!(
            d("Brief 01.01.2025\nErstellt am 02.02.2025"),
            Some(date!(2025 - 2 - 2))
        );
        assert_eq!(
            d("Brief 01.01.2025\nBriefdatum 02.02.2025"),
            Some(date!(2025 - 2 - 2))
        );
    }

    #[test]
    fn pending_label_is_narrow() {
        assert_eq!(
            d("Datum Text Betrag\n01.03.2025 Miete\nRechnungsdatum 05.10.2026"),
            Some(date!(2026 - 10 - 5))
        );
        assert_eq!(
            d(
                "Zahlbar innerhalb 14 Tagen ab Rechnungsdatum\n01.03.2025 Abschlag\nDatum: 05.10.2025"
            ),
            Some(date!(2025 - 10 - 5))
        );
    }

    #[test]
    fn open_range_is_narrow_and_dash_edges() {
        assert_eq!(
            d("Sent from my phone to you 05.10.2025"),
            Some(date!(2025 - 10 - 5))
        );
        assert_eq!(d("von 01.10. bis 31.10.2026"), None);
        assert_eq!(d("01.10.2026 – 31.10.2026"), None);
        assert_eq!(d("Datum 17.11.2026\u{202f}"), Some(date!(2026 - 11 - 17)));
        assert_eq!(d("17.\u{202f}November 2026"), Some(date!(2026 - 11 - 17)));
        // Whitespace alone (NBSP) between two dates is no range.
        assert_eq!(d("01.10.2026\u{a0}31.10.2026"), Some(date!(2026 - 10 - 1)));
    }

    #[test]
    fn range_joiners() {
        assert_eq!(d("01.10.2026 bis zum 31.10.2026"), None);
        assert_eq!(d("vom 01.10. bis 31.10.2026"), None);
    }

    #[test]
    fn year_and_timestamp_edges() {
        assert_eq!(d("17.11.0026"), None);
        assert_eq!(d("2026-11-17T10:00:00Z"), Some(date!(2026 - 11 - 17)));
    }

    #[test]
    fn boundary_cases() {
        for s in [
            "x17.11.2026",
            "17.11.20261",
            "1.17.11.2026",
            "17.11.2026.5",
            "17.11,26 €",
        ] {
            assert_eq!(d(s), None, "{s}");
        }
        assert_eq!(d("Nov 17th, 2026"), Some(date!(2026 - 11 - 17)));
        assert_eq!(
            d("Datum 05.10.2026\nRechnungsdatum 03.10.2026"),
            Some(date!(2026 - 10 - 3))
        );
        assert_eq!(
            d("Datum 01.10.2026, fällig 15.10.2026"),
            Some(date!(2026 - 10 - 1))
        );
    }

    #[test]
    fn huge_tail_after_page_one_is_never_scanned() {
        let garbage = "Tel 040 123 456 78 IBAN DE12 3456 7890 1234 5678 90 Nov\n".repeat(90_000);
        assert!(garbage.len() > 5_000_000);
        let text = format!("Datum 01.02.2026\n\u{c}{garbage}");
        let t = std::time::Instant::now();
        assert_eq!(d(&text), Some(date!(2026 - 2 - 1)));
        assert!(t.elapsed().as_millis() < 50, "{:?}", t.elapsed());
    }

    #[test]
    fn large_text_is_fast() {
        let filler = "Lorem ipsum 040 123 456 78 dolor sit amet\n".repeat(75);
        let mut pages: Vec<String> = (0..200).map(|_| filler.clone()).collect();
        pages[149].push_str("Rechnung 03.03.2026\n");
        let text = pages.join("\u{c}");
        let max = if cfg!(debug_assertions) { 300 } else { 50 };
        let t = std::time::Instant::now();
        assert_eq!(d(&text), Some(date!(2026 - 3 - 3)));
        assert!(t.elapsed().as_millis() < max, "{:?}", t.elapsed());
    }
}
