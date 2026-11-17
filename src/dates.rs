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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Label,
    Top,
    Rest,
}

fn detect_on_page(page: &str, limit: Date) -> Option<Date> {
    let lines: Vec<&str> = page.lines().filter(|l| !l.trim().is_empty()).collect();
    let top_lines = (lines.len() / 3).max(3);
    let mut best: Option<(Tier, Date)> = None;
    for (idx, line) in lines.iter().enumerate() {
        let in_top = idx < top_lines;
        for (date, labelled) in line_candidates(line, limit) {
            let tier = if labelled {
                Tier::Label
            } else if in_top {
                Tier::Top
            } else {
                Tier::Rest
            };
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
    "date",
];
const DUE: &[&str] = &[
    "fällig",
    "fälligkeit",
    "fälligkeitsdatum",
    "faellig",
    "zahlbar",
    "due",
    "payable",
];
const PERIOD: &[&str] = &["zeitraum", "abrechnungszeitraum", "period"];
const BIRTH: &[&str] = &[
    "geb",
    "geboren",
    "geburtsdatum",
    "born",
    "dob",
    "birth",
    "birthday",
];
const RANGE_JOINERS: &[&str] = &["bis", "–", "—", "-", "to", "until", "through"];

struct Found {
    start: usize,
    end: usize,
    date: Date,
}

/// Dates on one line that survive the exclusion rules, with a flag telling
/// whether they carry a label or a place prefix.
fn line_candidates(line: &str, limit: Date) -> Vec<(Date, bool)> {
    let c = line.as_bytes();
    let found = scan_line(c, limit);
    let mut out = Vec::new();
    let mut prev_end = 0;
    let mut period_seen = false;
    for (i, f) in found.iter().enumerate() {
        let seg = String::from_utf8_lossy(&c[prev_end..f.start]);
        let words = words_of(&seg);
        let has = |set: &[&str]| words.iter().any(|w| set.contains(&w.as_str()));
        period_seen |= has(PERIOD);
        let before = i > 0 && joiner(&c[found[i - 1].end..f.start]);
        let after = found.get(i + 1).is_some_and(|n| joiner(&c[f.end..n.start]));
        prev_end = f.end;
        if period_seen || before || after || has(DUE) || has(BIRTH) {
            continue;
        }
        out.push((f.date, has(LABELS) || is_place(&seg)));
    }
    out
}

fn joiner(between: &[u8]) -> bool {
    let s = String::from_utf8_lossy(between);
    RANGE_JOINERS.contains(&s.trim().to_lowercase().as_str())
}

/// `<Capitalised word>,` right before the date.
fn is_place(seg: &str) -> bool {
    let Some(t) = seg.trim_end().strip_suffix(',') else {
        return false;
    };
    let word: String = t
        .trim_end()
        .chars()
        .rev()
        .take_while(|c| c.is_alphabetic())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    word.chars().next().is_some_and(|c| c.is_uppercase()) && word.chars().count() >= 2
}

fn words_of(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphabetic())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect()
}

/// Bytes `>= 0x80` count as letters so non-ASCII words never look like gaps.
fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b >= 0x80
}

/// Cheap pre-filter: every month name starts with one of these letters.
fn is_month_initial(b: u8) -> bool {
    matches!(
        b.to_ascii_lowercase(),
        b'j' | b'f' | b'm' | b'a' | b's' | b'o' | b'n' | b'd'
    )
}

fn scan_line(c: &[u8], limit: Date) -> Vec<Found> {
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
            let p = c[i - 1];
            !is_alnum(p)
                && !(matches!(p, b'.' | b'/' | b'-') && i >= 2 && c[i - 2].is_ascii_digit())
        };
        if start_ok {
            let hit = if digit {
                numeric(c, i).or_else(|| day_first(c, i))
            } else {
                month_first(c, i)
            };
            if let Some((end, y, m, d)) = hit
                && let Some(date) = make_date(y, m, d, limit)
            {
                out.push(Found {
                    start: i,
                    end,
                    date,
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Builds a valid date, expanding 2-digit years (`< 100`) and applying the
/// year and future limits.
fn make_date(y: i32, m: u8, d: u8, limit: Date) -> Option<Date> {
    let month = Month::try_from(m).ok()?;
    let year = if y < 100 {
        match Date::from_calendar_date(2000 + y, month, d) {
            Ok(dt) if dt <= limit => 2000 + y,
            _ => 1900 + y,
        }
    } else {
        y
    };
    if year < 1900 {
        return None;
    }
    let date = Date::from_calendar_date(year, month, d).ok()?;
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
fn end_ok(c: &[u8], end: usize) -> bool {
    match c.get(end) {
        None => true,
        Some(&b) if is_alnum(b) => false,
        Some(b'.' | b'/' | b'-') => !c.get(end + 1).is_some_and(u8::is_ascii_digit),
        Some(_) => true,
    }
}

type Hit = (usize, i32, u8, u8);

/// `17.11.2026`, `17.11.26`, `17/11/2026` (day first) and `2026-11-17`.
fn numeric(c: &[u8], i: usize) -> Option<Hit> {
    let (a, alen, p) = digits(c, i)?;
    let sep = *c.get(p)?;
    if alen == 4 && sep == b'-' {
        let (m, mlen, p2) = digits(c, p + 1)?;
        if !(1..=2).contains(&mlen) || *c.get(p2)? != b'-' {
            return None;
        }
        let (d, dlen, p3) = digits(c, p2 + 1)?;
        if !(1..=2).contains(&dlen) || !end_ok(c, p3) {
            return None;
        }
        return Some((p3, a, m as u8, d as u8));
    }
    if !(1..=2).contains(&alen) || !matches!(sep, b'.' | b'/') {
        return None;
    }
    let (m, mlen, p2) = digits(c, p + 1)?;
    if !(1..=2).contains(&mlen) || *c.get(p2)? != sep {
        return None;
    }
    let (y, ylen, p3) = digits(c, p2 + 1)?;
    if !matches!(ylen, 2 | 4) || !end_ok(c, p3) {
        return None;
    }
    Some((p3, y, m as u8, a as u8))
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
fn month_word(c: &[u8], i: usize) -> Option<(u8, usize)> {
    let mut j = i;
    while j < c.len() && is_alnum(c[j]) && !c[j].is_ascii_digit() {
        j += 1;
    }
    if j == i || j - i > 10 {
        return None;
    }
    let w = std::str::from_utf8(&c[i..j]).ok()?;
    let m = if w.is_ascii() {
        let mut buf = [0u8; 10];
        let b = &mut buf[..w.len()];
        b.copy_from_slice(w.as_bytes());
        b.make_ascii_lowercase();
        month_of(std::str::from_utf8(b).ok()?)?
    } else {
        month_of(&w.to_lowercase())?
    };
    Some((m, if c.get(j) == Some(&b'.') { j + 1 } else { j }))
}

fn skip_ws(c: &[u8], mut i: usize) -> usize {
    while i < c.len() && c[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn year4(c: &[u8], i: usize) -> Option<(i32, usize)> {
    let (y, len, end) = digits(c, i)?;
    (len == 4 && end_ok(c, end)).then_some((y, end))
}

/// `17. November 2026`, `17 Nov. 2026`.
fn day_first(c: &[u8], i: usize) -> Option<Hit> {
    let (d, len, mut p) = digits(c, i)?;
    if !(1..=2).contains(&len) {
        return None;
    }
    if c.get(p) == Some(&b'.') {
        p += 1;
    }
    let (m, p2) = month_word(c, skip_ws(c, p))?;
    let (y, end) = year4(c, skip_ws(c, p2))?;
    Some((end, y, m, d as u8))
}

/// `November 17, 2026`, `Nov 17th 2026`.
fn month_first(c: &[u8], i: usize) -> Option<Hit> {
    let (m, p) = month_word(c, i)?;
    let (d, len, mut p2) = digits(c, skip_ws(c, p))?;
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
    let (y, end) = year4(c, skip_ws(c, p2))?;
    Some((end, y, m, d as u8))
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
    fn large_text_is_fast() {
        let filler = "Lorem ipsum 040 123 456 78 dolor sit amet\n".repeat(75);
        let mut pages: Vec<String> = (0..200).map(|_| filler.clone()).collect();
        pages[149].push_str("Rechnung 03.03.2026\n");
        let text = pages.join("\u{c}");
        let t = std::time::Instant::now();
        assert_eq!(d(&text), Some(date!(2026 - 3 - 3)));
        assert!(t.elapsed().as_millis() < 50, "{:?}", t.elapsed());
    }
}
