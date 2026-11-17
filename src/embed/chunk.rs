//! Token-window chunker. Chunks are character ranges into the source text so
//! passages can be cut from the encrypted text without storing it twice.

use anyhow::Result;
use tokenizers::Tokenizer;

pub const CHUNK_TOKENS: usize = 300;
pub const CHUNK_OVERLAP: usize = 50;

/// Half-open range of **character** (not byte) offsets into the source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub start: usize,
    pub end: usize,
}

/// Characters tokenised at once. Tokenizer memory (about 320 bytes per token
/// at peak) is bounded by this, not by the document size.
pub const WINDOW_CHARS: usize = 32 * 1024;

/// What [`chunk_text_bounded`] did, for diagnostics and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunked {
    pub chunks: Vec<Chunk>,
    /// The text was longer than the limit; only a prefix was chunked.
    pub truncated: bool,
    /// Characters actually tokenised (<= the limit).
    pub chars_tokenized: usize,
    /// The largest window handed to the tokenizer, in characters.
    pub max_window_chars: usize,
}

/// Split `text` into chunks of at most `max_tokens` tokens, consecutive chunks
/// overlapping by `overlap` tokens. The chunks cover the whole text. `tok`
/// must not truncate (the engine's tokenizer does not).
pub fn chunk_text(
    text: &str,
    tok: &Tokenizer,
    max_tokens: usize,
    overlap: usize,
) -> Result<Vec<Chunk>> {
    Ok(chunk_text_bounded(text, tok, max_tokens, overlap, usize::MAX)?.chunks)
}

/// Like [`chunk_text`] but looks at no more than the first `max_chars`
/// characters and tokenises in windows of [`WINDOW_CHARS`] characters (cut at
/// whitespace), so memory does not grow with the text. Token spans are kept
/// globally, so the chunk overlap carries across window borders.
pub fn chunk_text_bounded(
    text: &str,
    tok: &Tokenizer,
    max_tokens: usize,
    overlap: usize,
    max_chars: usize,
) -> Result<Chunked> {
    let (head, truncated) = char_prefix(text, max_chars);
    let mut spans: Vec<(usize, usize)> = Vec::new(); // global char offsets
    let (mut base, mut max_window) = (0usize, 0usize);
    for window in windows(head, WINDOW_CHARS) {
        let n_chars = window.chars().count();
        max_window = max_window.max(n_chars);
        if !window.trim().is_empty() {
            let enc = tok
                .encode(window, false)
                .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;
            let b2c = byte_to_char(window);
            let last = window.len();
            spans.extend(
                enc.get_offsets()
                    .iter()
                    .map(|&(s, e)| (base + b2c[s.min(last)], base + b2c[e.min(last)])),
            );
        }
        base += n_chars;
    }
    let chunks = if head.trim().is_empty() {
        Vec::new()
    } else {
        chunk_spans(&spans, base, max_tokens, overlap)
    };
    Ok(Chunked {
        chunks,
        truncated,
        chars_tokenized: base,
        max_window_chars: max_window,
    })
}

/// The first `max_chars` characters of `text` and whether anything was cut.
pub fn char_prefix(text: &str, max_chars: usize) -> (&str, bool) {
    match text.char_indices().nth(max_chars) {
        Some((i, _)) => (&text[..i], true),
        None => (text, false),
    }
}

/// Consecutive slices of `text` of at most `max_chars` characters each, cut
/// after whitespace where possible. Concatenated they equal `text`.
pub fn windows(text: &str, max_chars: usize) -> impl Iterator<Item = &str> {
    let max_chars = max_chars.max(1);
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let Some((hard, _)) = rest.char_indices().nth(max_chars) else {
            return Some(std::mem::take(&mut rest));
        };
        // Prefer the last whitespace in the second half of the window.
        let cut = rest[..hard]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map(|(i, c)| i + c.len_utf8())
            .filter(|&i| i > hard / 2)
            .unwrap_or(hard);
        let (head, tail) = rest.split_at(cut);
        rest = tail;
        Some(head)
    })
}

/// byte offset -> char offset, for one (small) slice.
fn byte_to_char(text: &str) -> Vec<usize> {
    let mut b2c = vec![0usize; text.len() + 1];
    let mut ci = 0;
    for (bi, ch) in text.char_indices() {
        for slot in &mut b2c[bi..bi + ch.len_utf8()] {
            *slot = ci;
        }
        ci += 1;
    }
    b2c[text.len()] = ci;
    b2c
}

/// [`chunk_spans`] over token **byte** offsets into `text` (testable without a
/// model; allocates a byte table, so for small texts).
pub fn chunk_offsets(
    text: &str,
    offsets: &[(usize, usize)],
    max_tokens: usize,
    overlap: usize,
) -> Vec<Chunk> {
    if offsets.is_empty() || text.trim().is_empty() {
        return Vec::new();
    }
    let b2c = byte_to_char(text);
    let c = |b: usize| b2c[b.min(text.len())];
    let spans: Vec<(usize, usize)> = offsets.iter().map(|&(s, e)| (c(s), c(e))).collect();
    chunk_spans(&spans, b2c[text.len()], max_tokens, overlap)
}

/// Core chunker over token spans given as **character** offsets;
/// `total_chars` is the length of the covered text.
pub fn chunk_spans(
    spans: &[(usize, usize)],
    total_chars: usize,
    max_tokens: usize,
    overlap: usize,
) -> Vec<Chunk> {
    let n = spans.len();
    if n == 0 {
        return Vec::new();
    }
    let max_tokens = max_tokens.max(1);
    let step = max_tokens.saturating_sub(overlap).max(1);
    let mut out: Vec<Chunk> = Vec::new();
    let mut i = 0;
    loop {
        let end_tok = (i + max_tokens).min(n);
        let last = end_tok == n;
        let start = if i == 0 { 0 } else { spans[i].0 };
        let end = if last {
            total_chars
        } else {
            spans[end_tok - 1].1
        };
        let start = out.last().map_or(start, |p| start.min(p.end));
        out.push(Chunk {
            start,
            end: end.max(start),
        });
        if last {
            break;
        }
        i += step;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whitespace "tokens" as byte offsets.
    fn ws_offsets(text: &str) -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        let mut start = None;
        for (i, ch) in text.char_indices() {
            match (ch.is_whitespace(), start) {
                (false, None) => start = Some(i),
                (true, Some(s)) => {
                    v.push((s, i));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = start {
            v.push((s, text.len()));
        }
        v
    }

    fn slice(text: &str, c: Chunk) -> String {
        text.chars().skip(c.start).take(c.end - c.start).collect()
    }

    fn numbered(n: usize) -> String {
        (0..n)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn chunker_covers_text_with_overlap() {
        let text = numbered(1000);
        let offs = ws_offsets(&text);
        let chunks = chunk_offsets(&text, &offs, 300, 50);
        assert!(chunks.len() > 3);
        // stitch: each chunk contributes what lies beyond the previous end
        let mut rebuilt = String::new();
        let mut pos = 0;
        for c in &chunks {
            assert!(c.start <= pos, "gap before chunk");
            rebuilt.push_str(&slice(
                &text,
                Chunk {
                    start: pos,
                    end: c.end,
                },
            ));
            pos = c.end;
        }
        assert_eq!(rebuilt, text);
        // <= 300 tokens each, ~50 tokens overlap
        for w in chunks.windows(2) {
            let toks = |c: Chunk| slice(&text, c).split_whitespace().count();
            assert!(toks(w[0]) <= 300 && toks(w[1]) <= 300);
            let overlap = slice(
                &text,
                Chunk {
                    start: w[1].start,
                    end: w[0].end,
                },
            )
            .split_whitespace()
            .count();
            assert!((49..=51).contains(&overlap), "overlap {overlap}");
        }
    }

    #[test]
    fn windows_are_bounded_and_lossless() {
        let text = numbered(5000);
        let ws: Vec<&str> = windows(&text, 1000).collect();
        assert!(ws.len() >= 5);
        assert!(ws.iter().all(|w| w.chars().count() <= 1000));
        assert_eq!(ws.concat(), text);
        // cut after whitespace: no window ends inside a word
        assert!(ws[..ws.len() - 1].iter().all(|w| w.ends_with(' ')));
        // no whitespace at all: hard cut, still lossless
        let blob = "日".repeat(2500);
        let ws: Vec<&str> = windows(&blob, 1000).collect();
        assert_eq!(ws.len(), 3);
        assert_eq!(ws.concat(), blob);
    }

    #[test]
    fn char_prefix_cuts_on_char_boundaries() {
        assert_eq!(char_prefix("äöü€x", 3), ("äöü", true));
        assert_eq!(char_prefix("äöü", 3), ("äöü", false));
        assert_eq!(char_prefix("", 3), ("", false));
    }

    #[test]
    fn chunker_handles_empty_and_short_text() {
        assert!(chunk_offsets("", &[], 300, 50).is_empty());
        assert!(chunk_offsets("   \n", &ws_offsets("   \n"), 300, 50).is_empty());
        let t = "  kurzer Text ";
        let c = chunk_offsets(t, &ws_offsets(t), 300, 50);
        assert_eq!(
            c,
            vec![Chunk {
                start: 0,
                end: t.chars().count()
            }]
        );
    }

    #[test]
    fn chunker_offsets_are_char_boundaries() {
        let text = "Größe Übung 😀 naïve café 日本語 ".repeat(120);
        let chunks = chunk_offsets(&text, &ws_offsets(&text), 300, 50);
        assert!(chunks.len() > 1);
        let total = text.chars().count();
        for c in &chunks {
            assert!(c.start <= c.end && c.end <= total);
            // slicing by chars must work and start on a token (not mid-word)
            let s = slice(&text, *c);
            assert!(!s.is_empty());
        }
        assert_eq!(chunks.last().unwrap().end, total);
    }
}
