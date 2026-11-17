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

/// Split `text` into chunks of at most `max_tokens` tokens, consecutive chunks
/// overlapping by `overlap` tokens. The chunks cover the whole text. `tok`
/// must not truncate (the engine's tokenizer does not).
pub fn chunk_text(
    text: &str,
    tok: &Tokenizer,
    max_tokens: usize,
    overlap: usize,
) -> Result<Vec<Chunk>> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let enc = tok
        .encode(text, false)
        .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;
    Ok(chunk_offsets(text, enc.get_offsets(), max_tokens, overlap))
}

/// Core of [`chunk_text`] over token byte offsets (testable without a model).
pub fn chunk_offsets(
    text: &str,
    offsets: &[(usize, usize)],
    max_tokens: usize,
    overlap: usize,
) -> Vec<Chunk> {
    let n = offsets.len();
    if n == 0 || text.trim().is_empty() {
        return Vec::new();
    }
    let max_tokens = max_tokens.max(1);
    let step = max_tokens.saturating_sub(overlap).max(1);

    // byte offset -> char offset
    let mut b2c = vec![0usize; text.len() + 1];
    let mut ci = 0;
    for (bi, ch) in text.char_indices() {
        for slot in &mut b2c[bi..bi + ch.len_utf8()] {
            *slot = ci;
        }
        ci += 1;
    }
    b2c[text.len()] = ci;
    let total_chars = ci;
    let c = |b: usize| b2c[b.min(text.len())];

    let mut out: Vec<Chunk> = Vec::new();
    let mut i = 0;
    loop {
        let end_tok = (i + max_tokens).min(n);
        let last = end_tok == n;
        let start = if i == 0 { 0 } else { c(offsets[i].0) };
        let end = if last {
            total_chars
        } else {
            c(offsets[end_tok - 1].1)
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
