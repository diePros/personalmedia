//! Bounded-memory chunking of huge texts (C1). Own test binary so the peak
//! RSS (`VmHWM`) belongs to this test alone. Needs the model files (see
//! tests/embed.rs; set `PM_TEST_MODELS_DIR`) and prints `SKIP` otherwise.

use std::path::PathBuf;
use std::time::Duration;

use personal_media::embed::model::{MODEL_FILE, TOKENIZER_FILE};
use personal_media::embed::{Engine, MAX_EMBED_CHARS, MODEL, WINDOW_CHARS};

fn model_or_skip(test: &str) -> Option<PathBuf> {
    let root =
        std::env::var("PM_TEST_MODELS_DIR").unwrap_or_else(|_| "/tmp/pms-test-models".into());
    let models = PathBuf::from(root).join("models");
    let dir = MODEL.dir(&models);
    if dir.join(MODEL_FILE).exists() && dir.join(TOKENIZER_FILE).exists() {
        Some(models)
    } else {
        eprintln!("SKIP {test}: model files not found in {}", dir.display());
        None
    }
}

/// Peak resident set size of this process in MiB.
fn peak_rss_mib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let kb: u64 = s
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap();
    kb / 1024
}

#[test]
fn huge_text_embeds_in_bounded_memory() {
    let Some(models) = model_or_skip("huge_text_embeds_in_bounded_memory") else {
        return;
    };
    // ~20 MB of text, far beyond the cap.
    let text: String = (0..1_400_000u32)
        .map(|i| format!("Vertrag{} Zahlung{} ", i % 977, i % 31))
        .collect();
    assert!(text.len() > 20_000_000, "{}", text.len());
    let engine = Engine::new(models, Duration::from_secs(600));
    let out = engine.chunk_bounded(&text, MAX_EMBED_CHARS).unwrap();

    // Only the first MAX_EMBED_CHARS characters were looked at ...
    assert!(out.truncated);
    assert_eq!(out.chars_tokenized, MAX_EMBED_CHARS);
    assert_eq!(out.chunks.last().unwrap().end, MAX_EMBED_CHARS);
    assert!(out.chunks.len() > 1000, "{} chunks", out.chunks.len());
    // ... in windows, never the whole text at once ...
    assert!(out.max_window_chars <= WINDOW_CHARS);
    // ... and consecutive chunks still overlap across window borders.
    for w in out.chunks.windows(2) {
        assert!(w[1].start < w[0].end, "chunks must overlap");
    }
    // Whole-text tokenisation of this input peaks near 1.7 GiB (measured);
    // the model itself is ~450 MiB.
    let peak = peak_rss_mib();
    eprintln!("peak RSS {peak} MiB for {} chars", text.chars().count());
    assert!(peak < 900, "peak RSS {peak} MiB");
}
