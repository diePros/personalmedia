//! `personal-media embed-selftest`: a quick check that the (quantized) model
//! ranks sensibly on this CPU and how fast and large it is. All text here is
//! synthetic and hard-coded.

use std::time::Instant;

use anyhow::{Result, ensure};

use super::Engine;

/// Passages: German and English, one topic each.
pub const PASSAGES: [&str; 6] = [
    "Die Heizkostenabrechnung für das Jahr 2023 zeigt einen Verbrauch von 1200 Kilowattstunden und eine Nachzahlung von 85 Euro.",
    "The lease agreement for the apartment runs for twenty-four months and may be terminated with three months notice.",
    "Der Arzt verordnete ein Antibiotikum gegen die Mandelentzündung und empfahl drei Tage Bettruhe.",
    "The car insurance policy covers collision damage, theft and liability, with a deductible of 300 euros.",
    "Die Steuererklärung muss bis zum 31. Juli beim Finanzamt eingereicht werden, Belege sind beizufügen.",
    "Our flight to Lisbon departs at 7:45 in the morning from terminal two, boarding starts at 7:10.",
];

/// (query, index of the passage that must rank first, cross-language).
pub const QUERIES: [(&str, usize, bool); 4] = [
    ("Wie hoch ist die Nachzahlung für die Heizung?", 0, false),
    ("Wie lange ist die Kündigungsfrist meiner Wohnung?", 1, true),
    (
        "Which medicine did the doctor prescribe for the sore throat?",
        2,
        true,
    ),
    ("What does my car insurance cover?", 3, false),
];

/// At least this many queries must rank the expected passage first.
pub const REQUIRED: usize = 3;
const ITERATIONS: usize = 10;

pub struct QueryResult {
    pub query: &'static str,
    pub cross_language: bool,
    pub expected: usize,
    pub top: usize,
}

impl QueryResult {
    pub fn ok(&self) -> bool {
        self.top == self.expected
    }
}

pub struct Report {
    pub queries: Vec<QueryResult>,
    pub ms_per_passage: f64,
    pub chunk_tokens_run: usize,
    pub peak_rss_mb: Option<f64>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.queries.iter().filter(|q| q.ok()).count() >= REQUIRED
    }
}

/// Index of the highest score (first on ties).
pub fn argmax(scores: &[f32]) -> usize {
    let mut best = 0;
    for (i, s) in scores.iter().enumerate() {
        if *s > scores[best] {
            best = i;
        }
    }
    best
}

/// Peak resident set size of this process (`VmHWM`) in MB, if readable.
pub fn peak_rss_mb() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb: f64 = s
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(kb / 1024.0)
}

/// Long synthetic text; its first chunk is about 300 tokens.
fn long_text() -> String {
    let mut t = String::new();
    for i in 0..60 {
        t.push_str(PASSAGES[i % PASSAGES.len()]);
        t.push(' ');
    }
    t
}

/// Rank the queries against the passages and time a 300-token chunk run.
pub fn run(engine: &Engine) -> Result<Report> {
    let refs: Vec<&str> = PASSAGES.to_vec();
    let passages = engine.embed_passages(&refs)?;
    let mut queries = Vec::new();
    for (q, expected, cross) in QUERIES {
        let qv = engine.embed_query(q)?;
        let scores: Vec<f32> = passages
            .iter()
            .map(|p| p.iter().zip(&qv).map(|(a, b)| a * b).sum())
            .collect();
        queries.push(QueryResult {
            query: q,
            cross_language: cross,
            expected,
            top: argmax(&scores),
        });
    }

    let text = long_text();
    let chunks = engine.chunk(&text)?;
    let first = chunks.first().ok_or_else(|| anyhow::anyhow!("no chunks"))?;
    let chunk: String = text
        .chars()
        .skip(first.start)
        .take(first.end - first.start)
        .collect();
    ensure!(!chunk.is_empty(), "empty chunk");
    engine.embed_passages(&[chunk.as_str()])?; // warm-up
    let started = Instant::now();
    for _ in 0..ITERATIONS {
        engine.embed_passages(&[chunk.as_str()])?;
    }
    let ms_per_passage = started.elapsed().as_secs_f64() * 1000.0 / ITERATIONS as f64;
    Ok(Report {
        queries,
        ms_per_passage,
        chunk_tokens_run: super::CHUNK_TOKENS,
        peak_rss_mb: peak_rss_mb(),
    })
}
