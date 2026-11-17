//! Ranking logic of `embed-selftest` on this machine. Model-gated: set
//! `PM_TEST_MODELS_DIR` (the data dir holding `models/`); without the files the
//! test prints `SKIP`.

use std::path::PathBuf;
use std::time::Duration;

use personal_media::embed::model::{MODEL_FILE, TOKENIZER_FILE};
use personal_media::embed::selftest::{self, REQUIRED};
use personal_media::embed::{Engine, MODEL};

#[test]
fn argmax_picks_highest_first_on_ties() {
    assert_eq!(selftest::argmax(&[0.1, 0.9, 0.9, 0.2]), 1);
}

#[test]
fn selftest_ranking_passes_on_this_machine() {
    let root =
        std::env::var("PM_TEST_MODELS_DIR").unwrap_or_else(|_| "/tmp/pms-test-models".into());
    let models = PathBuf::from(root).join("models");
    let dir = MODEL.dir(&models);
    if !(dir.join(MODEL_FILE).exists() && dir.join(TOKENIZER_FILE).exists()) {
        eprintln!("SKIP selftest_ranking_passes_on_this_machine: model files not found");
        return;
    }
    let engine = Engine::new(models, Duration::from_secs(600));
    let report = selftest::run(&engine).unwrap();
    let hits = report.queries.iter().filter(|q| q.ok()).count();
    assert!(
        report.passed() && hits >= REQUIRED,
        "only {hits} of {} queries ranked first",
        report.queries.len()
    );
    assert!(report.ms_per_passage > 0.0);
}
