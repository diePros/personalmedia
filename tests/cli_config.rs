use assert_cmd::Command;
use personal_media::config::validate_public_url;

fn run(sub: &[&str], url: Option<&str>, dir: &std::path::Path) -> assert_cmd::assert::Assert {
    let mut c = Command::cargo_bin("personal-media").unwrap();
    c.args(sub)
        .env("PM_DATA_DIR", dir)
        .env("PM_BIND", "127.0.0.1:0");
    match url {
        Some(u) => c.env("PM_PUBLIC_URL", u),
        None => c.env_remove("PM_PUBLIC_URL"),
    };
    c.assert()
}

#[test]
fn public_url_rules() {
    for ok in [
        "https://node.tailnet.ts.net",
        "https://node.tailnet.ts.net/",
        "https://node.tailnet.ts.net:8443",
        "http://localhost",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://127.0.0.1",
    ] {
        assert!(validate_public_url(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "https://<node>.<tailnet>.ts.net",
        "http://example.com",
        "http://localhost.evil.com",
        "ftp://example.com",
        "https://",
        "https:///path",
        "https://exa mple.com",
        "https://example.com/path",
        "https://user@example.com",
        "https://example.com:notaport",
        "node.tailnet.ts.net",
    ] {
        assert!(validate_public_url(bad).is_err(), "{bad}");
    }
}

#[test]
fn invite_and_serve_fail_fast_on_a_placeholder_url() {
    let dir = tempfile::tempdir().unwrap();
    for sub in [&["invite", "--admin"][..], &["serve"][..]] {
        let a = run(sub, Some("https://<node>.<tailnet>.ts.net"), dir.path()).failure();
        let err = String::from_utf8(a.get_output().stderr.clone()).unwrap();
        assert!(err.contains("PM_PUBLIC_URL"), "{err}");
    }
    // Nothing was created.
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn invite_works_with_a_valid_url() {
    let dir = tempfile::tempdir().unwrap();
    let a = run(
        &["invite", "--admin"],
        Some("https://node.tailnet.ts.net"),
        dir.path(),
    )
    .success();
    let out = String::from_utf8(a.get_output().stdout.clone()).unwrap();
    assert!(
        out.starts_with("https://node.tailnet.ts.net/invite/"),
        "{out}"
    );
}
