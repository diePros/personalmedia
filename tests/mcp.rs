//! MCP endpoint over HTTP: auth, scope enforcement and the six tools.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, header};
use bytes::Bytes;
use common::*;
use data_encoding::BASE64;
use futures_util::stream;
use personal_media::documents::{OnDuplicate, UploadMeta};
use personal_media::keyring::Unlocked;
use personal_media::tokens::create_token;
use personal_media::user_db::{
    Access, Channel, Content, Level, TextStatus, TokenScope, get_document, set_document_access,
    set_text, tag_ids,
};
use serde_json::{Value, json};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Fx {
    t: TestApp,
    u: Arc<Unlocked>,
}

impl Fx {
    fn new() -> Fx {
        let t = TestApp::new();
        let c = t.session_for("alice");
        let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
        Fx { t, u }
    }

    fn token(&self, access: Access, content: Content, tags: Option<&[&str]>) -> String {
        let ids = tags.map(|names| {
            let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            self.u.with_db(|c| tag_ids(c, &names)).unwrap()
        });
        let scope = TokenScope {
            access,
            content,
            tags: ids,
        };
        create_token(&self.t.state.sys, &self.u, "hermes", scope, now()).unwrap()
    }

    /// Stores a document with the given extracted text and MCP level.
    async fn doc(&self, name: &str, text: &str, tags: &[&str], mcp: Option<Level>) -> String {
        let meta = UploadMeta {
            filename: name.to_owned(),
            mime: Some("application/octet-stream".into()),
            title: Some(format!("title of {name}")),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            document_date: None,
        };
        let body = stream::once(std::future::ready(Ok::<_, anyhow::Error>(Bytes::from(
            format!("bytes of {name}"),
        ))));
        let out = self
            .t
            .state
            .docs
            .store(
                &self.u,
                meta,
                Box::pin(body),
                OnDuplicate::Keep,
                None,
                now(),
            )
            .await
            .unwrap();
        let id = match serde_json::to_value(out).unwrap()["id"].as_str() {
            Some(id) => id.to_owned(),
            None => panic!("not stored"),
        };
        self.u.with_db(|c| {
            set_text(c, &id, TextStatus::Done, Some(text), None, 1).unwrap();
            if let Some(l) = mcp {
                set_document_access(c, &id, Channel::Mcp, Some(l)).unwrap();
            }
        });
        id
    }

    async fn post(&self, token: Option<&str>, body: &Value) -> (u16, Value) {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(t) = token {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let resp = self
            .t
            .request(b.body(Body::from(body.to_string())).unwrap())
            .await;
        let status = resp.status().as_u16();
        let bytes = body_bytes(resp).await;
        let v = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, v)
    }

    /// `tools/call`; returns `(is_error, parsed text content)`.
    async fn call(&self, token: &str, tool: &str, args: Value) -> (bool, Value) {
        let (status, v) = self
            .post(
                Some(token),
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                        "params":{"name":tool,"arguments":args}}),
            )
            .await;
        assert_eq!(status, 200, "{v}");
        let r = &v["result"];
        let text = r["content"][0]["text"].as_str().unwrap();
        let parsed = serde_json::from_str(text).unwrap_or(Value::String(text.to_owned()));
        (r["isError"].as_bool().unwrap(), parsed)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_or_bad_token_401() {
    let f = Fx::new();
    let tok = f.token(Access::Read, Content::FullText, None);
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
    assert_eq!(f.post(None, &body).await.0, 401);
    assert_eq!(f.post(Some("garbage"), &body).await.0, 401);
    // Right id, wrong secret.
    let wrong = format!("{}{}", &tok[..tok.len() - 4], "0000");
    assert_ne!(wrong, tok);
    assert_eq!(f.post(Some(&wrong), &body).await.0, 401);
    // Unknown id, well formed.
    let unknown = format!("pm_{}_{}", "a".repeat(32), "b".repeat(64));
    assert_eq!(f.post(Some(&unknown), &body).await.0, 401);
    assert_eq!(f.post(Some(&tok), &body).await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_have_empty_body() {
    let f = Fx::new();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(header::AUTHORIZATION, "Bearer nope")
        .body(Body::from("{}"))
        .unwrap();
    let resp = f.t.request(req).await;
    assert_eq!(resp.status(), 401);
    assert!(body_bytes(resp).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_token_rejected_immediately() {
    let f = Fx::new();
    let tok = f.token(Access::Read, Content::FullText, None);
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
    // Warm the cache.
    assert_eq!(f.post(Some(&tok), &body).await.0, 200);
    assert_eq!(f.t.state.tokens.len(), 1);
    let id =
        f.t.state
            .sys
            .token_ids_for_user(&f.u.user_id)
            .unwrap()
            .remove(0);
    personal_media::tokens::revoke_token(&f.t.state.sys, &f.u, &id, &f.t.state.tokens).unwrap();
    assert_eq!(f.post(Some(&tok), &body).await.0, 401);
    // Even if the cache entry survived (stale), the missing system row fails it.
    assert_eq!(f.t.state.tokens.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_user_token_401() {
    let f = Fx::new();
    let tok = f.token(Access::Read, Content::FullText, None);
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
    assert_eq!(f.post(Some(&tok), &body).await.0, 200);
    // Disable without evicting: the per-request user check must catch it.
    f.t.state.sys.set_disabled(&f.u.user_id, true).unwrap();
    assert_eq!(f.post(Some(&tok), &body).await.0, 401);
    f.t.state.sys.set_disabled(&f.u.user_id, false).unwrap();
    assert_eq!(f.post(Some(&tok), &body).await.0, 200);
    f.t.state.sys.delete_user(&f.u.user_id).unwrap();
    assert_eq!(f.post(Some(&tok), &body).await.0, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_auth_failures_rate_limited() {
    let f = Fx::new();
    let tok = f.token(Access::Read, Content::FullText, None);
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
    for _ in 0..10 {
        assert_eq!(f.post(Some("bad"), &body).await.0, 401);
    }
    // Locked: even the right token is refused with 429.
    assert_eq!(f.post(Some(&tok), &body).await.0, 429);
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_requests_do_not_lock() {
    let f = Fx::new();
    let tok = f.token(Access::Read, Content::FullText, None);
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
    for _ in 0..30 {
        assert_eq!(f.post(Some(&tok), &body).await.0, 200);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn client_handshake_with_mcp_headers() {
    let f = Fx::new();
    let tok = f.token(Access::Read, Content::FullText, None);
    let send = |body: Value, extra: Option<(&'static str, &'static str)>| {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::AUTHORIZATION, format!("Bearer {tok}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("user-agent", "hermes-mcp/1.0");
        if let Some((k, v)) = extra {
            b = b.header(k, v);
        }
        b.body(Body::from(body.to_string())).unwrap()
    };
    let resp =
        f.t.request(send(
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"hermes","version":"1"}}}),
            None,
        ))
        .await;
    assert_eq!(resp.status(), 200);
    assert!(
        header_str(&resp, "content-type").starts_with("application/json"),
        "plain JSON, not SSE"
    );
    let v: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["id"], 0);
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(v["result"]["serverInfo"]["name"], "personal-media");
    assert!(v["result"]["capabilities"]["tools"].is_object());

    // The initialized notification is acknowledged without a body.
    let resp =
        f.t.request(send(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            Some(("mcp-protocol-version", "2025-06-18")),
        ))
        .await;
    assert_eq!(resp.status(), 202);
    assert!(body_bytes(resp).await.is_empty());

    let resp =
        f.t.request(send(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            Some(("mcp-protocol-version", "2025-06-18")),
        ))
        .await;
    assert_eq!(resp.status(), 200);
    let v: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["result"]["tools"].as_array().unwrap().len(), 6);

    // An unsupported version is answered with ours.
    let resp = f
        .t
        .request(send(
            json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}),
            None,
        ))
        .await;
    let v: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    // Unknown methods are JSON-RPC errors.
    let resp =
        f.t.request(send(json!({"jsonrpc":"2.0","id":3,"method":"nope"}), None))
            .await;
    let v: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["error"]["code"], -32601);
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_list_has_six_tools() {
    let f = Fx::new();
    let tok = f.token(Access::Read, Content::MetadataOnly, None);
    let (status, v) = f
        .post(
            Some(&tok),
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await;
    assert_eq!(status, 200);
    let mut names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "get_document",
            "list_documents",
            "list_tags",
            "search_documents",
            "update_document",
            "upload_document"
        ]
    );
    for t in v["result"]["tools"].as_array().unwrap() {
        assert_eq!(t["inputSchema"]["type"], "object");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_only_token_never_returns_text_or_snippets() {
    let f = Fx::new();
    let id = f
        .doc("a.dat", "streng geheim inhalt", &[], Some(Level::Full))
        .await;
    let tok = f.token(Access::Read, Content::MetadataOnly, None);
    let (err, hits) = f
        .call(&tok, "search_documents", json!({"query":"geheim"}))
        .await;
    assert!(!err);
    assert_eq!(hits, json!([]));
    // The filename is metadata, so that match is found, but without a snippet.
    let (_, hits) = f
        .call(&tok, "search_documents", json!({"query":"a.dat"}))
        .await;
    assert_eq!(hits.as_array().unwrap().len(), 1);
    assert!(hits[0].get("snippet").is_none());
    let (err, d) = f.call(&tok, "get_document", json!({"id": id})).await;
    assert!(!err);
    assert_eq!(d["id"], id.as_str());
    assert!(d.get("text").is_none());
    assert!(!d.to_string().contains("geheim"));
    let (_, list) = f.call(&tok, "list_documents", json!({})).await;
    assert!(!list.to_string().contains("geheim"));
}

#[tokio::test(flavor = "multi_thread")]
async fn full_text_token_gets_snippets_and_text() {
    let f = Fx::new();
    let full = f
        .doc("a.dat", "streng geheim inhalt", &[], Some(Level::Full))
        .await;
    let meta = f
        .doc("b.dat", "auch geheim", &[], Some(Level::Metadata))
        .await;
    let off = f
        .doc("c.dat", "ebenfalls geheim", &[], Some(Level::Off))
        .await;
    let tok = f.token(Access::Read, Content::FullText, None);
    let (_, hits) = f
        .call(&tok, "search_documents", json!({"query":"geheim"}))
        .await;
    let hits = hits.as_array().unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0]["id"], full.as_str());
    assert!(hits[0]["snippet"].as_str().unwrap().contains("geheim"));
    let (_, d) = f.call(&tok, "get_document", json!({"id": full})).await;
    assert_eq!(d["text"], "streng geheim inhalt");
    assert_eq!(d["truncated"], false);
    // Metadata-level document: no text even for a full_text token.
    let (_, d) = f.call(&tok, "get_document", json!({"id": meta})).await;
    assert!(d.get("text").is_none());
    // Off: not found.
    let (err, d) = f.call(&tok, "get_document", json!({"id": off})).await;
    assert!(err);
    assert_eq!(d, "document not found");
    let (_, list) = f.call(&tok, "list_documents", json!({})).await;
    assert_eq!(list.as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn long_text_is_truncated() {
    let f = Fx::new();
    let id = f
        .doc("a.dat", &"x".repeat(100_050), &[], Some(Level::Full))
        .await;
    let tok = f.token(Access::Read, Content::FullText, None);
    let (_, d) = f.call(&tok, "get_document", json!({"id": id})).await;
    assert_eq!(d["text"].as_str().unwrap().len(), 100_000);
    assert_eq!(d["truncated"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn tag_restricted_token_cannot_see_other_documents() {
    let f = Fx::new();
    let ok = f
        .doc("a.dat", "geheim eins", &["work"], Some(Level::Full))
        .await;
    let hidden = f
        .doc("b.dat", "geheim zwei", &["private"], Some(Level::Full))
        .await;
    let tok = f.token(Access::Read, Content::FullText, Some(&["work"]));
    let (_, hits) = f
        .call(&tok, "search_documents", json!({"query":"geheim"}))
        .await;
    let ids: Vec<&str> = hits
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [ok.as_str()]);
    let (_, list) = f.call(&tok, "list_documents", json!({})).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (_, tags) = f.call(&tok, "list_tags", json!({})).await;
    assert_eq!(tags, json!(["work"]));
    let (err, d) = f.call(&tok, "get_document", json!({"id": hidden})).await;
    assert!(err);
    assert_eq!(d, "document not found");
    let (err, _) = f.call(&tok, "get_document", json!({"id": ok})).await;
    assert!(!err);
}

#[tokio::test(flavor = "multi_thread")]
async fn read_only_token_cannot_upload() {
    let f = Fx::new();
    let id = f.doc("a.dat", "x", &[], Some(Level::Full)).await;
    let tok = f.token(Access::Read, Content::FullText, None);
    let (err, msg) = f
        .call(
            &tok,
            "upload_document",
            json!({"filename":"n.txt","content_base64":BASE64.encode(b"hi")}),
        )
        .await;
    assert!(err);
    assert_eq!(msg, "token is read-only");
    let (err, msg) = f
        .call(&tok, "update_document", json!({"id": id, "title":"x"}))
        .await;
    assert!(err);
    assert_eq!(msg, "token is read-only");
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_and_update_with_unrestricted_token() {
    let f = Fx::new();
    let tok = f.token(Access::ReadWrite, Content::FullText, None);
    let (err, out) = f
        .call(
            &tok,
            "upload_document",
            json!({"filename":"n.dat","content_base64":BASE64.encode(b"hello"),
                   "title":"Hello","tags":["x"],"date":"2024-05-06"}),
        )
        .await;
    assert!(!err, "{out}");
    assert_eq!(out["status"], "stored");
    let id = out["id"].as_str().unwrap().to_owned();
    // Same bytes again: duplicate of a visible document.
    let (_, dup) = f
        .call(
            &tok,
            "upload_document",
            json!({"filename":"n.dat","content_base64":BASE64.encode(b"hello")}),
        )
        .await;
    assert_eq!(dup["status"], "duplicate");
    let (err, _) = f
        .call(
            &tok,
            "update_document",
            json!({"id": id, "title":"Renamed","tags":["y","z"],"date":"2024-06-07"}),
        )
        .await;
    assert!(!err);
    let (_, d) = f.call(&tok, "get_document", json!({"id": id})).await;
    assert_eq!(d["title"], "Renamed");
    assert_eq!(d["tags"], json!(["y", "z"]));
    assert_eq!(d["document_date"], "2024-06-07");
    // Bad input is a tool error.
    let (err, _) = f
        .call(
            &tok,
            "upload_document",
            json!({"filename":"n","content_base64":"!!"}),
        )
        .await;
    assert!(err);
    let (err, _) = f
        .call(&tok, "update_document", json!({"id": id, "date":"nope"}))
        .await;
    assert!(err);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_upload_rejected() {
    let t = TestApp::with_config(|c| c.max_upload_bytes = 1024);
    let c = t.session_for("alice");
    let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
    let f = Fx { t, u };
    let tok = f.token(Access::ReadWrite, Content::FullText, None);
    let (err, msg) = f
        .call(
            &tok,
            "upload_document",
            json!({"filename":"big.dat","content_base64":BASE64.encode(&vec![7u8; 2048])}),
        )
        .await;
    assert!(err);
    assert_eq!(msg, "upload too large");
}

#[tokio::test(flavor = "multi_thread")]
async fn restricted_upload_gets_allowed_tag() {
    let f = Fx::new();
    let tok = f.token(
        Access::ReadWrite,
        Content::FullText,
        Some(&["work", "other"]),
    );
    let (err, out) = f
        .call(
            &tok,
            "upload_document",
            json!({"filename":"n.dat","content_base64":BASE64.encode(b"one"),"tags":["private"]}),
        )
        .await;
    assert!(!err, "{out}");
    let id = out["id"].as_str().unwrap();
    let (_, d) = f.call(&tok, "get_document", json!({"id": id})).await;
    let mut tags: Vec<&str> = d["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    tags.sort();
    // Ruling N: the token only sees the allowed tag; the owner sees both.
    assert_eq!(tags, ["work"]);
    let stored = f.u.with_db(|c| get_document(c, id)).unwrap().unwrap();
    assert_eq!(stored.tags, ["private", "work"]);
    // A given allowed tag is not supplemented.
    let (_, out) = f
        .call(
            &tok,
            "upload_document",
            json!({"filename":"m.dat","content_base64":BASE64.encode(b"two"),"tags":["other"]}),
        )
        .await;
    let (_, d) = f.call(&tok, "get_document", json!({"id": out["id"]})).await;
    assert_eq!(d["tags"], json!(["other"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn restricted_upload_does_not_reveal_hidden_duplicate() {
    let f = Fx::new();
    // A hidden document (other tag) with the same bytes as the upload below.
    let hidden = f.doc("h.dat", "x", &["private"], Some(Level::Full)).await;
    let _ = hidden;
    let tok = f.token(Access::ReadWrite, Content::FullText, Some(&["work"]));
    let (err, out) = f
        .call(
            &tok,
            "upload_document",
            json!({"filename":"h.dat","content_base64":BASE64.encode(b"bytes of h.dat")}),
        )
        .await;
    assert!(!err);
    assert_eq!(
        out["status"], "stored",
        "hidden duplicate must not be revealed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn update_cannot_remove_last_allowed_tag() {
    let f = Fx::new();
    let id = f
        .doc("a.dat", "x", &["work", "extra"], Some(Level::Full))
        .await;
    let hidden = f.doc("b.dat", "y", &["private"], Some(Level::Full)).await;
    let tok = f.token(Access::ReadWrite, Content::FullText, Some(&["work"]));
    let (err, msg) = f
        .call(&tok, "update_document", json!({"id": id, "tags":["extra"]}))
        .await;
    assert!(err);
    assert_eq!(msg, "tags must include an allowed tag");
    let (err, msg) = f
        .call(&tok, "update_document", json!({"id": id, "tags":[]}))
        .await;
    assert!(err);
    assert_eq!(msg, "tags must include an allowed tag");
    let (err, _) = f
        .call(
            &tok,
            "update_document",
            json!({"id": id, "tags":["work","new"]}),
        )
        .await;
    assert!(!err);
    // A document outside the allow-list cannot be touched at all.
    let (err, msg) = f
        .call(
            &tok,
            "update_document",
            json!({"id": hidden, "title":"pwn"}),
        )
        .await;
    assert!(err);
    assert_eq!(msg, "document not found");
}

// ---- bearer upload via /api/upload ----

async fn api_upload(
    f: &Fx,
    token: Option<&str>,
    fields: &[(&str, &str)],
    name: &str,
    bytes: &[u8],
) -> (u16, Value) {
    const B: &str = "pm-bearer-boundary";
    let mut body = Vec::new();
    for (k, v) in fields {
        body.extend_from_slice(
            format!("--{B}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!("--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{B}--\r\n").as_bytes());
    let mut b = Request::builder()
        .method(Method::POST)
        .uri("/api/upload")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={B}"),
        );
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let mut req = b.body(Body::from(body)).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo::<std::net::SocketAddr>(PEER.parse().unwrap()));
    let resp = f.t.request(req).await;
    let status = resp.status().as_u16();
    let bytes = body_bytes(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn bearer_upload_via_api_upload() {
    let f = Fx::new();
    let rw = f.token(Access::ReadWrite, Content::MetadataOnly, Some(&["work"]));
    let (status, out) =
        api_upload(&f, Some(&rw), &[("tags", "private")], "n.dat", b"payload").await;
    assert_eq!(status, 200, "{out}");
    assert_eq!(out["status"], "stored");
    let id = out["id"].as_str().unwrap();
    let doc =
        f.u.with_db(|c| personal_media::user_db::get_document(c, id))
            .unwrap()
            .unwrap();
    assert!(doc.tags.contains(&"work".to_string()), "{:?}", doc.tags);

    // Read-only tokens may not upload; bad tokens are 401.
    let ro = f.token(Access::Read, Content::FullText, None);
    assert_eq!(api_upload(&f, Some(&ro), &[], "x.dat", b"p2").await.0, 403);
    assert_eq!(
        api_upload(&f, Some("pm_bad"), &[], "x.dat", b"p2").await.0,
        401
    );
    assert_eq!(api_upload(&f, None, &[], "x.dat", b"p2").await.0, 303);

    // A hidden document with identical bytes is not revealed as a duplicate.
    let _ = f.doc("h.dat", "x", &["private"], Some(Level::Full)).await;
    let (status, out) = api_upload(&f, Some(&rw), &[], "h2.dat", b"bytes of h.dat").await;
    assert_eq!(status, 200);
    assert_eq!(out["status"], "stored");
}

fn sys_conn(f: &Fx) -> rusqlite::Connection {
    rusqlite::Connection::open(f.t.dir.path().join("system.db")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_token_wrap_rejected_while_user_unlocked() {
    use personal_media::crypto::{INFO_TOKEN, Key32, aad, secret_kek, wrap_key};
    let f = Fx::new();
    let real = f.token(Access::Read, Content::FullText, None);
    let token_id = &real[3..35];
    let secret = [7u8; 32];
    let forged = wrap_key(
        &secret_kek(&secret, INFO_TOKEN),
        &Key32::from_bytes([9u8; 32]),
        aad::umk_token(token_id).as_bytes(),
    );
    sys_conn(&f)
        .execute(
            "UPDATE tokens SET umk_wrapped=?1 WHERE token_id=?2",
            rusqlite::params![forged, token_id],
        )
        .unwrap();
    let (status, _) = f
        .post(
            Some(&format!("pm_{token_id}_{}", hex::encode(secret))),
            &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn swapped_token_rows_between_users_rejected() {
    let f = Fx::new();
    let real = f.token(Access::Read, Content::FullText, None);
    let token_id = real[3..35].to_string();
    let bob = f.t.session_for("bobby");
    let bob_id =
        f.t.state
            .sessions
            .get(&bob.cookie)
            .unwrap()
            .unlocked
            .user_id
            .clone();
    sys_conn(&f)
        .execute(
            "UPDATE tokens SET user_id=?1 WHERE token_id=?2",
            rusqlite::params![bob_id, token_id],
        )
        .unwrap();
    let (status, _) = f
        .post(
            Some(&real),
            &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn reinserted_revoked_token_row_rejected() {
    use personal_media::tokens::revoke_token;
    let f = Fx::new();
    let real = f.token(Access::Read, Content::FullText, None);
    let token_id = real[3..35].to_string();
    let (uid, wrap) = f.t.state.sys.token(&token_id).unwrap().unwrap();
    revoke_token(&f.t.state.sys, &f.u, &token_id, &f.t.state.tokens).unwrap();
    f.t.state.sys.insert_token(&token_id, &uid, &wrap).unwrap();
    let (status, _) = f
        .post(
            Some(&real),
            &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn restricted_token_never_sees_other_tag_names() {
    let f = Fx::new();
    let id = f
        .doc(
            "a.txt",
            "plain body",
            &["work", "hiv-therapy"],
            Some(Level::Full),
        )
        .await;
    let tok = f.token(Access::Read, Content::FullText, Some(&["work"]));

    let (err, tags) = f.call(&tok, "list_tags", json!({})).await;
    assert!(!err);
    assert_eq!(tags, json!(["work"]));

    let (_, hits) = f
        .call(&tok, "search_documents", json!({"query": "title"}))
        .await;
    assert_eq!(hits[0]["tags"], json!(["work"]));
    assert!(!hits.to_string().contains("hiv"));

    let (_, listed) = f.call(&tok, "list_documents", json!({})).await;
    assert_eq!(listed[0]["tags"], json!(["work"]));

    let (_, got) = f.call(&tok, "get_document", json!({"id": id})).await;
    assert_eq!(got["tags"], json!(["work"]));
    assert!(!got.to_string().contains("hiv"));

    // Hidden tag names are not searchable or filterable either.
    let (_, by_name) = f
        .call(&tok, "search_documents", json!({"query": "hiv"}))
        .await;
    assert_eq!(by_name, json!([]));
    let (_, by_tag) = f
        .call(&tok, "list_documents", json!({"tags": ["hiv-therapy"]}))
        .await;
    assert_eq!(by_tag, json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn restricted_update_preserves_hidden_tags() {
    let f = Fx::new();
    let id = f
        .doc(
            "a.txt",
            "plain body",
            &["work", "hiv-therapy"],
            Some(Level::Full),
        )
        .await;
    let tok = f.token(Access::ReadWrite, Content::FullText, Some(&["work"]));
    let (err, _) = f
        .call(
            &tok,
            "update_document",
            json!({"id": id, "tags": ["work", "extra"]}),
        )
        .await;
    assert!(!err);
    let doc = f.u.with_db(|c| get_document(c, &id)).unwrap().unwrap();
    assert_eq!(doc.tags, vec!["extra", "hiv-therapy", "work"]);
}
