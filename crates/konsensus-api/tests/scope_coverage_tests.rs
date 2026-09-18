//! genome #72: every dangerous route must DEMAND its scope, not merely have one.
//!
//! A partial migration is worse than none, because it looks finished. The first pass of
//! this work missed `send_onchain`, `open_channel` and `close_channel` purely because
//! their parameter is named `_user` rather than `_auth` — three spend routes left
//! unenforced while the change appeared complete. This test reads the handler sources
//! and fails if a listed handler still takes a bare `AuthUser`, so that gap cannot
//! reopen silently.

use std::path::{Path, PathBuf};

const SPEND: &[&str] = &[
    "pay_invoice",
    "keysend",
    "send_onchain",
    "open_channel",
    "close_channel",
    "send_file",
    "send_message",
    "compose_message",
];

/// Key material and identity replacement — what loopback presence must never reach.
const IDENTITY: &[&str] = &["reveal_mnemonic", "restore_identity", "verify_mnemonic"];

const ADMIN: &[&str] = &[
    "import_peers",
    "export_peers",
    "export_bundle",
    "connect_peer",
    "publish_gossip",
    "write_page",
    "delete_page",
];

fn handlers_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers")
}

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file in the crate, not just `src/handlers`.
///
/// The first version of this guard walked only `src/handlers`, which made
/// `src/ws.rs` structurally invisible to it: that endpoint authenticates itself
/// rather than using an extractor, so it was silently exempt from the whole
/// authorization migration while every coverage test stayed green.
fn all_sources() -> Vec<(String, String)> {
    walk_rs(&src_dir())
}

fn walk_rs(root: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read handlers dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push((
                    path.display().to_string(),
                    std::fs::read_to_string(&path).expect("read handler"),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    assert!(!out.is_empty(), "no sources found under {}", root.display());
    out
}

fn handler_sources() -> Vec<(String, String)> {
    walk_rs(&handlers_dir())
}

/// `fn name(...)` through to the end of its body, by brace balance.
fn function_body(src: &str, at: usize) -> String {
    let rest = &src[at..];
    let Some(open) = rest.find('{') else {
        return rest.to_string();
    };
    let mut depth = 0usize;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[..open + i + 1].to_string();
                }
            }
            _ => {}
        }
    }
    rest.to_string()
}

/// `fn name(` up to the closing paren of the parameter list.
fn signature_of(src: &str, name: &str) -> Option<String> {
    let idx = src.find(&format!("fn {name}("))?;
    let rest = &src[idx..];
    let end = rest.find(") ->").or_else(|| rest.find(") {"))?;
    Some(rest[..end].to_string())
}

fn assert_scoped(handlers: &[&str], scope: &str) {
    let sources = handler_sources();
    let mut bad = Vec::new();
    for h in handlers {
        match sources
            .iter()
            .find_map(|(f, src)| signature_of(src, h).map(|sig| (f.clone(), sig)))
        {
            None => bad.push(format!("{h}: handler not found (renamed or removed?)")),
            Some((file, sig)) => {
                if !sig.contains(&format!("ScopedAuth<{scope}>")) {
                    bad.push(format!(
                        "{h} in {file} does not demand ScopedAuth<{scope}>: {}",
                        sig.split_whitespace().collect::<Vec<_>>().join(" ")
                    ));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "routes missing {scope} enforcement:\n  {}",
        bad.join("\n  ")
    );
}

#[test]
fn every_spend_route_demands_spend_scope() {
    assert_scoped(SPEND, "Spend");
}

#[test]
fn every_identity_route_demands_identity_scope() {
    assert_scoped(IDENTITY, "Identity");
}

#[test]
fn representative_admin_routes_demand_admin_scope() {
    assert_scoped(ADMIN, "Admin");
}

/// The exhaustive invariant, and the one that actually closes this hole.
///
/// The per-scope lists above are hand-written, so they only prove what someone remembered
/// to list. Twice during this ticket that was not enough: a first pass missed three spend
/// routes whose parameter was named `_user`, and a second pass missed every handler
/// declared `pub(super) async fn` — 45 authenticated handlers were still accepting *any*
/// valid token, including a loopback one, while the lists above were green.
///
/// A bare `AuthUser` extractor performs authentication but no authorization. This test
/// therefore admits no allowlist: every authenticated handler must name the scope it
/// requires. A new route cannot be added unscoped without failing here.
#[test]
fn no_handler_accepts_an_unscoped_token() {
    let mut bad = Vec::new();
    for (file, src) in all_sources() {
        // `auth.rs` defines both `AuthUser` and the `ScopedAuth` that wraps it, so its own
        // field declarations are not handler extractors.
        if file.ends_with("src/auth.rs") {
            continue;
        }
        for (n, line) in src.lines().enumerate() {
            let t = line.trim();
            // An extractor parameter, e.g. `_auth: AuthUser,`. A `pub` prefix makes it a
            // struct field instead, and `//` a comment.
            if t.ends_with(": AuthUser,") && !t.starts_with("//") && !t.starts_with("pub ") {
                bad.push(format!("{file}:{}: {t}", n + 1));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} handler(s) still take a bare AuthUser, which authenticates but does not \
         authorize — a loopback token would be accepted:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}

/// The issuance constraint itself. Both issuers previously called one shared
/// `create_token`, so a change made for the loopback path would silently have altered
/// the key-proof path too.
#[test]
fn issuers_name_their_own_scopes() {
    let src = std::fs::read_to_string(handlers_dir().join("auth_routes.rs"))
        .expect("read auth_routes.rs");

    let local = function_text(&src, "issue_local_token");
    assert!(
        local.contains("Scope::loopback_only()"),
        "/auth/local must mint only the loopback scope set"
    );
    assert!(
        !local.contains("Scope::all()"),
        "/auth/local must never mint full authority"
    );

    let key_proof = function_text(&src, "issue_token");
    assert!(
        key_proof.contains("Scope::all()"),
        "the key-proof path must keep full authority explicitly"
    );
}

fn function_text(src: &str, name: &str) -> String {
    let start = src
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("{name} not found"));
    let rest = &src[start..];
    let end = rest[1..]
        .find("\nasync fn ")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// Generalizes the calendar defect rather than listing its three handlers.
///
/// `create_event`, `update_event` and `create_rsvp` required only `admin` while calling
/// `create_payment_proof`, which at a nonzero price dispatches a keysend or an invoice
/// payment. An admin-without-spend token therefore passed authorization for an operation
/// that moves value. The list-driven spend check did not name those handlers, so it saw
/// nothing.
///
/// The rule is the invariant, not the list: if a function can reach the payment helper, it
/// must demand `spend`.
#[test]
fn every_function_that_can_pay_demands_spend() {
    let mut bad = Vec::new();
    for (file, src) in all_sources() {
        let mut from = 0;
        while let Some(rel) = src[from..].find("async fn ") {
            let at = from + rel;
            let body = function_body(&src, at);
            from = at + body.len().max(1);

            if !body.contains("create_payment_proof(") {
                continue;
            }
            let name = body
                .trim_start_matches("async fn ")
                .split('(')
                .next()
                .unwrap_or("<unknown>")
                .trim()
                .to_string();
            // Only the signature, so a `Spend` mentioned deep in the body cannot satisfy it.
            let sig = body.split_once(") ->").map(|(s, _)| s).unwrap_or(&body);
            // Route handlers take axum extractors, so they receive `State<Arc<AppState>>`.
            // Internal machinery (the payment helper itself, the per-member room fanout)
            // takes `&AppState` and is only reachable through a handler that IS checked
            // here. Excluding by shape rather than by filename keeps the rest of each
            // module covered — `compose.rs` also holds the paid message handlers.
            if !sig.contains("State<Arc<AppState>>") {
                continue;
            }
            if !sig.contains("ScopedAuth<Spend>") {
                bad.push(format!("{file}: {name}"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} function(s) can dispatch a payment without demanding the spend scope:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}

/// Any endpoint that validates a token itself, instead of going through `ScopedAuth`, must
/// also authorize it. `src/ws.rs` did the first and not the second: a token the REST routes
/// refused was upgraded and subscribed to plaintext message broadcasts.
#[test]
fn self_authenticating_endpoints_also_check_scope() {
    let mut bad = Vec::new();
    for (file, src) in all_sources() {
        if file.ends_with("auth.rs") || !src.contains("validate_token(") {
            continue;
        }
        if !src.contains("Scope::") {
            bad.push(file);
        }
    }
    assert!(
        bad.is_empty(),
        "{} file(s) validate a token without ever consulting its scopes:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}
