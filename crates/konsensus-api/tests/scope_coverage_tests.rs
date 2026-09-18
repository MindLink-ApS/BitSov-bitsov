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

fn handler_sources() -> Vec<(String, String)> {
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
    walk(&handlers_dir(), &mut out);
    assert!(!out.is_empty(), "no handler sources found");
    out
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
    for (file, src) in handler_sources() {
        for (n, line) in src.lines().enumerate() {
            let t = line.trim();
            // An extractor parameter, e.g. `_auth: AuthUser,` — not a use/doc/type line.
            if t.ends_with(": AuthUser,") && !t.starts_with("//") {
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
