//! `konsensus chain-tip` is read-only: it shows the chain tip source of an
//! existing node and whether it is an explorer default, and it never changes
//! the config or writes any file next to it. No chain source is contacted.
use std::path::{Path, PathBuf};
use std::process::Output;

use sha2::{Digest, Sha256};

fn konsensus(args: &[&str], dir: &Path) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(args)
        .env("HOME", dir)
        .output()
        .unwrap()
}

/// An existing Full node on signet whose `[chain]` and embedded LDK read
/// public explorers it never explicitly accepted. `chain` replaces `[chain]`.
fn existing_full_node(dir: &Path, chain: &str) -> PathBuf {
    let output = konsensus(
        &[
            "init",
            "--non-interactive",
            "--tier",
            "full",
            "--dir",
            dir.to_str().unwrap(),
        ],
        dir,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = dir.join("konsensus.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut table: toml::Table = toml::from_str(&text).unwrap();
    let lightning = table["lightning"].as_table_mut().unwrap();
    lightning.insert("network".into(), "signet".into());
    lightning.insert(
        "esplora_url".into(),
        "https://mempool.space/signet/api".into(),
    );
    lightning.insert(
        "esplora_url_fallback".into(),
        "https://blockstream.info/signet/api".into(),
    );
    table.insert(
        "chain".into(),
        toml::Value::Table(toml::from_str(chain).unwrap()),
    );
    let mut text = toml::to_string(&table).unwrap();
    text.insert_str(0, "# owner note: must survive untouched\n");
    std::fs::write(&path, text).unwrap();
    path
}

const EXPLORER_CHAIN: &str = "backend = \"esplora\"\n\
     api_url = \"https://mempool.space/signet\"\n\
     esplora_url_fallback = \"https://blockstream.info/signet\"";

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Content hash, length and modification time of the config, and the names
/// of every file in its directory.
fn snapshot(path: &Path) -> (Vec<u8>, u64, std::time::SystemTime, Vec<String>) {
    let bytes = std::fs::read(path).unwrap();
    let meta = std::fs::metadata(path).unwrap();
    let mut names: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    (
        Sha256::digest(&bytes).to_vec(),
        meta.len(),
        meta.modified().unwrap(),
        names,
    )
}

#[test]
fn show_reports_the_explorer_default_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path(), EXPLORER_CHAIN);
    let before = snapshot(&path);
    let output = konsensus(
        &["chain-tip", "--config", path.to_str().unwrap()],
        dir.path(),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    for needle in [
        "third_party, explorer_default",
        "[chain] mempool.space",
        "[chain] blockstream.info",
        "[lightning] mempool.space",
        "[lightning] blockstream.info",
        "accept_third_party_tip = true",
        "backend = \"bitcoind\"",
        "docs/CHAIN-SOURCE.md",
    ] {
        assert!(out.contains(needle), "{needle}: {out}");
    }
    // Hosts only: no configured URL or network path is printed.
    assert!(!out.contains("://"), "{out}");
    assert!(!out.contains("/signet"), "{out}");
    assert_eq!(snapshot(&path), before, "chain-tip must not change any file");
}

#[test]
fn show_reports_an_accepted_explorer_without_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    let chain = format!("{EXPLORER_CHAIN}\naccept_third_party_tip = true");
    let path = existing_full_node(dir.path(), &chain);
    let before = snapshot(&path);
    let output = konsensus(
        &["chain-tip", "--config", path.to_str().unwrap()],
        dir.path(),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("third_party: public Esplora at mempool.space, accepted"),
        "{out}"
    );
    assert!(!out.contains("explorer_default"), "{out}");
    assert_eq!(snapshot(&path), before);
}

/// The command has no option that writes: the earlier writer flags are
/// rejected by argument parsing, before the config is read.
#[test]
fn writer_flags_do_not_exist_and_change_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path(), EXPLORER_CHAIN);
    let before = snapshot(&path);
    for extra in [
        &["--accept-third-party-tip"][..],
        &["--chain", "bitcoind"][..],
        &["--chain", "electrum", "--electrum-server-url", "tcp://127.0.0.1:50001"][..],
    ] {
        let mut args = vec!["chain-tip", "--config", path.to_str().unwrap()];
        args.extend_from_slice(extra);
        let output = konsensus(&args, dir.path());
        assert!(!output.status.success(), "{extra:?}: {}", stdout(&output));
        assert!(
            stderr(&output).contains("unexpected argument"),
            "{extra:?}: {}",
            stderr(&output)
        );
        assert_eq!(snapshot(&path), before, "{extra:?}");
    }
}

/// `[chain] backend = "mock"` with embedded LDK on an explorer: flagged, and
/// acceptance is not offered because there is no `[chain]` Esplora table.
#[test]
fn an_ldk_only_explorer_is_offered_only_the_move() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path(), "backend = \"mock\"");
    let before = snapshot(&path);
    let output = konsensus(
        &["chain-tip", "--config", path.to_str().unwrap()],
        dir.path(),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("[lightning] mempool.space"), "{out}");
    assert!(!out.contains("[chain] mempool.space"), "{out}");
    assert!(out.contains("backend = \"bitcoind\""), "{out}");
    assert!(!out.contains("accept_third_party_tip"), "{out}");
    assert_eq!(snapshot(&path), before);
}
