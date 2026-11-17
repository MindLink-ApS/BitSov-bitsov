//! `init` and `restore` write one Bitcoin network into `[lightning]` and
//! `[chain]` (signet unless `--network` says otherwise), and `start` refuses
//! a mainnet config the owner never opted into. Nothing here contacts a chain
//! source: every test either only writes a config or is refused before any
//! network I/O, and the refused start uses loopback addresses only.
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The public BIP-39 test vector, never a real seed.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn konsensus(args: &[&str], home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn init(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "init",
        "--non-interactive",
        "--tier",
        "full",
        "--dir",
        dir.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    konsensus(&args, dir.parent().unwrap())
}

fn restore(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "restore",
        "--tier",
        "full",
        "--mnemonic",
        TEST_MNEMONIC,
        "--insecure-argv",
        "--dir",
        dir.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    konsensus(&args, dir.parent().unwrap())
}

fn ok(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn table(dir: &Path) -> toml::Table {
    toml::from_str(&std::fs::read_to_string(dir.join("konsensus.toml")).unwrap()).unwrap()
}

/// `[lightning] network`, both `[lightning]` Esplora URLs and both `[chain]` URLs.
fn network_fields(t: &toml::Table) -> [Option<String>; 5] {
    let get = |section: &str, key: &str| {
        t[section]
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };
    [
        get("lightning", "network"),
        get("lightning", "esplora_url"),
        get("lightning", "esplora_url_fallback"),
        get("chain", "api_url"),
        get("chain", "esplora_url_fallback"),
    ]
}

fn signet_fields() -> [Option<String>; 5] {
    [
        Some("signet".into()),
        Some("https://mempool.space/signet/api".into()),
        Some("https://blockstream.info/signet/api".into()),
        Some("https://mempool.space/signet".into()),
        Some("https://blockstream.info/signet".into()),
    ]
}

fn last_line(stdout: &str) -> &str {
    stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
}

#[test]
fn init_writes_signet_by_default() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("node");
    let stdout = ok(&init(&dir, &[]));
    assert_eq!(network_fields(&table(&dir)), signet_fields());
    assert_eq!(last_line(&stdout), "Network:    signet");
    assert!(!stdout.contains("Bitcoin mainnet"), "{stdout}");
}

#[test]
fn init_network_flag_writes_regtest_or_mainnet_consistently() {
    let temp = tempfile::tempdir().unwrap();

    let dir = temp.path().join("regtest");
    let stdout = ok(&init(&dir, &["--network", "regtest"]));
    let [network, ldk, ldk_fallback, chain, chain_fallback] = network_fields(&table(&dir));
    assert_eq!(network.as_deref(), Some("regtest"));
    // A local Esplora only: no third-party server is written for regtest.
    for url in [&ldk, &chain] {
        let url = url.as_deref().unwrap();
        assert!(url.starts_with("http://localhost:"), "{url}");
    }
    assert_eq!(ldk.as_deref(), Some("http://localhost:3002/api"));
    assert_eq!(chain.as_deref(), Some("http://localhost:3002"));
    assert_eq!(ldk_fallback, None);
    assert_eq!(chain_fallback, None);
    assert_eq!(last_line(&stdout), "Network:    regtest");

    let dir = temp.path().join("bitcoin");
    let stdout = ok(&init(&dir, &["--network", "bitcoin"]));
    assert_eq!(
        network_fields(&table(&dir)),
        [
            Some("bitcoin".into()),
            Some("https://blockstream.info/api".into()),
            Some("https://mempool.space/api".into()),
            Some("https://blockstream.info".into()),
            Some("https://mempool.space".into()),
        ]
    );
    // The mainnet note stays, and the network is still the last line.
    assert!(stdout.contains("Bitcoin mainnet"), "{stdout}");
    assert!(stdout.contains("mainnet_not_approved"), "{stdout}");
    assert_eq!(last_line(&stdout), "Network:    bitcoin (mainnet)");
    // The opt-in is never written by `init`.
    let t = table(&dir);
    assert!(
        t.get("node")
            .and_then(|node| node.get("allow_mainnet"))
            .is_none(),
        "{t:?}"
    );
}

#[test]
fn init_rejects_an_unknown_network_and_writes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("node");
    for network in ["testnet", "mainnet", "Signet", ""] {
        let output = init(&dir, &["--network", network]);
        assert!(!output.status.success(), "{network} was accepted");
        assert!(!dir.exists(), "{network}: init wrote files before refusing");
    }
}

#[test]
fn restore_writes_signet_by_default_and_takes_the_network_flag() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("default");
    let stdout = ok(&restore(&dir, &[]));
    assert_eq!(network_fields(&table(&dir)), signet_fields());
    assert_eq!(last_line(&stdout), "Network:    signet");

    let dir = temp.path().join("regtest");
    let stdout = ok(&restore(&dir, &["--network", "regtest"]));
    assert_eq!(
        network_fields(&table(&dir))[0].as_deref(),
        Some("regtest")
    );
    assert_eq!(last_line(&stdout), "Network:    regtest");
}

#[test]
fn init_on_a_mock_tier_names_the_mock_network() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("node");
    let output = konsensus(
        &[
            "init",
            "--non-interactive",
            "--tier",
            "light",
            "--dir",
            dir.to_str().unwrap(),
        ],
        temp.path(),
    );
    let stdout = ok(&output);
    assert!(
        last_line(&stdout).starts_with("Network:    regtest (mock"),
        "{stdout}"
    );
}

fn free_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Run `start` with a bound: a start that is not refused is killed and fails.
fn start_refused(config: &Path, home: &Path) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["start", "--config"])
        .arg(config)
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("start was not refused within 30 seconds");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success(), "start succeeded");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn start_refuses_mainnet_without_the_owner_opt_in() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("node");
    ok(&init(&dir, &[]));
    // A mainnet config whose every address is loopback: even an unrefused
    // start would reach no chain source and no running node.
    let mut t = table(&dir);
    let lightning = t["lightning"].as_table_mut().unwrap();
    lightning.insert("network".into(), "bitcoin".into());
    lightning.insert("esplora_url".into(), "http://127.0.0.1:9/api".into());
    lightning.remove("esplora_url_fallback");
    lightning.insert("listening_address".into(), free_addr().into());
    let chain = t["chain"].as_table_mut().unwrap();
    chain.insert("api_url".into(), "http://127.0.0.1:9".into());
    chain.remove("esplora_url_fallback");
    t["api"]
        .as_table_mut()
        .unwrap()
        .insert("listen_addr".into(), free_addr().into());
    t["network"]
        .as_table_mut()
        .unwrap()
        .insert("listen_addr".into(), free_addr().into());
    let config = dir.join("konsensus.toml");
    std::fs::write(&config, toml::to_string(&t).unwrap()).unwrap();

    let before = listing(&dir);
    let stderr = start_refused(&config, temp.path());
    assert!(stderr.contains("mainnet_not_approved"), "{stderr}");
    assert!(stderr.contains("allow_mainnet = true"), "{stderr}");
    assert_eq!(listing(&dir), before, "a refused start writes nothing");
}
