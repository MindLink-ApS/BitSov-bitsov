//! `konsensus chain-tip` on an existing node that reads a public explorer:
//! it shows the source, moves to an owned tip only when asked and only after
//! checking it, keeps a backup, and changes nothing when it refuses.
//!
//! Chain sources here are loopback fixtures; no real node is contacted.
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use bitcoin::Network;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn konsensus(args: &[&str], dir: &Path) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(args)
        .env("HOME", dir)
        .output()
        .unwrap()
}

/// An existing Full node, as generated before owned-tip onboarding: public
/// Esplora for `[chain]` and embedded LDK, never explicitly accepted. The
/// network is switched to signet the way the signet quickstart does it.
fn existing_full_node(dir: &Path) -> PathBuf {
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
    let chain = table["chain"].as_table_mut().unwrap();
    assert_eq!(chain["backend"].as_str(), Some("esplora"));
    chain.insert("api_url".into(), "https://mempool.space/signet".into());
    chain.insert(
        "esplora_url_fallback".into(),
        "https://blockstream.info/signet".into(),
    );
    // Test ports only: the running-node probe connects to these.
    for (stanza, port) in [("api", free_port()), ("network", free_port())] {
        table
            .entry(stanza)
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .unwrap()
            .insert("listen_addr".into(), format!("127.0.0.1:{port}").into());
    }
    let mut text = toml::to_string(&table).unwrap();
    text.insert_str(0, "# owner note: kept across the switch\n");
    std::fs::write(&path, text).unwrap();
    path
}

/// A loopback port nothing listens on (bound, then released).
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn listen_port(path: &Path, stanza: &str) -> u16 {
    let table: toml::Table = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let addr: std::net::SocketAddr = table[stanza]["listen_addr"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    addr.port()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn backups(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("konsensus.toml.before-chain-tip-")
        })
        .collect();
    found.sort();
    found
}

fn genesis_hash(network: Network) -> String {
    bitcoin::blockdata::constants::genesis_block(network)
        .block_hash()
        .to_string()
}

/// Loopback Bitcoin Core JSON-RPC on `network`; `ibd` keeps it syncing.
async fn core_fixture(network: Network, ibd: bool) -> (u16, tokio::task::JoinHandle<()>) {
    core_fixture_editing(network, ibd, None).await
}

/// As [`core_fixture`]; when `edit` is set, appends to that file on the first
/// RPC, like an owner editing the config while the source is checked.
async fn core_fixture_editing(
    network: Network,
    ibd: bool,
    edit: Option<PathBuf>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let genesis = genesis_hash(network);
    let edit = Arc::new(std::sync::Mutex::new(edit));
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let genesis = genesis.clone();
            let edit = Arc::clone(&edit);
            async move {
                if let Some(path) = edit.lock().unwrap().take() {
                    let mut text = std::fs::read_to_string(&path).unwrap();
                    text.push_str("# edited meanwhile\n");
                    std::fs::write(&path, text).unwrap();
                }
                let result = match request["method"].as_str().unwrap() {
                    "getblockhash" => json!(genesis),
                    "getblockheader" => {
                        json!({"height":0,"hash":genesis,"time":1598918400,"bits":"1e0377ae"})
                    }
                    "getblockcount" => json!(200_000),
                    "getblockchaininfo" => {
                        json!({"blocks":200_000,"headers":if ibd {300_000} else {200_000},"initialblockdownload":ibd})
                    }
                    other => panic!("unexpected RPC {other}"),
                };
                axum::Json(json!({"result":result,"error":null,"id":1}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, task)
}

/// Loopback Electrum server on `network`.
async fn electrum_fixture(network: Network) -> (String, tokio::task::JoinHandle<()>) {
    let header = bitcoin::consensus::encode::serialize_hex(
        &bitcoin::blockdata::constants::genesis_block(network).header,
    );
    let header = Arc::new(header);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("tcp://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let header = Arc::clone(&header);
            tokio::spawn(async move {
                let (read, mut write) = socket.into_split();
                let mut lines = BufReader::new(read).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let request: Value = serde_json::from_str(&line).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "blockchain.block.header" => json!(*header),
                        "blockchain.headers.subscribe" => json!({"height":200_000,"hex":*header}),
                        other => panic!("unexpected Electrum method {other}"),
                    };
                    let response = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
                    if write
                        .write_all(format!("{response}\n").as_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    (url, task)
}

fn cookie(dir: &Path) -> PathBuf {
    let path = dir.join("core.cookie");
    std::fs::write(&path, "__cookie__:fixture\n").unwrap();
    path
}

async fn run_in_blocking<F: FnOnce() -> Output + Send + 'static>(f: F) -> Output {
    tokio::task::spawn_blocking(f).await.unwrap()
}

#[test]
fn show_reports_the_explorer_default_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let before = std::fs::read(&path).unwrap();
    let output = konsensus(
        &["chain-tip", "--config", path.to_str().unwrap()],
        dir.path(),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    for needle in [
        "third_party, explorer_default",
        "[chain] mempool.space",
        "[lightning] blockstream.info",
        "--accept-third-party-tip",
        "--chain bitcoind",
    ] {
        assert!(out.contains(needle), "{needle}: {out}");
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(backups(dir.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn switch_to_owned_core_writes_the_owned_tip_and_keeps_a_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let before = std::fs::read(&path).unwrap();
    let (port, _core) = core_fixture(Network::Signet, false).await;
    let cookie = cookie(dir.path());
    let (p, d) = (path.clone(), dir.path().to_path_buf());
    let output = run_in_blocking(move || {
        konsensus(
            &[
                "chain-tip",
                "--config",
                p.to_str().unwrap(),
                "--chain",
                "bitcoind",
                "--rpc-port",
                &port.to_string(),
                "--cookie-file",
                cookie.to_str().unwrap(),
            ],
            &d,
        )
    })
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("owned tip: Bitcoin Core RPC at 127.0.0.1"),
        "{out}"
    );
    assert!(out.contains("signet at height 200000"), "{out}");

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.starts_with("# owner note: kept across the switch\n"),
        "{text}"
    );
    assert!(!text.contains("mempool.space"), "{text}");
    assert!(!text.contains("blockstream.info"), "{text}");
    let table: toml::Table = toml::from_str(&text).unwrap();
    let chain = table["chain"].as_table().unwrap();
    assert_eq!(chain["backend"].as_str(), Some("bitcoind"));
    assert_eq!(chain["rpc_host"].as_str(), Some("127.0.0.1"));
    assert_eq!(chain["rpc_port"].as_integer(), Some(i64::from(port)));
    assert_eq!(
        chain["cookie_file"].as_str(),
        Some(dir.path().join("core.cookie").to_str().unwrap())
    );
    assert_eq!(table["lightning"]["esplora_url"].as_str(), Some(""));
    assert!(table["lightning"].get("esplora_url_fallback").is_none());
    assert_eq!(table["lightning"]["network"].as_str(), Some("signet"));

    // Everything else is as it was.
    let mut old: toml::Table = toml::from_str(std::str::from_utf8(&before).unwrap()).unwrap();
    let mut new = table.clone();
    for t in [&mut old, &mut new] {
        t.remove("chain");
        let lightning = t["lightning"].as_table_mut().unwrap();
        lightning.remove("esplora_url");
        lightning.remove("esplora_url_fallback");
    }
    assert_eq!(old, new);

    // The backup is the old file, private to the owner; no temporary is left.
    let found = backups(dir.path());
    assert_eq!(found.len(), 1);
    let named: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("before-chain-tip"))
        .collect();
    assert_eq!(named.len(), 1, "{named:?}");
    assert_eq!(std::fs::read(&found[0]).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&found[0]).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The node now reads an owned tip and is no longer flagged.
    let show = konsensus(
        &["chain-tip", "--config", path.to_str().unwrap()],
        dir.path(),
    );
    assert!(show.status.success(), "{}", stderr(&show));
    assert!(stdout(&show).contains("owned tip"), "{}", stdout(&show));
    assert!(
        !stdout(&show).contains("explorer_default"),
        "{}",
        stdout(&show)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn switch_to_own_electrum_writes_the_declared_server() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let (url, _server) = electrum_fixture(Network::Signet).await;
    let (p, d, u) = (path.clone(), dir.path().to_path_buf(), url.clone());
    let output = run_in_blocking(move || {
        konsensus(
            &[
                "chain-tip",
                "--config",
                p.to_str().unwrap(),
                "--chain",
                "electrum",
                "--electrum-server-url",
                &u,
                "--electrum-operator",
                "own",
            ],
            &d,
        )
    })
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("backed by a Bitcoin Core you control"),
        "{}",
        stdout(&output)
    );
    let table: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(table["chain"]["backend"].as_str(), Some("electrum"));
    assert_eq!(table["chain"]["server_url"].as_str(), Some(url.as_str()));
    assert_eq!(table["chain"]["operator"].as_str(), Some("own"));
    assert_eq!(backups(dir.path()).len(), 1);
}

/// Each refusal leaves the config byte for byte as it was, with no backup.
async fn assert_refused(dir: &Path, path: &Path, extra: Vec<String>, needle: &str) {
    let before = std::fs::read(path).unwrap();
    let (p, d) = (path.to_path_buf(), dir.to_path_buf());
    let output = run_in_blocking(move || {
        let mut args = vec![
            "chain-tip".to_string(),
            "--config".into(),
            p.to_str().unwrap().into(),
        ];
        args.extend(extra);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        konsensus(&args, &d)
    })
    .await;
    assert!(!output.status.success(), "must refuse: {}", stdout(&output));
    let err = stderr(&output);
    assert!(err.contains(needle), "{needle}: {err}");
    assert!(err.contains("nothing was changed"), "{err}");
    assert_eq!(
        std::fs::read(path).unwrap(),
        before,
        "config changed on refusal"
    );
    assert!(backups(dir).is_empty(), "no backup on refusal");
}

fn core_args(port: u16, cookie: &Path) -> Vec<String> {
    vec![
        "--chain".into(),
        "bitcoind".into(),
        "--rpc-port".into(),
        port.to_string(),
        "--cookie-file".into(),
        cookie.to_str().unwrap().into(),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_on_another_network_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let cookie = cookie(dir.path());
    let (port, _core) = core_fixture(Network::Bitcoin, false).await;
    assert_refused(
        dir.path(),
        &path,
        core_args(port, &cookie),
        "the source is on bitcoin (mainnet) but [lightning] network is signet",
    )
    .await;
    let (url, _server) = electrum_fixture(Network::Testnet).await;
    assert_refused(
        dir.path(),
        &path,
        vec![
            "--chain".into(),
            "electrum".into(),
            "--electrum-server-url".into(),
            url,
            "--electrum-operator".into(),
            "own".into(),
        ],
        "the source is on testnet but [lightning] network is signet",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_or_syncing_source_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let cookie = cookie(dir.path());
    // A port nothing listens on.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    assert_refused(
        dir.path(),
        &path,
        core_args(closed, &cookie),
        "could not read",
    )
    .await;
    let (port, _core) = core_fixture(Network::Signet, true).await;
    assert_refused(
        dir.path(),
        &path,
        core_args(port, &cookie),
        "still synchronizing",
    )
    .await;
    // Unreadable credentials are caught before any request.
    let missing = dir.path().join("missing.cookie");
    assert_refused(
        dir.path(),
        &path,
        core_args(port, &missing),
        "Bitcoin Core settings",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_running_node_or_an_owned_tip_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    // The node's owner control socket answers: it is running.
    #[cfg(unix)]
    {
        let socket = dir.path().join("control.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert_refused(
            dir.path(),
            &path,
            vec!["--accept-third-party-tip".into()],
            "the node is running",
        )
        .await;
        drop(_listener);
        std::fs::remove_file(&socket).unwrap();
    }
    // A node already on Core has nothing to switch or accept.
    let mut table: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    table.insert(
        "chain".into(),
        toml::Value::Table(
            toml::from_str(&format!(
                "backend = \"bitcoind\"\nrpc_host = \"127.0.0.1\"\nrpc_port = 38332\ncookie_file = {:?}",
                cookie(dir.path())
            ))
            .unwrap(),
        ),
    );
    std::fs::write(&path, toml::to_string(&table).unwrap()).unwrap();
    assert_refused(
        dir.path(),
        &path,
        vec!["--accept-third-party-tip".into()],
        "not esplora",
    )
    .await;
    assert_refused(
        dir.path(),
        &path,
        core_args(1, &cookie(dir.path())),
        "backend is bitcoind",
    )
    .await;
}

#[test]
fn accept_records_the_choice_and_clears_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let before = std::fs::read(&path).unwrap();
    let output = konsensus(
        &[
            "chain-tip",
            "--config",
            path.to_str().unwrap(),
            "--accept-third-party-tip",
        ],
        dir.path(),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = std::fs::read_to_string(&path).unwrap();
    let table: toml::Table = toml::from_str(&text).unwrap();
    assert_eq!(
        table["chain"]["accept_third_party_tip"].as_bool(),
        Some(true)
    );
    // The explorer itself is kept.
    assert_eq!(
        table["chain"]["api_url"].as_str(),
        Some("https://mempool.space/signet")
    );
    assert_eq!(
        table["lightning"]["esplora_url"].as_str(),
        Some("https://mempool.space/signet/api")
    );
    let found = backups(dir.path());
    assert_eq!(found.len(), 1);
    assert_eq!(std::fs::read(&found[0]).unwrap(), before);

    let show = konsensus(
        &["chain-tip", "--config", path.to_str().unwrap()],
        dir.path(),
    );
    let out = stdout(&show);
    assert!(
        out.contains("accepted (accept_third_party_tip = true)"),
        "{out}"
    );
    assert!(!out.contains("explorer_default"), "{out}");

    // Accepting again changes nothing.
    let again = konsensus(
        &[
            "chain-tip",
            "--config",
            path.to_str().unwrap(),
            "--accept-third-party-tip",
        ],
        dir.path(),
    );
    assert!(again.status.success());
    assert!(
        stdout(&again).contains("already records"),
        "{}",
        stdout(&again)
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    assert_eq!(backups(dir.path()).len(), 1);
}

/// A paid Esplora's credentials belong to the Esplora being left. Left in
/// `[lightning]`, embedded LDK would build its authenticated transport from
/// the now empty `esplora_url` and refuse to start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn switch_removes_paid_esplora_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let credentials = dir.path().join("chain-api.toml");
    std::fs::write(
        &credentials,
        "token_url = \"https://login.example/token\"\nclient_id = \"fixture\"\nclient_secret = \"fixture-only\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut table: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for stanza in ["lightning", "chain"] {
        table[stanza].as_table_mut().unwrap().insert(
            "credentials_file".into(),
            credentials.to_str().unwrap().into(),
        );
    }
    table["lightning"].as_table_mut().unwrap().insert(
        "esplora_url".into(),
        "https://enterprise.example/api".into(),
    );
    table["chain"]
        .as_table_mut()
        .unwrap()
        .insert("api_url".into(), "https://enterprise.example/api".into());
    std::fs::write(&path, toml::to_string(&table).unwrap()).unwrap();
    let (port, _core) = core_fixture(Network::Signet, false).await;
    let cookie = cookie(dir.path());
    let (p, d) = (path.clone(), dir.path().to_path_buf());
    let output = run_in_blocking(move || {
        let mut args = vec![
            "chain-tip".to_string(),
            "--config".into(),
            p.to_str().unwrap().into(),
        ];
        args.extend(core_args(port, &cookie));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        konsensus(&args, &d)
    })
    .await;
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("`credentials_file` setting was removed"),
        "{}",
        stdout(&output)
    );
    let table: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(
        table["lightning"].get("credentials_file").is_none(),
        "{table:?}"
    );
    assert!(
        table["chain"].get("credentials_file").is_none(),
        "{table:?}"
    );
    assert_eq!(table["lightning"]["esplora_url"].as_str(), Some(""));
    // The credentials file itself is left alone.
    assert!(credentials.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_holding_its_lock_or_ports_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let cookie = cookie(dir.path());
    let (port, _core) = core_fixture(Network::Signet, false).await;
    // A running node holds its state lock for its whole life.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.path().join("STATE_GENERATION.lock"))
        .unwrap();
    lock.lock().unwrap();
    assert_refused(
        dir.path(),
        &path,
        core_args(port, &cookie),
        "state lock is held",
    )
    .await;
    assert_refused(
        dir.path(),
        &path,
        vec!["--accept-third-party-tip".into()],
        "state lock is held",
    )
    .await;
    lock.unlock().unwrap();
    drop(lock);
    // Or answers on its own configured API or peer address (test ports).
    for stanza in ["api", "network"] {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", listen_port(&path, stanza))).unwrap();
        assert_refused(
            dir.path(),
            &path,
            core_args(port, &cookie),
            "something answers on the node's",
        )
        .await;
        drop(listener);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_source_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let cookie = cookie(dir.path());
    // Accepts connections and never answers.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _silent = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            held.push(socket);
        }
    });
    let started = std::time::Instant::now();
    assert_refused(
        dir.path(),
        &path,
        core_args(port, &cookie),
        "did not answer within 20 seconds",
    )
    .await;
    assert!(started.elapsed() >= std::time::Duration::from_secs(19));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_config_edited_during_the_check_is_not_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = existing_full_node(dir.path());
    let cookie = cookie(dir.path());
    let (port, _core) = core_fixture_editing(Network::Signet, false, Some(path.clone())).await;
    let (p, d) = (path.clone(), dir.path().to_path_buf());
    let output = run_in_blocking(move || {
        let mut args = vec![
            "chain-tip".to_string(),
            "--config".into(),
            p.to_str().unwrap().into(),
        ];
        args.extend(core_args(port, &cookie));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        konsensus(&args, &d)
    })
    .await;
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("changed while the source was checked"),
        "{}",
        stderr(&output)
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.ends_with("# edited meanwhile\n"),
        "the owner's edit must survive"
    );
    assert!(text.contains("mempool.space"), "the old source must stay");
    assert!(backups(dir.path()).is_empty());
}

/// A backup that cannot be written leaves no file under a backup name and no change.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_backup_leaves_nothing_behind() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let node = dir.path().join("node");
    std::fs::create_dir(&node).unwrap();
    let path = existing_full_node(&node);
    let cookie = cookie(dir.path());
    let (port, _core) = core_fixture(Network::Signet, false).await;
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o500)).unwrap();
    let before = std::fs::read(&path).unwrap();
    let (p, d) = (path.clone(), node.clone());
    let output = run_in_blocking(move || {
        let mut args = vec![
            "chain-tip".to_string(),
            "--config".into(),
            p.to_str().unwrap().into(),
        ];
        args.extend(core_args(port, &cookie));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        konsensus(&args, &d)
    })
    .await;
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("could not write the backup"),
        "{}",
        stderr(&output)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let leftovers: Vec<_> = std::fs::read_dir(&node)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("before-chain-tip"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}
