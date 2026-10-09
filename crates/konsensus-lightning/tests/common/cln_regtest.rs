//! Real, loopback-only daemons. Admin RPC is a private Unix socket used only
//! for fixture provisioning/inspection; all tested payments use restricted TLS.
use konsensus_core::traits::lightning::{
    LightningProvider, PaymentDetails, PaymentStatus, RoutingFeePolicy,
};
use konsensus_lightning::{ClnConfig, ClnProvider, LdkConfig, LdkProvider};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Binaries {
    pub bitcoind: PathBuf,
    lightningd: PathBuf,
    bitcoin_cli: PathBuf,
}
impl Binaries {
    pub fn from_env() -> Option<Self> {
        let mut paths = Vec::new();
        for name in ["BITCOIND_EXE", "LIGHTNINGD_EXE"] {
            let Some(path) = std::env::var_os(name).filter(|p| !p.is_empty()) else {
                eprintln!(
                    "CLN REGTEST SKIP: set BITCOIND_EXE and LIGHTNINGD_EXE to local executables"
                );
                return None;
            };
            paths.push(PathBuf::from(path));
        }
        // Check presence of BOTH variables before touching either executable.
        // Once both are configured, a broken installation must fail, not skip.
        for (path, name) in paths.iter_mut().zip(["BITCOIND_EXE", "LIGHTNINGD_EXE"]) {
            *path = std::fs::canonicalize(&*path).unwrap_or_else(|e| panic!("invalid {name}: {e}"));
        }
        let bitcoin_cli = paths[0].with_file_name("bitcoin-cli");
        assert!(
            bitcoin_cli.is_file(),
            "CLN's bcli plugin requires bitcoin-cli beside BITCOIND_EXE"
        );
        Some(Self {
            bitcoind: paths.remove(0),
            lightningd: paths.remove(0),
            bitcoin_cli,
        })
    }
}

fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
struct Daemon {
    child: Child,
    log: PathBuf,
}
impl Daemon {
    fn spawn(command: &mut Command, log: PathBuf) -> Self {
        use std::os::unix::process::CommandExt;
        let output = std::fs::File::create(&log).unwrap();
        let child = command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap();
        Self { child, log }
    }
    fn alive(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "daemon exited; see {}",
            self.log.display()
        );
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        // lightningd owns plugins and subdaemons: terminate its whole isolated
        // process group, including on panic. `kill` is available on Unix hosts.
        let group = format!("-{}", self.child.id());
        let _ = Command::new("/bin/kill")
            .args(["-TERM", "--", &group])
            .status();
        for _ in 0..30 {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &group])
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
        if std::thread::panicking() {
            // Do not dump daemon logs: createrune replies may contain credentials.
            eprintln!("daemon failure; temporary log: {}", self.log.display());
        }
    }
}

pub async fn wait<F, Fut>(label: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(90), async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout: {label}"));
}
pub async fn settle(provider: &dyn LightningProvider, hash: &str) -> PaymentDetails {
    wait("incoming/outgoing settlement", || async {
        match provider.get_payment_status(hash).await {
            Ok(p) => {
                assert_ne!(p.status, PaymentStatus::Failed);
                p.status == PaymentStatus::Settled
            }
            Err(_) => false,
        }
    })
    .await;
    provider.get_payment_status(hash).await.unwrap()
}

pub struct Core {
    daemon: Daemon,
    pub port: u16,
    client: reqwest::Client,
    dir: tempfile::TempDir,
}
impl Core {
    pub async fn start(executable: &Path) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = port();
        let daemon = Daemon::spawn(
            Command::new(executable)
                .args([
                    "-regtest",
                    "-server",
                    "-listen=0",
                    "-networkactive=0",
                    "-dnsseed=0",
                    "-discover=0",
                    "-txindex=1",
                    "-fallbackfee=0.0001",
                    "-rpcbind=127.0.0.1",
                    "-rpcallowip=127.0.0.1",
                    "-rpcuser=cln-regtest",
                    "-rpcpassword=disposable-regtest",
                ])
                .arg(format!("-datadir={}", dir.path().display()))
                .arg(format!("-rpcport={port}")),
            dir.path().join("bitcoind.log"),
        );
        let mut core = Self {
            daemon,
            port,
            dir,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        };
        wait("Bitcoin Core RPC", || async {
            core.try_rpc("getblockchaininfo", json!([])).await.is_some()
        })
        .await;
        core.daemon.alive();
        core.rpc("createwallet", json!(["cln-regtest"])).await;
        core
    }
    async fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
        let result: Value = self
            .client
            .post(format!("http://127.0.0.1:{}", self.port))
            .basic_auth("cln-regtest", Some("disposable-regtest"))
            .json(&json!({"jsonrpc":"1.0", "id":1, "method":method, "params":params}))
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        result["error"].is_null().then(|| result["result"].clone())
    }
    pub async fn rpc(&self, method: &str, params: Value) -> Value {
        self.try_rpc(method, params)
            .await
            .unwrap_or_else(|| panic!("Core RPC {method} failed"))
    }
    pub async fn mine(&self, count: u32) {
        let address = self.rpc("getnewaddress", json!([])).await;
        self.rpc("generatetoaddress", json!([count, address])).await;
    }
}

pub struct Cln {
    daemon: Daemon,
    dir: tempfile::TempDir,
    socket: PathBuf,
    rest_port: u16,
    rune: String,
    pub version: String,
    pub keysend_method: &'static str,
}
impl Cln {
    pub async fn start(binaries: &Binaries, core: &Core) -> Self {
        // /tmp avoids macOS's 104-byte Unix socket path limit.
        let dir = tempfile::Builder::new()
            .prefix("cln-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("regtest/lightning-rpc");
        let certs = dir.path().join("certs");
        std::fs::create_dir(&certs).unwrap();
        let rest_port = port();
        let daemon = Daemon::spawn(
            Command::new(&binaries.lightningd)
                .args([
                    "--network=regtest",
                    "--disable-dns",
                    "--autolisten=false",
                    "--announce-addr-discovered=false",
                    "--bitcoin-rpcconnect=127.0.0.1",
                    "--bitcoin-rpcuser=cln-regtest",
                    "--bitcoin-rpcpassword=disposable-regtest",
                    "--bitcoin-poll=1",
                    "--clnrest-host=127.0.0.1",
                    "--clnrest-protocol=https",
                ])
                .arg(format!("--lightning-dir={}", dir.path().display()))
                .arg(format!("--bitcoin-datadir={}", core.dir.path().display()))
                .arg(format!("--bitcoin-cli={}", binaries.bitcoin_cli.display()))
                .arg(format!("--bitcoin-rpcport={}", core.port))
                .arg(format!("--addr=127.0.0.1:{}", port()))
                .arg(format!("--clnrest-port={rest_port}"))
                .arg(format!("--clnrest-certs={}", certs.display())),
            dir.path().join("lightningd.log"),
        );
        let mut cln = Self {
            daemon,
            dir,
            socket,
            rest_port,
            rune: String::new(),
            version: String::new(),
            keysend_method: "keysend",
        };
        wait("lightningd admin RPC and clnrest certificate", || async {
            cln.socket.exists()
                && certs.join("ca.pem").exists()
                && cln.try_rpc("getinfo", json!({})).await.is_some()
        })
        .await;
        cln.daemon.alive();
        cln.version = cln.rpc("getinfo", json!({})).await["version"]
            .as_str()
            .unwrap()
            .to_owned();
        let help = cln.rpc("help", json!({})).await;
        let commands: Vec<_> = help["help"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["command"].as_str())
            .filter_map(|s| s.split_whitespace().next())
            .collect();
        assert!(commands.contains(&"xpay"), "real CLN must support xpay");
        if cln.version.starts_with("v26.06") {
            assert!(
                commands.contains(&"xkeysend"),
                "26.06 must exercise xkeysend"
            );
            cln.keysend_method = "xkeysend";
        } else {
            assert!(
                cln.version.starts_with("v24.11"),
                "unsupported fixture version"
            );
            assert!(commands.contains(&"keysend"));
        }
        // Only the selected keysend method is authorized. On 26.06 an accidental
        // fallback to legacy keysend therefore fails T7 instead of passing unnoticed.
        let restrictions = json!([
            [
                "method=getinfo",
                "method=help",
                "method=invoice",
                "method=listinvoices",
                "method=listpays",
                "method=listpeerchannels",
                "method=listfunds",
                "method=xpay",
                format!("method={}", cln.keysend_method)
            ],
            ["method/xpay", "pnamemaxfee<10001"],
            ["method/xkeysend", "pnamemaxfee<10001"],
            ["method/keysend", "pnamemaxfee<10001"]
        ]);
        cln.rune = cln
            .rpc("createrune", json!({"restrictions":restrictions}))
            .await["rune"]
            .as_str()
            .unwrap()
            .to_owned();
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(cln.dir.path().join("bitsov.rune"))
            .unwrap();
        file.write_all(cln.rune.as_bytes()).unwrap();
        wait("restricted clnrest TLS", || async {
            ClnProvider::new(cln.config()).await.is_ok()
        })
        .await;
        cln
    }
    async fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut socket = tokio::net::UnixStream::connect(&self.socket).await.ok()?;
            socket
                .write_all(
                    format!(
                        "{}\n\n",
                        json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params})
                    )
                    .as_bytes(),
                )
                .await
                .ok()?;
            let mut data = Vec::new();
            loop {
                let mut buf = [0; 8192];
                let n = socket.read(&mut buf).await.ok()?;
                if n == 0 {
                    return None;
                }
                data.extend_from_slice(&buf[..n]);
                if let Ok(reply) = serde_json::from_slice::<Value>(&data) {
                    if reply.get("id") != Some(&json!(1)) {
                        data.clear();
                        continue;
                    }
                    if reply.get("error").is_some() {
                        // Never echo params or the response (createrune is secret).
                        panic!(
                            "CLN admin RPC {method} failed, code {}",
                            reply["error"]["code"]
                        );
                    }
                    return Some(reply["result"].clone());
                }
                assert!(data.len() < 4 * 1024 * 1024, "oversized admin RPC reply");
            }
        })
        .await
        .ok()
        .flatten()
    }
    pub async fn rpc(&self, method: &str, params: Value) -> Value {
        self.try_rpc(method, params)
            .await
            .unwrap_or_else(|| panic!("CLN admin RPC {method} timed out"))
    }
    fn config(&self) -> ClnConfig {
        ClnConfig {
            rest_url: format!("https://localhost:{}", self.rest_port),
            resolve_ip: Some("127.0.0.1".parse().unwrap()),
            ca_cert_path: self.dir.path().join("certs/ca.pem"),
            rune_file: self.dir.path().join("bitsov.rune"),
            network: "regtest".into(),
            minimum_version: "v24.11".into(),
        }
    }
    pub async fn provider(&self) -> ClnProvider {
        ClnProvider::new(self.config())
            .await
            .unwrap()
            .with_routing_fee_policy(RoutingFeePolicy {
                minimum_msat: 10_000,
                proportional_millionths: 0,
                maximum_msat: 10_000,
            })
    }
    pub async fn channels(&self) -> Vec<Value> {
        self.rpc("listpeerchannels", json!({})).await["channels"]
            .as_array()
            .unwrap()
            .clone()
    }
    pub async fn idle(&self) {
        wait("CLN HTLCs drained", || async {
            self.channels()
                .await
                .iter()
                .all(|c| c["htlcs"].as_array().is_some_and(|h| h.is_empty()))
        })
        .await;
    }
    pub async fn balances(&self) -> Value {
        let channels: Vec<_> = self
            .channels()
            .await
            .into_iter()
            .map(
                |c| json!({"id":c["channel_id"], "local":c["to_us_msat"], "total":c["total_msat"]}),
            )
            .collect();
        json!({"channels":channels, "outputs":self.rpc("listfunds", json!({})).await["outputs"]})
    }
    pub async fn wait_failed_payment(&self, hash: &str) {
        // ClnProvider's HTTP timeout is 10s but xpay retry_for is 60s.
        // Start this full retry window AFTER the provider returns, including
        // an ambiguous timeout. Never treat an empty history as fee refusal:
        // a rejection without a recorded attempt must fail for lack of evidence.
        tokio::time::sleep(Duration::from_secs(65)).await;
        let pays = self.rpc("listpays", json!({"payment_hash":hash})).await;
        assert!(
            recorded_failed_attempts(&pays["pays"]),
            "T8 requires a recorded failed payment after the retry window; got {pays}"
        );
    }
    pub async fn assert_rune_denied(&self, method: &str, params: Value) {
        let cert =
            reqwest::Certificate::from_pem(&std::fs::read(self.config().ca_cert_path).unwrap())
                .unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .resolve("localhost", ([127, 0, 0, 1], self.rest_port).into())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let response = client
            .post(format!("https://localhost:{}/v1/{method}", self.rest_port))
            .header("rune", &self.rune)
            .json(&params)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        // checkrune's authorization failure is 1502 (not a routing/parameter
        // error). clnrest versions may map it to 401 or 403.
        assert!(
            status == 401 || status == 403,
            "{method}: expected HTTP authorization refusal, got {status}"
        );
        let code = body
            .get("code")
            .or_else(|| body.get("error").and_then(|e| e.get("code")))
            .and_then(Value::as_i64);
        assert_eq!(
            code,
            Some(1502),
            "{method}: must fail rune restrictions, not RPC validation"
        );
    }
}

pub struct Ldk {
    pub provider: LdkProvider,
    pub port: u16,
    _dir: tempfile::TempDir,
}
impl Ldk {
    pub async fn start(core: &Core, forwarding: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = port();
        let password_file = dir.path().join("core.pass");
        std::fs::write(&password_file, "disposable-regtest").unwrap();
        let (mnemonic, _) = konsensus_core::NodeIdentity::generate().unwrap();
        let provider = LdkProvider::new(LdkConfig {
            tower: Default::default(),
            channel_capacity_limits: Default::default(),
            forward_to_private_channels: forwarding,
            our_to_self_delay_blocks: None,
            logging: Default::default(),
            bitcoind: Some(konsensus_chain::BitcoindConfig {
                rpc_host: "127.0.0.1".into(),
                rpc_port: core.port,
                cookie_file: None,
                rpc_user: Some("cln-regtest".into()),
                rpc_password_file: Some(password_file),
            }),
            electrum: None,
            liquidity: Default::default(),
            lsps2_service: Default::default(),
            channel_peers: None,
            storage_dir: dir.path().join("ldk"),
            scb_backup_dir: None,
            scb_rotation_count: 3,
            mnemonic,
            passphrase: None,
            network: "regtest".into(),
            esplora_url: "disabled".into(),
            esplora_url_fallback: None,
            esplora_sync_intervals: Default::default(),
            credentials_file: None,
            rgs_url: None,
            lsp_node_id: None,
            lsp_address: None,
            lsp_token: None,
            listening_address: Some(format!("127.0.0.1:{port}")),
        })
        .await
        .unwrap();
        wait("LDK money ready", || provider.money_ready()).await;
        Self {
            provider,
            port,
            _dir: dir,
        }
    }
    pub fn id(&self) -> String {
        self.provider.node().node_id().to_string()
    }
}
pub async fn sync(core: &Core, cln: &Cln, nodes: &[&Ldk]) {
    let height = core.rpc("getblockcount", json!([])).await.as_u64().unwrap();
    for node in nodes {
        tokio::task::block_in_place(|| node.provider.node().sync_wallets()).unwrap();
    }
    wait("all nodes follow Core", || async {
        cln.rpc("getinfo", json!({})).await["blockheight"] == height
            && nodes
                .iter()
                .all(|n| u64::from(n.provider.node().status().current_best_block.height) == height)
    })
    .await;
}
pub async fn confirm(
    core: &Core,
    cln: &Cln,
    nodes: &[&Ldk],
    hub_channels: usize,
    recipient_channels: usize,
) {
    wait("channel funding broadcast", || async {
        !core
            .rpc("getrawmempool", json!([]))
            .await
            .as_array()
            .unwrap()
            .is_empty()
    })
    .await;
    core.mine(6).await;
    sync(core, cln, nodes).await;
    wait("channels usable on both ends", || async {
        cln.channels()
            .await
            .iter()
            .all(|c| c["state"] == "CHANNELD_NORMAL")
            && nodes
                .iter()
                .zip([hub_channels, recipient_channels])
                .all(|(n, count)| {
                    let channels = n.provider.node().list_channels();
                    channels.len() == count && channels.iter().all(|c| c.is_usable)
                })
    })
    .await;
}
pub fn capacities(nodes: &[&Ldk]) -> Vec<Vec<(String, u64, u64)>> {
    nodes
        .iter()
        .map(|n| {
            let mut channels: Vec<_> = n
                .provider
                .node()
                .list_channels()
                .into_iter()
                .map(|c| {
                    (
                        c.channel_id.to_string(),
                        c.outbound_capacity_msat,
                        c.inbound_capacity_msat,
                    )
                })
                .collect();
            channels.sort();
            channels
        })
        .collect()
}

/// Evidence shared by the aggregate and individual send-attempt checks.
pub fn recorded_failed_attempts(attempts: &Value) -> bool {
    attempts.as_array().is_some_and(|attempts| {
        !attempts.is_empty() && attempts.iter().all(|p| p["status"] == "failed")
    })
}

#[test]
fn failed_attempt_evidence_requires_a_record_and_only_failures() {
    for (attempts, expected) in [
        (json!([]), false),
        (json!([{"status":"failed"}]), true),
        (json!([{"status":"failed"}, {"status":"failed"}]), true),
        (json!([{"status":"pending"}]), false),
        (json!([{"status":"complete"}]), false),
        (json!([{"status":"failed"}, {"status":"pending"}]), false),
        (json!([{"status":"failed"}, {"status":"complete"}]), false),
        (json!([{}]), false),
        (Value::Null, false),
    ] {
        assert_eq!(recorded_failed_attempts(&attempts), expected, "{attempts}");
    }
}
