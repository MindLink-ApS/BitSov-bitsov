use super::*;
use clap::Parser;

#[derive(Parser)]
struct Wrapper {
    #[command(flatten)]
    args: ChainTipArgs,
}

fn parse(argv: &[&str]) -> Result<ChainTipArgs, clap::Error> {
    Wrapper::try_parse_from(std::iter::once("chain-tip").chain(argv.iter().copied()))
        .map(|w| w.args)
}

fn request(argv: &[&str]) -> Result<Request> {
    parse(argv).unwrap().request()
}

#[test]
fn flags_resolve_to_one_request() {
    assert!(matches!(request(&[]).unwrap(), Request::Show));
    assert!(matches!(
        request(&["--accept-third-party-tip"]).unwrap(),
        Request::Accept
    ));
    assert!(matches!(
        request(&["--chain", "bitcoind"]).unwrap(),
        Request::Switch(SourceArgs::Bitcoind {
            ref host,
            port: None,
            auth: None
        }) if host == "127.0.0.1"
    ));
    assert!(matches!(
        request(&[
            "--chain",
            "electrum",
            "--electrum-server-url",
            "tcp://127.0.0.1:50001",
            "--electrum-operator",
            "own"
        ])
        .unwrap(),
        Request::Switch(SourceArgs::Electrum { .. })
    ));
}

#[test]
fn inconsistent_flags_are_refused_before_anything_is_read() {
    // clap-level conflicts
    assert!(parse(&["--chain", "bitcoind", "--accept-third-party-tip"]).is_err());
    assert!(parse(&["--chain", "esplora"]).is_err());
    assert!(parse(&["--rpc-user", "u"]).is_err());
    assert!(parse(&[
        "--cookie-file",
        "/c",
        "--rpc-user",
        "u",
        "--rpc-password-file",
        "/p"
    ])
    .is_err());
    for (argv, needle) in [
        (vec!["--rpc-port", "8332"], "require --chain bitcoind"),
        (
            vec!["--chain", "electrum", "--rpc-port", "8332"],
            "require --chain bitcoind",
        ),
        (
            vec!["--electrum-server-url", "tcp://127.0.0.1:1"],
            "require --chain electrum",
        ),
        (
            vec!["--accept-third-party-tip", "--cookie-file", "/c"],
            "require --chain bitcoind",
        ),
        (vec!["--chain", "electrum"], "--electrum-server-url"),
        (
            vec![
                "--chain",
                "electrum",
                "--electrum-server-url",
                "tcp://127.0.0.1:1",
            ],
            "--electrum-operator own",
        ),
        (
            vec![
                "--chain",
                "electrum",
                "--electrum-server-url",
                "tcp://127.0.0.1:1",
                "--electrum-operator",
                "third_party",
            ],
            "server you run",
        ),
        (
            vec!["--chain", "bitcoind", "--cookie-file", "relative/.cookie"],
            "absolute path",
        ),
        (
            vec![
                "--chain",
                "bitcoind",
                "--rpc-user",
                "u",
                "--rpc-password-file",
                "pw",
            ],
            "absolute path",
        ),
    ] {
        let error = match request(&argv) {
            Ok(_) => panic!("{argv:?} must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(error.contains(needle), "{argv:?}: {error}");
        assert!(error.ends_with("nothing was changed"), "{error}");
    }
}

#[test]
fn bitcoind_defaults_follow_the_network_like_fresh_init() {
    let home = Some(PathBuf::from("/home/owner"));
    for (network, port, cookie) in [
        (Network::Bitcoin, 8332, "/home/owner/.bitcoin/.cookie"),
        (
            Network::Testnet,
            18332,
            "/home/owner/.bitcoin/testnet3/.cookie",
        ),
        (
            Network::Signet,
            38332,
            "/home/owner/.bitcoin/signet/.cookie",
        ),
        (
            Network::Regtest,
            18443,
            "/home/owner/.bitcoin/regtest/.cookie",
        ),
    ] {
        let source = SourceArgs::Bitcoind {
            host: "127.0.0.1".into(),
            port: None,
            auth: None,
        };
        let ChainConfig::Bitcoind(rpc) = owned_chain(source, network, home.clone()).unwrap() else {
            panic!("bitcoind expected");
        };
        assert_eq!(rpc.rpc_host, "127.0.0.1");
        assert_eq!(rpc.rpc_port, port);
        assert_eq!(rpc.cookie_file.as_deref(), Some(Path::new(cookie)));
    }
    let explicit = SourceArgs::Bitcoind {
        host: "10.0.0.20".into(),
        port: Some(8332),
        auth: Some(CoreAuth::UserPassword(
            "bitsov".into(),
            "/secrets/pw".into(),
        )),
    };
    let ChainConfig::Bitcoind(rpc) = owned_chain(explicit, Network::Signet, None).unwrap() else {
        panic!("bitcoind expected");
    };
    assert_eq!((rpc.rpc_host.as_str(), rpc.rpc_port), ("10.0.0.20", 8332));
    assert_eq!(rpc.rpc_user.as_deref(), Some("bitsov"));
    assert!(rpc.cookie_file.is_none());

    for home in [None, Some(PathBuf::from("relative"))] {
        let source = SourceArgs::Bitcoind {
            host: "127.0.0.1".into(),
            port: None,
            auth: None,
        };
        let error = owned_chain(source, Network::Signet, home)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--cookie-file"), "{error}");
    }
    let bad_host = SourceArgs::Bitcoind {
        host: "http://127.0.0.1".into(),
        port: None,
        auth: None,
    };
    assert!(owned_chain(bad_host, Network::Signet, Some("/h".into())).is_err());
}

#[test]
fn electrum_is_written_as_declared_own() {
    let source = SourceArgs::Electrum {
        server_url: "tcp://127.0.0.1:50001".into(),
    };
    let ChainConfig::Electrum(server) = owned_chain(source, Network::Signet, None).unwrap() else {
        panic!("electrum expected");
    };
    assert_eq!(server.operator, konsensus_chain::ElectrumOperator::Own);
    let public_tcp = SourceArgs::Electrum {
        server_url: "tcp://public.example:50001".into(),
    };
    assert!(owned_chain(public_tcp, Network::Signet, None).is_err());
}

#[test]
fn configured_network_needs_a_known_lightning_network() {
    let ldk = |network: &str| -> LightningConfig {
        toml::from_str(&format!("backend = \"ldk\"\nnetwork = \"{network}\"")).unwrap()
    };
    assert_eq!(configured_network(&ldk("signet")), Some(Network::Signet));
    assert_eq!(configured_network(&ldk("MAINNET")), Some(Network::Bitcoin));
    assert_eq!(configured_network(&ldk("testnet3")), Some(Network::Testnet));
    assert_eq!(configured_network(&ldk("liquid")), None);
    let mock: LightningConfig = toml::from_str("backend = \"mock\"").unwrap();
    assert_eq!(configured_network(&mock), None);
}

const CONFIG: &str = r#"# my node
tier = "full"

[identity]
mnemonic_file = "/n/mnemonic.txt"

[lightning]
backend = "ldk"
# keep signet
network = "signet"
esplora_url = "https://mempool.space/signet/api"
esplora_url_fallback = "https://blockstream.info/signet/api"

[lightning.liquidity]
enabled = false

# chain source below
[chain]
backend = "esplora"
api_url = "https://mempool.space/signet"
# old comment inside chain

[[peers]]
node_id = "ab"
"#;

#[test]
fn chain_edits_touch_only_the_chain_table_and_two_ldk_keys() {
    let chain = ChainConfig::Bitcoind(konsensus_chain::BitcoindConfig {
        rpc_host: "127.0.0.1".into(),
        rpc_port: 38332,
        cookie_file: Some("/home/o/.bitcoin/signet/.cookie".into()),
        rpc_user: None,
        rpc_password_file: None,
    });
    let edited = replace_chain(CONFIG, &chain).unwrap();
    let edited = edit_table(
        &edited,
        "lightning",
        &["esplora_url", "esplora_url_fallback"],
        &["esplora_url = \"\"".to_string()],
    )
    .unwrap();
    // Comments and layout outside the edited keys survive.
    for kept in [
        "# my node",
        "# keep signet",
        "# chain source below",
        "[lightning.liquidity]",
        "[[peers]]",
    ] {
        assert!(edited.contains(kept), "{kept}: {edited}");
    }
    assert!(!edited.contains("mempool.space"), "{edited}");
    assert!(!edited.contains("blockstream.info"), "{edited}");
    let table: toml::Table = toml::from_str(&edited).unwrap();
    assert_eq!(table["chain"]["backend"].as_str(), Some("bitcoind"));
    assert_eq!(table["chain"]["rpc_port"].as_integer(), Some(38332));
    assert_eq!(table["lightning"]["esplora_url"].as_str(), Some(""));
    assert!(table["lightning"].get("esplora_url_fallback").is_none());
    assert_eq!(table["lightning"]["network"].as_str(), Some("signet"));
    assert_eq!(
        table["lightning"]["liquidity"]["enabled"].as_bool(),
        Some(false)
    );
    assert_eq!(table["peers"][0]["node_id"].as_str(), Some("ab"));
    assert_eq!(table["tier"].as_str(), Some("full"));
}

#[test]
fn an_omitted_ldk_url_is_written_empty_rather_than_left_to_the_frozen_default() {
    let text =
        "[lightning]\nbackend = \"ldk\"\nnetwork = \"signet\"\n\n[chain]\nbackend = \"esplora\"\n";
    let edited = edit_table(
        text,
        "lightning",
        &["esplora_url", "esplora_url_fallback"],
        &["esplora_url = \"\"".to_string()],
    )
    .unwrap();
    let table: toml::Table = toml::from_str(&edited).unwrap();
    assert_eq!(table["lightning"]["esplora_url"].as_str(), Some(""));
}

#[test]
fn layouts_this_command_cannot_edit_are_refused() {
    for text in [
        // Inline table: no [chain] header.
        "chain = { backend = \"esplora\" }\n",
        // Dotted keys.
        "chain.backend = \"esplora\"\n",
        // Two headers.
        "[chain]\nbackend = \"esplora\"\n[chain]\nbackend = \"mock\"\n",
    ] {
        let error = replace_chain(text, &ChainConfig::Mock)
            .unwrap_err()
            .to_string();
        assert!(error.ends_with("nothing was changed"), "{error}");
    }
    // An edit that would change more than intended fails verification.
    let original = "[chain]\nbackend = \"esplora\"\n";
    let error = verify_edit(original, "[chain]\nbackend = \"mock\"\n", |_| {})
        .unwrap_err()
        .to_string();
    assert!(error.contains("edit it by hand"), "{error}");
}

#[test]
fn verification_never_quotes_config_lines() {
    let original = "[chain]\nbackend = \"esplora\"\n";
    let error = verify_edit(original, "[chain]\nsecret = SECRET-VALUE\n", |_| {})
        .unwrap_err()
        .to_string();
    assert!(!error.contains("SECRET-VALUE"), "{error}");
}

#[test]
fn genesis_hashes_name_their_network() {
    for network in KNOWN_NETWORKS {
        let hash = bitcoin::blockdata::constants::genesis_block(network).block_hash();
        assert_eq!(network_of_genesis(hash), Some(network));
    }
    use bitcoin::hashes::Hash as _;
    assert_eq!(
        network_of_genesis(BlockHash::from_byte_array([7; 32])),
        None
    );
}
