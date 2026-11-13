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

/// A generated config with `[chain]` and `[lightning]` replaced.
fn node_config(dir: &Path, chain: &str, lightning: &str) -> NodeConfig {
    let base = NodeConfig::default_for_tier(
        crate::config::NodeTier::Light,
        dir.join("mnemonic.txt"),
        dir,
    );
    let mut table = toml::Table::try_from(&base).unwrap();
    table.insert(
        "chain".into(),
        toml::Value::Table(toml::from_str(chain).unwrap()),
    );
    table.insert(
        "lightning".into(),
        toml::Value::Table(toml::from_str(lightning).unwrap()),
    );
    toml::from_str(&toml::to_string(&table).unwrap()).unwrap()
}

#[cfg(unix)]
fn private_file(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The preflight builds what embedded LDK builds at start: a leftover paid
/// Esplora `credentials_file` with an empty `esplora_url` cannot start.
#[cfg(unix)]
#[test]
fn ldk_preflight_refuses_leftover_esplora_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = dir.path().join("chain-api.toml");
    private_file(
        &credentials,
        "token_url = \"https://login.example/token\"\nclient_id = \"fixture\"\nclient_secret = \"fixture-only\"\n",
    );
    let cookie = dir.path().join("core.cookie");
    std::fs::write(&cookie, "__cookie__:fixture\n").unwrap();
    let chain = format!(
        "backend = \"bitcoind\"\nrpc_host = \"127.0.0.1\"\nrpc_port = 38332\ncookie_file = {:?}",
        cookie
    );
    let leftover = node_config(
        dir.path(),
        &chain,
        &format!(
            "backend = \"ldk\"\nnetwork = \"signet\"\nesplora_url = \"\"\ncredentials_file = {:?}",
            credentials
        ),
    );
    let error = ldk_chain_source_preflight(&leftover)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("embedded Lightning could not start"),
        "{error}"
    );
    let clean = node_config(
        dir.path(),
        &chain,
        "backend = \"ldk\"\nnetwork = \"signet\"\nesplora_url = \"\"",
    );
    ldk_chain_source_preflight(&clean).unwrap();
    // A missing cookie is caught the same way start would.
    std::fs::remove_file(&cookie).unwrap();
    assert!(ldk_chain_source_preflight(&clean).is_err());
}

#[test]
fn credentials_are_noticed_in_either_stanza() {
    let dir = tempfile::tempdir().unwrap();
    for (chain, lightning, expected) in [
        (
            "backend = \"esplora\"",
            "backend = \"ldk\"\nnetwork = \"signet\"\ncredentials_file = \"/s/c.toml\"",
            true,
        ),
        (
            "backend = \"esplora\"\ncredentials_file = \"/s/c.toml\"",
            "backend = \"ldk\"\nnetwork = \"signet\"",
            true,
        ),
        (
            "backend = \"esplora\"",
            "backend = \"ldk\"\nnetwork = \"signet\"",
            false,
        ),
    ] {
        let config = node_config(dir.path(), chain, lightning);
        assert_eq!(
            had_esplora_credentials(&config),
            expected,
            "{chain} / {lightning}"
        );
    }
}

/// A backup that fails after its file was created and partly written leaves
/// neither a published backup nor a temporary, and the config is untouched.
#[test]
fn a_backup_failing_after_its_file_was_written_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("konsensus.toml");
    std::fs::write(&config, "tier = \"full\"\n").unwrap();
    let files = WriteFiles::new(&config).unwrap();
    FAIL_BACKUP_AFTER_WRITE.set(true);
    let error = write_backup(&files, b"tier = \"full\"\n")
        .unwrap_err()
        .to_string();
    assert!(
        !FAIL_BACKUP_AFTER_WRITE.get(),
        "the failure was not injected"
    );
    assert!(error.contains("could not write the backup"), "{error}");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "tier = \"full\"\n"
    );
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["konsensus.toml"], "left behind: {names:?}");
}

#[test]
fn the_config_is_replaced_through_a_fresh_temporary() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("konsensus.toml");
    std::fs::write(&config, "old\n").unwrap();
    // A file at the shared writer's fixed temporary name is not touched.
    let fixed = dir.path().join("konsensus.toml.tmp");
    std::fs::write(&fixed, "keep\n").unwrap();
    let files = WriteFiles::new(&config).unwrap();
    assert_ne!(files.config_temp, fixed);
    assert_ne!(files.backup_temp, fixed);
    replace_config(&config, &files.config_temp, b"new\n").unwrap();
    assert_eq!(std::fs::read_to_string(&config).unwrap(), "new\n");
    assert_eq!(std::fs::read_to_string(&fixed).unwrap(), "keep\n");
    assert!(!files.config_temp.exists());
    // An existing file at the temporary name is never replaced or removed.
    std::fs::write(&files.config_temp, "someone else's\n").unwrap();
    assert!(replace_config(&config, &files.config_temp, b"newer\n").is_err());
    assert_eq!(
        std::fs::read_to_string(&files.config_temp).unwrap(),
        "someone else's\n"
    );
    assert_eq!(std::fs::read_to_string(&config).unwrap(), "new\n");
}

#[cfg(unix)]
#[test]
fn same_file_sees_symlinks_and_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("konsensus.toml");
    std::fs::write(&file, "x\n").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(same_file(&link, &file));
    assert!(same_file(
        &dir.path().join(".").join("konsensus.toml"),
        &file
    ));
    assert!(!same_file(&dir.path().join("other"), &file));
}

/// A config whose recovery phrase is `phrase` (Light tier, mock chain).
#[cfg(unix)]
fn config_reading(dir: &Path, phrase: &Path) -> NodeConfig {
    NodeConfig::default_for_tier(crate::config::NodeTier::Light, phrase.to_path_buf(), dir)
}

/// The reviewed race: the config path goes through a symlinked directory. The
/// checks pass against directory A; right after the directory is pinned the
/// symlink is pointed at the directory holding the recovery phrase under the
/// config's own name. Every write must still land in A: the phrase survives,
/// A's config is replaced, and A holds the backup of the original.
#[cfg(unix)]
#[test]
fn a_parent_symlink_changed_after_the_checks_cannot_redirect_the_writes() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a");
    let private = root.path().join("private");
    for d in [&a, &private] {
        std::fs::create_dir(d).unwrap();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let phrase = private.join("konsensus.toml");
    std::fs::write(&phrase, "synthetic recovery words\n").unwrap();
    std::fs::write(a.join("konsensus.toml"), "original\n").unwrap();
    let link = root.path().join("node");
    std::os::unix::fs::symlink(&a, &link).unwrap();
    let config_path = link.join("konsensus.toml");
    let files = WriteFiles::new(&config_path).unwrap();
    let config = config_reading(root.path(), &phrase);

    let (link2, private2) = (link.clone(), private.clone());
    AFTER_PIN.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::remove_file(&link2).unwrap();
            std::os::unix::fs::symlink(&private2, &link2).unwrap();
        }))
    });
    let backup = write_pinned(&files, b"original\n", b"edited\n", &config, &ChainConfig::Mock).unwrap();
    assert!(AFTER_PIN.with(|h| h.borrow().is_none()), "the retarget did not run");
    assert_eq!(std::fs::read_to_string(&phrase).unwrap(), "synthetic recovery words\n");
    assert_eq!(std::fs::read_to_string(a.join("konsensus.toml")).unwrap(), "edited\n");
    let backup_in_a = a.join(backup.file_name().unwrap());
    assert_eq!(std::fs::read_to_string(&backup_in_a).unwrap(), "original\n");
    let private_names: Vec<String> = std::fs::read_dir(&private)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(private_names, ["konsensus.toml"], "written into the recovery directory: {private_names:?}");
}

/// A config directory that group or others can write is refused before any
/// write: someone else could swap names inside it.
#[cfg(unix)]
#[test]
fn a_config_directory_others_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let shared = root.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
    let config_path = shared.join("konsensus.toml");
    std::fs::write(&config_path, "original\n").unwrap();
    let files = WriteFiles::new(&config_path).unwrap();
    let config = config_reading(root.path(), &root.path().join("phrase.txt"));
    let error = write_pinned(&files, b"original\n", b"edited\n", &config, &ChainConfig::Mock)
        .unwrap_err()
        .to_string();
    assert!(error.contains("can be written by other users"), "{error}");
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), "original\n");
    assert_eq!(std::fs::read_dir(&shared).unwrap().count(), 1);
}

/// The recovery phrase at one of the written names in the pinned directory
/// (here: the backup name) is refused, and nothing is written.
#[cfg(unix)]
#[test]
fn a_recovery_phrase_at_a_written_name_in_the_pinned_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("konsensus.toml");
    std::fs::write(&config_path, "original\n").unwrap();
    let files = WriteFiles::new(&config_path).unwrap();
    std::fs::write(&files.backup, "synthetic recovery words\n").unwrap();
    let config = config_reading(dir.path(), &files.backup);
    let error = write_pinned(&files, b"original\n", b"edited\n", &config, &ChainConfig::Mock)
        .unwrap_err()
        .to_string();
    assert!(error.contains("is the same file as"), "{error}");
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), "original\n");
    assert_eq!(std::fs::read_to_string(&files.backup).unwrap(), "synthetic recovery words\n");
}

/// Cleanup removes a temporary only while the name still points at the file
/// this operation created; an entry swapped in under that name is kept.
#[cfg(unix)]
#[test]
fn cleanup_keeps_an_entry_swapped_in_under_the_temporary_name() {
    let dir = tempfile::tempdir().unwrap();
    let pinned = crate::config_dir::ConfigDir::open(&dir.path().join("konsensus.toml")).unwrap();
    let name = std::ffi::OsStr::new(".t.tmp");
    let created = pinned.create_new(name, b"ours\n").unwrap();
    std::fs::remove_file(dir.path().join(".t.tmp")).unwrap();
    std::fs::write(dir.path().join(".t.tmp"), "someone else's\n").unwrap();
    pinned.remove_if(name, created);
    assert_eq!(std::fs::read_to_string(dir.path().join(".t.tmp")).unwrap(), "someone else's\n");
}
