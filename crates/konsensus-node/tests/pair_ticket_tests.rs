use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::process::Command;

#[test]
fn pair_ticket_cli_writes_a_protected_prebootstrap_ticket_and_rejects_bad_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("konsensus.toml");
    std::fs::write(
        &config,
        r#"
[node]
hosted_by = "Rasmus's Pi"
[identity]
mnemonic_file = "absent.enc"
[network]
[lightning]
backend = "mock"
[chain]
backend = "mock"
[storage]
backend = "sqlite"
[remote_access]
listen_addr = "127.0.0.1:18443"
advertised_endpoint = "node.example:18443"
"#,
    )
    .unwrap();
    let before = chrono::Utc::now().timestamp();
    let output = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["pair-ticket", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let uri = String::from_utf8(output.stdout).unwrap();
    let uri = uri.trim();
    let ticket: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(uri.strip_prefix("bitsov://pair/").unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(ticket.get("node_id").is_none());
    assert_eq!(ticket["hosted_by"], "Rasmus's Pi");
    assert_eq!(ticket["box_transport_pubkey"].as_str().unwrap().len(), 64);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(ticket["code"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert!((before + 86400..=chrono::Utc::now().timestamp() + 86400)
        .contains(&ticket["expires_at"].as_i64().unwrap()));
    let path = dir.path().join("pairing/remote-access-link");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), uri);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["pair-ticket", "--config"])
        .arg(&config)
        .args(["--qr", "--ttl", "2h"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    let (qr_uri, rendered) = output.split_once('\n').unwrap();
    assert_eq!(decode_terminal_qr(rendered), qr_uri.as_bytes());
    let ticket: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(qr_uri.strip_prefix("bitsov://pair/").unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!((before + 7200..=chrono::Utc::now().timestamp() + 7200)
        .contains(&ticket["expires_at"].as_i64().unwrap()));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), qr_uri);
    let uri = qr_uri;
    for ttl in ["0s", "nope", "18446744073709551615h"] {
        let bad = Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args(["pair-ticket", "--config"])
            .arg(&config)
            .args(["--ttl", ttl])
            .output()
            .unwrap();
        assert!(!bad.status.success());
        assert!(bad.stdout.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), uri);
    }
    let original = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, original.replace("hosted_by", "hosted_byy")).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["pair-ticket", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "unknown node fields must be refused"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), uri);
}

#[test]
fn pair_ticket_qr_fits_the_longest_label_and_refuses_unprintable_ones() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("konsensus.toml");
    let write_config = |hosted_by: &str| {
        std::fs::write(
            &config,
            format!(
                r#"
[node]
hosted_by = "{hosted_by}"
[identity]
mnemonic_file = "absent.enc"
[network]
[lightning]
backend = "mock"
[chain]
backend = "mock"
[storage]
backend = "sqlite"
[remote_access]
listen_addr = "127.0.0.1:18443"
advertised_endpoint = "{}.example:18443"
"#,
                "n".repeat(63)
            ),
        )
        .unwrap();
    };
    let pair_ticket = || {
        Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args(["pair-ticket", "--config"])
            .arg(&config)
            .args(["--qr", "--ttl", "365d"])
            .output()
            .unwrap()
    };
    // 64 four-byte characters is the largest label validation admits.
    let longest = "𝔅".repeat(64);
    write_config(&longest);
    let output = pair_ticket();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    let (uri, rendered) = output.split_once('\n').unwrap();
    assert_eq!(decode_terminal_qr(rendered), uri.as_bytes());
    let ticket: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(uri.strip_prefix("bitsov://pair/").unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ticket["hosted_by"], longest.as_str());
    let path = dir.path().join("pairing/remote-access-link");
    for bad in [
        "Rasmus\\u0007Pi".to_string(),
        "Pi\\u202Ekcab".to_string(),
        " Pi".to_string(),
        "x".repeat(65),
    ] {
        write_config(&bad);
        let rejected = pair_ticket();
        assert!(!rejected.status.success(), "{bad:?} must be refused");
        assert!(rejected.stdout.is_empty());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("hosted_by"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), uri);
    }
}

// Convert the actual printed half-block glyphs to a grayscale raster. Decode
// with an independent library, so polarity, quiet zone and URI wiring matter.
fn decode_terminal_qr(rendered: &str) -> Vec<u8> {
    let lines: Vec<_> = rendered.lines().collect();
    let width = lines[0].chars().count();
    let height = lines.len() * 2;
    let scale = 4;
    let mut pixels = vec![255u8; width * height * scale * scale];
    for (row, line) in lines.iter().enumerate() {
        assert_eq!(line.chars().count(), width);
        for (col, ch) in line.chars().enumerate() {
            let pair = match ch {
                ' ' => [0, 0],
                '▀' => [255, 0],
                '▄' => [0, 255],
                '█' => [255, 255],
                _ => panic!("unexpected terminal glyph"),
            };
            for (half, value) in pair.into_iter().enumerate() {
                for y in 0..scale {
                    for x in 0..scale {
                        pixels[((row * 2 + half) * scale + y) * width * scale + col * scale + x] =
                            value;
                    }
                }
            }
        }
    }
    let mut decoder = quircs::Quirc::default();
    let codes: Vec<_> = decoder
        .identify(width * scale, height * scale, &pixels)
        .collect();
    assert_eq!(codes.len(), 1);
    codes[0].as_ref().unwrap().decode().unwrap().payload
}
