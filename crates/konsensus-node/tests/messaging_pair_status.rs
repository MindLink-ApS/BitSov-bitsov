//! The CLI displays the same effective cap as the app's grant view.
#![cfg(unix)]

#[path = "../../konsensus-api/tests/common/owner_console.rs"]
mod owner_console;

use konsensus_api::control::{ControlRequest, ControlResponse};
use konsensus_api::pairing::{device, PairingService, RelationIntent};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn pair_status_shows_six_sat_messaging_cap_with_original_budget() {
    let dir = tempfile::tempdir().unwrap();
    let console = owner_console::OwnerConsole::default();
    let root = konsensus_core::OwnerApprovalKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "", &[9; 32],
    ).unwrap();
    let service = PairingService::open(dir.path(), "node-test".into(), true)
        .unwrap()
        .with_owner_approval_key(root.verifying_key())
        .with_owner_console(Box::new(console.clone()))
        .without_stdout_code();
    let client = service
        .create_ticket_remote_pairing(
            "app",
            &hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            &[2; 32],
        )
        .unwrap();
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let sign = |msg: &str| hex::encode(key.sign(&rng, msg.as_bytes()).unwrap().as_ref());
    let op = service
        .request_device_key(
            &client.client_id,
            &public,
            "device",
            &sign(&device::registration_message(
                "node-test",
                &client.client_id,
                &public,
            )),
        )
        .unwrap();
    let attestation = root.sign(
        device::owner_approval_message("node-test", &client.client_pubkey, client.epoch, &public)
            .as_bytes(),
    );
    service
        .approve_device_key(
            &op.op_id,
            &console.owner_code(&op.op_id),
            &hex::encode(attestation.to_bytes()),
        )
        .unwrap();
    let intent = RelationIntent {
        device_key_id: op.key_id,
        peer: "aa".repeat(32),
        level: 1,
        budget_msat: 200_000,
        per_act_max_msat: 20_000,
        window_secs: 3600,
        issued_at: chrono::Utc::now().timestamp(),
        nonce: "ab".repeat(16),
    };
    service
        .apply_relation_intent(
            &client.client_id,
            client.epoch,
            &intent,
            &sign(&device::intent_message(
                "node-test",
                &client.client_id,
                &intent,
            )),
        )
        .unwrap();
    let console_client = service
        .create_ticket_remote_pairing(
            "console app",
            &hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            &[3; 32],
        )
        .unwrap();
    let request = service
        .create_elevation_request(
            &console_client.client_id,
            vec![konsensus_api::auth::Scope::Spend],
        )
        .unwrap();
    service
        .grant_elevation(
            &request.op_id,
            &console.confirmation(&konsensus_api::pairing::grant_confirmation_phrase(&request)),
            konsensus_api::spend_budget::GrantTerms::new(200_000).per_call(20_000),
        )
        .unwrap();
    let response: ControlResponse = serde_json::from_value(serde_json::json!({
        "result": "status", "clients": [], "pending_elevations": [], "pending_replacements": [],
        "grants": service.grant_views(),
    }))
    .unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let line = BufReader::new(reader)
            .lines()
            .next_line()
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<ControlRequest>(&line).unwrap(),
            ControlRequest::Status
        ));
        let mut bytes = serde_json::to_vec(&response).unwrap();
        bytes.push(b'\n');
        writer.write_all(&bytes).await.unwrap();
    });
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["pair-status", "--config"])
        .arg(dir.path().join("konsensus.toml"))
        .output()
        .await
        .unwrap();
    server.await.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout.matches("per-call<=6 sats").count(), 2, "{stdout}");
    assert!(stdout.contains("200 of 200 sats left"), "{stdout}");
}
