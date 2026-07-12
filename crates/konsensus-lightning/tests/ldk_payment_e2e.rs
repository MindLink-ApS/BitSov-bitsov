//! B8: End-to-end LDK Lightning payment test with payment gate verification.
//!
//! Creates two in-process LDK nodes on regtest, opens a channel between them,
//! creates an invoice, pays it, and verifies the payment gate works end-to-end.
//!
//! This test requires Bitcoin Core + electrs binaries. With the `ldk-integration-test`
//! feature, they are auto-downloaded during compilation.
//!
//! Run with:
//! ```sh
//! cargo test -p konsensus-lightning --features ldk-integration-test \
//!     --test ldk_payment_e2e -- --nocapture
//! ```
//!
//! Or provide binaries manually:
//! ```sh
//! BITCOIND_EXE=/path/to/bitcoind ELECTRS_EXE=/path/to/electrs \
//!     cargo test -p konsensus-lightning --features ldk-integration-test \
//!     --test ldk_payment_e2e -- --nocapture
//! ```

#![cfg(feature = "ldk-integration-test")]

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Amount;
use electrsd::corepc_node::{self, Node as BitcoinD};
use electrsd::ElectrsD;
use konsensus_core::traits::lightning::{LightningProvider, PaymentDirection, PaymentStatus};
use konsensus_lightning::LdkProvider;
use ldk_node::config::EsploraSyncConfig;
use ldk_node::Builder;
use sha2::{Digest, Sha256};

// ── Infrastructure Setup ─────────────────────────────────────────────────────

/// Start a regtest bitcoind + electrsd (esplora) pair.
fn setup_bitcoind_and_electrsd() -> (BitcoinD, ElectrsD) {
    let bitcoind_exe = std::env::var("BITCOIND_EXE")
        .ok()
        .or_else(|| corepc_node::downloaded_exe_path().ok())
        .expect(
            "Set BITCOIND_EXE env var or enable corepc-node download feature",
        );

    let mut bitcoind_conf = corepc_node::Conf::default();
    bitcoind_conf.network = "regtest";
    bitcoind_conf.args.push("-rest");
    let bitcoind =
        BitcoinD::with_conf(bitcoind_exe, &bitcoind_conf).expect("failed to start bitcoind");

    let electrs_exe = std::env::var("ELECTRS_EXE")
        .ok()
        .or_else(electrsd::downloaded_exe_path)
        .expect("Set ELECTRS_EXE env var or enable electrsd download feature");

    let mut electrsd_conf = electrsd::Conf::default();
    electrsd_conf.http_enabled = true;
    electrsd_conf.network = "regtest";
    let electrsd = ElectrsD::with_conf(electrs_exe, &bitcoind, &electrsd_conf)
        .expect("failed to start electrsd");

    (bitcoind, electrsd)
}

/// Pick a random port to avoid conflicts between parallel test runs.
fn random_port() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen_range(10000..30000)
}

/// Build and start an LDK node pointed at the given esplora URL.
///
/// Returns the raw ldk_node::Node and a TempDir that must be kept alive.
fn build_ldk_node(
    esplora_url: &str,
    listen_port: u16,
) -> (ldk_node::Node, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");

    let mut builder = Builder::new();
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_storage_dir_path(tmp.path().to_str().unwrap().to_string());

    let sync_config = EsploraSyncConfig {
        background_sync_config: None,
    };
    builder.set_chain_source_esplora(esplora_url.to_string(), Some(sync_config));

    // P2P gossip — required for peer discovery in tests
    builder.set_gossip_source_p2p();

    let addr: ldk_node::lightning::ln::msgs::SocketAddress =
        format!("127.0.0.1:{listen_port}").parse().unwrap();
    builder
        .set_listening_addresses(vec![addr])
        .expect("failed to set listening address");

    let node = builder.build().expect("failed to build LDK node");
    node.start().expect("failed to start LDK node");

    (node, tmp)
}

/// Mine `num_blocks` blocks, wait for electrs to index them, then sync all nodes.
async fn mine_blocks_and_sync(
    bitcoind: &BitcoinD,
    electrsd: &ElectrsD,
    nodes: &[&ldk_node::Node],
    num_blocks: usize,
) {
    let _ = bitcoind.client.create_wallet("ldk_node_test");
    let _ = bitcoind.client.load_wallet("ldk_node_test");
    let addr = bitcoind
        .client
        .new_address()
        .expect("failed to get new address");
    let _ = bitcoind.client.generate_to_address(num_blocks, &addr);

    // Wait for electrs to index the new blocks.
    // Poll the electrum client's block height until it catches up.
    let target_height = bitcoind
        .client
        .get_blockchain_info()
        .unwrap()
        .blocks as usize;

    for _ in 0..40 {
        // electrsd exposes the esplora HTTP URL; use a simple height check
        let url = format!(
            "http://{}/blocks/tip/height",
            electrsd.esplora_url.as_ref().unwrap()
        );
        if let Ok(resp) = reqwest::get(&url).await {
            if let Ok(text) = resp.text().await {
                if let Ok(h) = text.trim().parse::<usize>() {
                    if h >= target_height {
                        break;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Sync each node's wallet with the chain
    for node in nodes {
        if let Err(e) = node.sync_wallets() {
            eprintln!("sync_wallets warning: {e}");
        }
    }
}

/// Wait for an LDK event with a timeout. Panics on timeout.
async fn expect_event(node: &ldk_node::Node, timeout_secs: u64) -> ldk_node::Event {
    tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        node.next_event_async(),
    )
    .await
    .expect("timed out waiting for LDK event")
}

// ── The Test ─────────────────────────────────────────────────────────────────

/// End-to-end test: two in-process LDK nodes, open channel, invoice, pay,
/// verify payment gate.
///
/// This test proves that:
/// 1. LdkProvider can create and manage real Lightning nodes
/// 2. Channels can be opened between nodes
/// 3. Invoice creation and payment work through the LightningProvider trait
/// 4. `verify_payment()` returns settled status with valid preimage
/// 5. SHA256(preimage) == payment_hash (cryptographic proof for the gate)
#[tokio::test(flavor = "multi_thread")]
async fn ldk_two_node_channel_payment_and_gate_verification() {
    // ── 1. Start infrastructure ──────────────────────────────────────────
    println!("Starting bitcoind + electrsd...");
    let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
    let esplora_url = format!("http://{}", electrsd.esplora_url.as_ref().unwrap());
    println!("Esplora URL: {esplora_url}");

    // ── 2. Create two LDK nodes ──────────────────────────────────────────
    println!("Building LDK nodes...");
    let port_a = random_port();
    let port_b = random_port();
    let (node_a_raw, _dir_a) = build_ldk_node(&esplora_url, port_a);
    let (node_b_raw, _dir_b) = build_ldk_node(&esplora_url, port_b);

    // Wrap in LdkProvider for LightningProvider trait testing
    let provider_a = LdkProvider::from_node(Arc::new(node_a_raw));
    let provider_b = LdkProvider::from_node(Arc::new(node_b_raw));

    // Verify both are running
    assert!(provider_a.is_available().await, "Node A should be available");
    assert!(provider_b.is_available().await, "Node B should be available");

    // Verify distinct pubkeys
    let pubkey_a = provider_a
        .get_node_pubkey()
        .await
        .expect("Node A should have a pubkey");
    let pubkey_b = provider_b
        .get_node_pubkey()
        .await
        .expect("Node B should have a pubkey");
    assert_ne!(pubkey_a, pubkey_b, "Nodes must have distinct pubkeys");
    println!("Node A: {pubkey_a}");
    println!("Node B: {pubkey_b}");

    // ── 3. Premine blocks for maturity ───────────────────────────────────
    println!("Premining 101 blocks...");
    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        101,
    )
    .await;

    // ── 4. Fund node A ──────────────────────────────────────────────────
    println!("Funding node A...");
    let addr_a = provider_a
        .node()
        .onchain_payment()
        .new_address()
        .expect("failed to get address for A");

    // Send 2.1M sats to node A via bitcoind RPC
    let send_amounts =
        serde_json::json!({ addr_a.to_string(): Amount::from_sat(2_100_000).to_btc() });
    bitcoind
        .client
        .call::<serde_json::Value>("sendmany", &[serde_json::json!(""), send_amounts])
        .expect("failed to send funds to node A");

    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        1,
    )
    .await;

    let balance_a = provider_a
        .get_balance_msat()
        .await
        .expect("failed to get balance");
    assert!(balance_a > 0, "Node A should have balance after funding");
    println!("Node A on-chain balance: {} msat", balance_a);

    // ── 5. Open channel A -> B with push amount ─────────────────────────
    let funding_sats: u64 = 1_000_000;
    let push_msat = (funding_sats / 2) * 1000; // Balance the channel
    println!("Opening {funding_sats} sat channel (push {push_msat} msat)...");

    let b_listen_addr = provider_b
        .node()
        .listening_addresses()
        .expect("Node B should have listening addresses")
        .first()
        .expect("Node B should have at least one address")
        .clone();

    provider_a
        .node()
        .open_channel(
            provider_b.node().node_id(),
            b_listen_addr,
            funding_sats,
            Some(push_msat),
            None,
        )
        .expect("failed to open channel");

    // Handle ChannelPending events on both nodes
    let ev_a = expect_event(provider_a.node(), 30).await;
    assert!(
        matches!(ev_a, ldk_node::Event::ChannelPending { .. }),
        "Expected ChannelPending on A, got: {ev_a:?}"
    );
    provider_a.node().event_handled().unwrap();

    let ev_b = expect_event(provider_b.node(), 30).await;
    assert!(
        matches!(ev_b, ldk_node::Event::ChannelPending { .. }),
        "Expected ChannelPending on B, got: {ev_b:?}"
    );
    provider_b.node().event_handled().unwrap();

    // Mine 6 blocks to confirm the funding tx
    println!("Mining 6 blocks for channel confirmation...");
    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        6,
    )
    .await;

    // Handle ChannelReady events
    let ev_a = expect_event(provider_a.node(), 30).await;
    assert!(
        matches!(ev_a, ldk_node::Event::ChannelReady { .. }),
        "Expected ChannelReady on A, got: {ev_a:?}"
    );
    provider_a.node().event_handled().unwrap();

    let ev_b = expect_event(provider_b.node(), 30).await;
    assert!(
        matches!(ev_b, ldk_node::Event::ChannelReady { .. }),
        "Expected ChannelReady on B, got: {ev_b:?}"
    );
    provider_b.node().event_handled().unwrap();

    // Verify channels via LightningProvider trait
    let channels_a = provider_a
        .list_channels()
        .await
        .expect("failed to list channels on A");
    assert!(!channels_a.is_empty(), "Node A should have an open channel");
    assert!(channels_a[0].active, "Channel should be active");
    println!(
        "Channel capacity: {} msat, A local: {} msat",
        channels_a[0].capacity_msat, channels_a[0].local_balance_msat
    );

    let channels_b = provider_b
        .list_channels()
        .await
        .expect("failed to list channels on B");
    assert!(!channels_b.is_empty(), "Node B should have an open channel");

    // ── 6. B creates invoice via LightningProvider ──────────────────────
    let payment_amount_msat: u64 = 100_000; // 100 sats
    println!("B creating invoice for {payment_amount_msat} msat...");

    let invoice = provider_b
        .create_invoice(payment_amount_msat, "B8 payment gate e2e test", 3600)
        .await
        .expect("failed to create invoice");

    assert_eq!(invoice.amount_msat, payment_amount_msat);
    assert!(!invoice.bolt11.is_empty(), "bolt11 should not be empty");
    assert!(!invoice.payment_hash.is_empty(), "payment_hash should not be empty");
    println!("Invoice hash: {}", invoice.payment_hash);

    // ── 7. A pays the invoice via LightningProvider ─────────────────────
    println!("A paying invoice...");
    let payment = provider_a
        .pay_invoice(&invoice.bolt11)
        .await
        .expect("failed to pay invoice");
    assert_eq!(payment.direction, PaymentDirection::Outgoing);
    println!("Payment initiated, status: {:?}", payment.status);

    // Process events: A gets PaymentSuccessful, B gets PaymentReceived
    let ev_a = expect_event(provider_a.node(), 30).await;
    assert!(
        matches!(ev_a, ldk_node::Event::PaymentSuccessful { .. }),
        "Expected PaymentSuccessful on A, got: {ev_a:?}"
    );
    provider_a.node().event_handled().unwrap();
    println!("A: payment successful");

    let ev_b = expect_event(provider_b.node(), 30).await;
    assert!(
        matches!(ev_b, ldk_node::Event::PaymentReceived { .. }),
        "Expected PaymentReceived on B, got: {ev_b:?}"
    );
    provider_b.node().event_handled().unwrap();
    println!("B: payment received");

    // ── 8. Verify payment settled on sender (A) ─────────────────────────
    let status_a = provider_a
        .get_payment_status(&invoice.payment_hash)
        .await
        .expect("failed to get payment status on A");
    assert_eq!(
        status_a.status,
        PaymentStatus::Settled,
        "Payment should be settled on sender"
    );
    assert_eq!(status_a.direction, PaymentDirection::Outgoing);
    assert!(status_a.preimage.is_some(), "Settled outgoing payment should have preimage");
    println!("A status: {:?}, fee: {:?} msat", status_a.status, status_a.fee_msat);

    // ── 9. Verify payment received on recipient (B) ─────────────────────
    let status_b = provider_b
        .get_payment_status(&invoice.payment_hash)
        .await
        .expect("failed to get payment status on B");
    assert_eq!(
        status_b.status,
        PaymentStatus::Settled,
        "Payment should be settled on recipient"
    );
    assert_eq!(status_b.direction, PaymentDirection::Incoming);
    assert_eq!(status_b.amount_msat, payment_amount_msat);
    println!("B status: {:?}, amount: {} msat", status_b.status, status_b.amount_msat);

    // ── 10. PAYMENT GATE VERIFICATION ───────────────────────────────────
    // verify_payment() is the method PaymentGate uses to confirm Lightning
    // settlement when verify_lightning_settlement is enabled.
    let gate_result = provider_b
        .verify_payment(&invoice.payment_hash)
        .await
        .expect("verify_payment should succeed for settled payment");
    assert_eq!(gate_result.status, PaymentStatus::Settled);
    assert!(
        gate_result.preimage.is_some(),
        "Gate verification must return preimage as settlement proof"
    );
    println!("Gate verification passed: preimage present");

    // ── 11. Cryptographic proof: SHA256(preimage) == payment_hash ────────
    // This is the fundamental invariant the payment gate relies on.
    // The preimage is the proof-of-payment that the gate checks.
    let preimage_hex = gate_result.preimage.unwrap();
    let preimage_bytes = hex::decode(&preimage_hex).expect("preimage should be valid hex");
    assert_eq!(preimage_bytes.len(), 32, "preimage should be 32 bytes");

    let computed_hash = Sha256::digest(&preimage_bytes);
    assert_eq!(
        hex::encode(computed_hash),
        invoice.payment_hash,
        "SHA256(preimage) must equal payment_hash - this is the cryptographic proof"
    );
    println!("Cryptographic proof verified: SHA256(preimage) == payment_hash");

    // ── 12. Verify payment listing ──────────────────────────────────────
    let payments_a = provider_a
        .list_payments(10)
        .await
        .expect("failed to list payments on A");
    assert!(
        payments_a.iter().any(|p| p.payment_hash == invoice.payment_hash),
        "Node A payment list should contain the payment"
    );

    let payments_b = provider_b
        .list_payments(10)
        .await
        .expect("failed to list payments on B");
    assert!(
        payments_b.iter().any(|p| p.payment_hash == invoice.payment_hash),
        "Node B payment list should contain the payment"
    );

    // ── 13. Verify balance changes ──────────────────────────────────────
    // A's local balance should decrease and B's should increase after the
    // payment settles. The sender (A) debits immediately, but the receiver (B)
    // only reflects the credit in `list_channels()` after the post-settlement
    // commitment round-trip, which can lag A's debit by a few hundred ms. Poll
    // until both balances reflect rather than reading a single early snapshot.
    // This is a settlement-reflection timing wait, NOT an assertion relaxation:
    // a genuine failure to credit B still trips the asserts below on timeout.
    let mut channels_a_after = provider_a.list_channels().await.unwrap();
    let mut channels_b_after = provider_b.list_channels().await.unwrap();
    for _ in 0..40 {
        let a_decreased =
            channels_a_after[0].local_balance_msat < channels_a[0].local_balance_msat;
        let b_increased =
            channels_b_after[0].local_balance_msat > channels_b[0].local_balance_msat;
        if a_decreased && b_increased {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        channels_a_after = provider_a.list_channels().await.unwrap();
        channels_b_after = provider_b.list_channels().await.unwrap();
    }

    // A's local balance should have decreased
    assert!(
        channels_a_after[0].local_balance_msat < channels_a[0].local_balance_msat,
        "A's local balance should decrease after paying"
    );
    // B's local balance should have increased
    assert!(
        channels_b_after[0].local_balance_msat > channels_b[0].local_balance_msat,
        "B's local balance should increase after receiving"
    );

    println!(
        "\n=== B8 LDK Payment Gate E2E Test PASSED ===\n\
         Nodes: {pubkey_a} <-> {pubkey_b}\n\
         Channel: {} sat\n\
         Payment: {} msat (hash: {})\n\
         Gate: verified (preimage proof valid)",
        funding_sats,
        payment_amount_msat,
        &invoice.payment_hash[..16],
    );
}

/// Keysend payment test: spontaneous payment without invoice.
///
/// Proves that the payment gate can verify keysend payments — useful for
/// streaming micropayments (VoIP, per-second billing).
#[tokio::test(flavor = "multi_thread")]
async fn ldk_keysend_payment() {
    // ── Setup (identical to above) ───────────────────────────────────────
    println!("Starting bitcoind + electrsd...");
    let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
    let esplora_url = format!("http://{}", electrsd.esplora_url.as_ref().unwrap());

    let port_a = random_port();
    let port_b = random_port();
    let (node_a_raw, _dir_a) = build_ldk_node(&esplora_url, port_a);
    let (node_b_raw, _dir_b) = build_ldk_node(&esplora_url, port_b);

    let provider_a = LdkProvider::from_node(Arc::new(node_a_raw));
    let provider_b = LdkProvider::from_node(Arc::new(node_b_raw));

    // Premine
    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        101,
    )
    .await;

    // Fund node A
    let addr_a = provider_a.node().onchain_payment().new_address().unwrap();
    let send_amounts =
        serde_json::json!({ addr_a.to_string(): Amount::from_sat(2_100_000).to_btc() });
    bitcoind
        .client
        .call::<serde_json::Value>("sendmany", &[serde_json::json!(""), send_amounts])
        .unwrap();
    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        1,
    )
    .await;

    // Open channel
    let b_addr = provider_b
        .node()
        .listening_addresses()
        .unwrap()
        .first()
        .unwrap()
        .clone();
    provider_a
        .node()
        .open_channel(
            provider_b.node().node_id(),
            b_addr,
            1_000_000,
            Some(500_000_000),
            None,
        )
        .unwrap();

    // Handle channel events
    let _ = expect_event(provider_a.node(), 30).await;
    provider_a.node().event_handled().unwrap();
    let _ = expect_event(provider_b.node(), 30).await;
    provider_b.node().event_handled().unwrap();

    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        6,
    )
    .await;

    let _ = expect_event(provider_a.node(), 30).await;
    provider_a.node().event_handled().unwrap();
    let _ = expect_event(provider_b.node(), 30).await;
    provider_b.node().event_handled().unwrap();

    // ── Keysend payment ─────────────────────────────────────────────────
    let pubkey_b = provider_b.get_node_pubkey().await.unwrap();
    let keysend_amount_msat: u64 = 50_000;

    println!("A keysending {keysend_amount_msat} msat to B ({pubkey_b})...");
    let payment = provider_a
        .keysend(&pubkey_b, keysend_amount_msat, Some("B8 keysend test"))
        .await
        .expect("keysend should succeed");
    assert_eq!(payment.direction, PaymentDirection::Outgoing);

    // Process events
    let ev_a = expect_event(provider_a.node(), 30).await;
    assert!(
        matches!(ev_a, ldk_node::Event::PaymentSuccessful { .. }),
        "Expected PaymentSuccessful, got: {ev_a:?}"
    );
    provider_a.node().event_handled().unwrap();

    let ev_b = expect_event(provider_b.node(), 30).await;
    assert!(
        matches!(ev_b, ldk_node::Event::PaymentReceived { .. }),
        "Expected PaymentReceived, got: {ev_b:?}"
    );
    provider_b.node().event_handled().unwrap();

    // Verify keysend was received
    let payments_b = provider_b.list_payments(10).await.unwrap();
    let keysend_payment = payments_b
        .iter()
        .find(|p| p.direction == PaymentDirection::Incoming && p.amount_msat == keysend_amount_msat)
        .expect("B should have received the keysend payment");
    assert_eq!(keysend_payment.status, PaymentStatus::Settled);

    println!("=== B8 Keysend Test PASSED ===");
}

/// R2 seam-3c: on-wire proof that `keysend_with_binding` delivers the ADR-037
/// binding TLV across a real regtest channel.
///
/// This closes the one integration gap the unit tests cannot cover: that a
/// custom (odd) application TLV pushed via `SpontaneousPayment::send_with_custom_tlvs`
/// actually survives a real HTLC and arrives in the recipient's
/// `Event::PaymentReceived.custom_records`. Everything downstream of that event
/// — the drainer fan-out, `extract_binding_tlv`, and the `watch_inbound_keysend`
/// stream — is already proven in-process by unit tests (mock keystone,
/// `ldk_event_drain`, and the `extract_binding_tlv` suite), so here we assert the
/// wire delivery that only two real nodes can demonstrate.
#[tokio::test(flavor = "multi_thread")]
async fn ldk_keysend_with_binding_delivers_adr037_tlv_on_wire() {
    // The agreed BitSov binding TLV type (ADR-037). Must match
    // `BITSOV_BINDING_TLV_TYPE` in `ldk.rs` (private there; pinned here so a
    // drift in the const is caught by this on-wire assertion). Odd per BOLT-1.
    const BITSOV_BINDING_TLV_TYPE: u64 = 0x4253_4F56_0001;

    // ── Setup (mirrors ldk_keysend_payment) ─────────────────────────────
    println!("Starting bitcoind + electrsd...");
    let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
    let esplora_url = format!("http://{}", electrsd.esplora_url.as_ref().unwrap());

    let port_a = random_port();
    let port_b = random_port();
    let (node_a_raw, _dir_a) = build_ldk_node(&esplora_url, port_a);
    let (node_b_raw, _dir_b) = build_ldk_node(&esplora_url, port_b);

    let provider_a = LdkProvider::from_node(Arc::new(node_a_raw));
    let provider_b = LdkProvider::from_node(Arc::new(node_b_raw));

    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        101,
    )
    .await;

    // Fund node A
    let addr_a = provider_a.node().onchain_payment().new_address().unwrap();
    let send_amounts =
        serde_json::json!({ addr_a.to_string(): Amount::from_sat(2_100_000).to_btc() });
    bitcoind
        .client
        .call::<serde_json::Value>("sendmany", &[serde_json::json!(""), send_amounts])
        .unwrap();
    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        1,
    )
    .await;

    // Open channel A -> B, push half so B can be paid immediately
    let b_addr = provider_b
        .node()
        .listening_addresses()
        .unwrap()
        .first()
        .unwrap()
        .clone();
    provider_a
        .node()
        .open_channel(
            provider_b.node().node_id(),
            b_addr,
            1_000_000,
            Some(500_000_000),
            None,
        )
        .unwrap();

    let _ = expect_event(provider_a.node(), 30).await;
    provider_a.node().event_handled().unwrap();
    let _ = expect_event(provider_b.node(), 30).await;
    provider_b.node().event_handled().unwrap();

    mine_blocks_and_sync(
        &bitcoind,
        &electrsd,
        &[provider_a.node(), provider_b.node()],
        6,
    )
    .await;

    let _ = expect_event(provider_a.node(), 30).await;
    provider_a.node().event_handled().unwrap();
    let _ = expect_event(provider_b.node(), 30).await;
    provider_b.node().event_handled().unwrap();

    // ── Send a keysend carrying the ADR-037 binding ─────────────────────
    let pubkey_b = provider_b.get_node_pubkey().await.unwrap();
    let amount_msat: u64 = 50_000;
    let binding = b"r2-seam3c-envelope-binding-pointer".to_vec();

    println!("A keysend_with_binding -> B ({pubkey_b}), {} byte binding...", binding.len());
    let payment = provider_a
        .keysend_with_binding(&pubkey_b, amount_msat, &binding)
        .await
        .expect("keysend_with_binding should succeed over a real channel");
    assert_eq!(payment.direction, PaymentDirection::Outgoing);

    // A: PaymentSuccessful
    let ev_a = expect_event(provider_a.node(), 30).await;
    assert!(
        matches!(ev_a, ldk_node::Event::PaymentSuccessful { .. }),
        "Expected PaymentSuccessful on A, got: {ev_a:?}"
    );
    provider_a.node().event_handled().unwrap();

    // B: PaymentReceived — MUST carry our binding TLV in custom_records
    let ev_b = expect_event(provider_b.node(), 30).await;
    let (recv_amount, custom_records) = match &ev_b {
        ldk_node::Event::PaymentReceived {
            amount_msat,
            custom_records,
            ..
        } => (*amount_msat, custom_records.clone()),
        other => panic!("Expected PaymentReceived on B, got: {other:?}"),
    };
    provider_b.node().event_handled().unwrap();

    assert_eq!(recv_amount, amount_msat, "received amount matches sent");

    // ── ON-WIRE PROOF ───────────────────────────────────────────────────
    // Exactly one BitSov binding record arrived, with the bytes verbatim.
    let bitsov_records: Vec<_> = custom_records
        .iter()
        .filter(|r| r.type_num == BITSOV_BINDING_TLV_TYPE)
        .collect();
    assert_eq!(
        bitsov_records.len(),
        1,
        "exactly one BitSov binding TLV must arrive (the send-side single-record \
         invariant the receiver's duplicate-guard relies on); got {} (all type_nums: {:?})",
        bitsov_records.len(),
        custom_records.iter().map(|r| r.type_num).collect::<Vec<_>>()
    );
    assert_eq!(
        bitsov_records[0].value, binding,
        "the binding bytes must survive the real HTLC verbatim — this is exactly \
         the input the receive-half's extract_binding_tlv consumes"
    );

    println!(
        "=== R2 seam-3c PASSED: ADR-037 binding TLV ({} bytes) delivered on-wire ===",
        binding.len()
    );
}
