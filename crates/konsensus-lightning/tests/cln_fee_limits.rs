//! PR3 money-path contract tests against a local TLS clnrest double.
#[path = "common/cln.rs"]
mod common;
use common::*;
use konsensus_core::traits::lightning::{
    LightningError, LightningProvider, PaymentDirection, PaymentStatus, RoutingFeePolicy,
};
use konsensus_lightning::ClnProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn hash() -> String {
    hex::encode(Sha256::digest([42; 32]))
}
fn invoice(amount: Option<u64>) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let mut builder = lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
        .description("CLN capped payment".into())
        .payment_hash(hash().parse().unwrap())
        .payment_secret(lightning_invoice::PaymentSecret([42; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(18);
    if let Some(amount) = amount {
        builder = builder.amount_milli_satoshis(amount);
    }
    builder
        .build_signed(|m| {
            Secp256k1::new().sign_ecdsa_recoverable(m, &SecretKey::from_slice(&[42; 32]).unwrap())
        })
        .unwrap()
        .to_string()
}
fn paid(amount: u64, fee: u64) -> Value {
    json!({"payment_preimage":hex::encode([42;32]), "amount_msat":amount,
        "amount_sent_msat":amount+fee, "failed_parts":0,"successful_parts":1})
}
async fn setup(version: &str) -> (Server, tempfile::TempDir, ClnProvider) {
    let server = Server::new(200, info(version, "regtest")).await;
    server.route("listpays", json!({"pays":[]}));
    let dir = tempfile::tempdir().unwrap();
    let provider = ClnProvider::new(server.config(&dir))
        .await
        .unwrap()
        .with_routing_fee_policy(RoutingFeePolicy {
            minimum_msat: 100,
            proportional_millionths: 10_000,
            maximum_msat: 500,
        });
    (server, dir, provider)
}
fn money_calls(server: &Server) -> Vec<(String, Value)> {
    server
        .calls()
        .into_iter()
        .filter(|(p, _)| {
            matches!(
                p.as_str(),
                "/v1/xpay" | "/v1/xkeysend" | "/v1/keysend" | "/v1/pay"
            )
        })
        .collect()
}
#[tokio::test]
async fn t2_exact_ceiling_including_zero_and_caller_cannot_widen() {
    for (amount, caller, expected) in [
        (1000, 0, 0),
        (1000, 23, 23),
        (1000, u64::MAX, 100),
        (20000, 999, 200),
        (100000, 999, 500),
    ] {
        let (server, _dir, provider) = setup("v24.11").await;
        server.route("xpay", paid(amount, expected));
        let inv = invoice(Some(amount));
        let result = provider
            .pay_invoice_with_fee_limit(&inv, caller)
            .await
            .unwrap();
        assert_eq!(result.status, PaymentStatus::Settled);
        assert_eq!(result.direction, PaymentDirection::Outgoing);
        assert_eq!(result.payment_hash, hash());
        assert_eq!(result.preimage, Some(hex::encode([42; 32])));
        assert_eq!(result.amount_msat, amount);
        assert_eq!(result.fee_msat, Some(expected));
        assert_eq!(
            money_calls(&server),
            vec![(
                "/v1/xpay".into(),
                json!({"invstring":inv,"maxfee":expected,"retry_for":60})
            )]
        );
        assert!(server
            .calls()
            .contains(&("/v1/listpays".into(), json!({"payment_hash":hash()}))));
    }
}
#[tokio::test]
async fn t2_local_parse_and_amountless_refusal_never_dispatch() {
    let (server, _dir, provider) = setup("v24.11").await;
    for inv in ["invalid".to_string(), invoice(None)] {
        assert!(provider.pay_invoice(&inv).await.is_err());
        assert!(provider.pay_invoice_with_fee_limit(&inv, 0).await.is_err());
    }
    assert!(matches!(
        provider.pay_invoice_with_fee_limit(&invoice(None), 0).await,
        Err(LightningError::PaymentNotDispatched(_))
    ));
    assert!(money_calls(&server).is_empty());
    assert!(!server.calls().iter().any(|(p, _)| p == "/v1/listpays"));
}
#[tokio::test]
async fn t2_startup_requires_version_and_xpay_discovery() {
    for (version, help) in [
        (
            "v24.08",
            json!({"help":[{"command":"xpay invstring [maxfee]"}]}),
        ),
        ("v24.11", json!({"help":[{"command":"pay bolt11"}]})),
        ("v26.06", json!({"help":[{"command":"xpay-other"}]})),
    ] {
        let server = Server::new(200, info(version, "regtest")).await;
        server.route("help", help);
        let dir = tempfile::tempdir().unwrap();
        let err = ClnProvider::new(server.config(&dir)).await.unwrap_err();
        assert!(err.to_string().contains("not_supported"));
        assert!(money_calls(&server).is_empty());
    }
}
#[tokio::test]
async fn t2_existing_and_unverifiable_hashes_never_dispatch() {
    for (status, body) in [
        (200, json!({"pays":[{"status":"failed"}]}).to_string()),
        (200, json!({"pays":[{"status":"pending"}]}).to_string()),
        (200, json!({"pays":[{"status":"complete"}]}).to_string()),
        (403, "denied".into()),
        (500, "oops".into()),
        (200, "{}".into()),
    ] {
        let (server, _dir, provider) = setup("v24.11").await;
        server
            .routes
            .lock()
            .unwrap()
            .insert("/v1/listpays".into(), (status, body));
        assert!(matches!(
            provider
                .pay_invoice_with_fee_limit(&invoice(Some(1000)), 100)
                .await,
            Err(LightningError::PaymentNotDispatched(_))
        ));
        assert!(money_calls(&server).is_empty());
    }
}
#[tokio::test]
async fn t2_concurrent_same_hash_only_posts_once() {
    let (server, _dir, provider) = setup("v24.11").await;
    server.route("xpay", paid(1000, 0));
    let inv = invoice(Some(1000));
    let (a, b) = tokio::join!(provider.pay_invoice(&inv), provider.pay_invoice(&inv));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(
        a.err().or(b.err()),
        Some(LightningError::PaymentNotDispatched(_))
    ));
    assert_eq!(money_calls(&server).len(), 1);
}
#[tokio::test]
async fn t7_keysend_version_selection_and_exact_ceiling() {
    for (version, method) in [("v24.11", "keysend"), ("v26.06", "xkeysend")] {
        for cap in [0, 23, u64::MAX] {
            let (server, _dir, provider) = setup(version).await;
            let fee = cap.min(100);
            let mut reply = paid(1000, fee);
            if method == "keysend" {
                reply["payment_hash"] = json!(hash());
                reply["status"] = json!("complete");
                reply["created_at"] = json!(1700000000.25);
            }
            server.route(method, reply);
            let result = provider
                .keysend_with_fee_limit(PUBKEY, 1000, Some("memo"), cap)
                .await
                .unwrap();
            assert_eq!(result.payment_hash, hash());
            assert_eq!(result.status, PaymentStatus::Settled);
            assert_eq!(result.fee_msat, Some(fee));
            assert_eq!(result.memo.as_deref(), Some("memo"));
            assert_eq!(
                money_calls(&server),
                vec![(
                    format!("/v1/{method}"),
                    json!({"destination":PUBKEY,"amount_msat":1000,"maxfee":fee,"retry_for":60})
                )]
            );
        }
    }
}
#[tokio::test]
async fn keysend_missing_method_refuses_and_modern_node_can_fall_back() {
    for available in [false, true] {
        let server = Server::new(200, info("v26.06", "regtest")).await;
        let mut help = vec![json!({"command":"xpay invstring [maxfee]"})];
        if available {
            help.push(json!({"command":"keysend destination amount_msat [maxfee]"}));
        }
        server.route("help", json!({"help":help}));
        server.route("keysend", paid(1000, 0));
        let dir = tempfile::tempdir().unwrap();
        let provider = ClnProvider::new(server.config(&dir)).await.unwrap();
        let result = provider.keysend(PUBKEY, 1000, None).await;
        if available {
            assert!(result.is_ok());
            assert_eq!(money_calls(&server)[0].0, "/v1/keysend");
        } else {
            assert!(matches!(
                result,
                Err(LightningError::PaymentNotDispatched(_))
            ));
            assert!(money_calls(&server).is_empty());
        }
    }
}
#[tokio::test]
async fn t8_t9_post_errors_remain_ambiguous_and_never_retry_hash() {
    // Fee refusal/rune denial are modeled at the HTTP boundary, not proof of CLN enforcement.
    for (status, body) in [
        (500, "oops"),
        (403, "rune denied"),
        (400, "route too expensive"),
        (200, "bad json"),
    ] {
        let (server, _dir, provider) = setup("v24.11").await;
        server
            .routes
            .lock()
            .unwrap()
            .insert("/v1/xpay".into(), (status, body.into()));
        let inv = invoice(Some(1000));
        let err = provider.pay_invoice(&inv).await.unwrap_err();
        assert!(!matches!(err, LightningError::PaymentNotDispatched(_)));
        assert!(matches!(
            provider.pay_invoice(&inv).await,
            Err(LightningError::PaymentNotDispatched(_))
        ));
        assert_eq!(money_calls(&server).len(), 1);
    }
}
#[tokio::test]
async fn timeout_after_post_is_ambiguous_and_hash_stays_used() {
    let (server, _dir, provider) = setup("v24.11").await;
    server
        .routes
        .lock()
        .unwrap()
        .insert("/v1/xpay".into(), (0, String::new()));
    let inv = invoice(Some(1000));
    let err = provider.pay_invoice(&inv).await.unwrap_err();
    assert!(!matches!(err, LightningError::PaymentNotDispatched(_)));
    assert!(matches!(
        provider.pay_invoice(&inv).await,
        Err(LightningError::PaymentNotDispatched(_))
    ));
    assert_eq!(money_calls(&server).len(), 1);
}
#[tokio::test]
async fn cancellation_after_post_keeps_hash_reserved() {
    let (server, _dir, provider) = setup("v24.11").await;
    server
        .routes
        .lock()
        .unwrap()
        .insert("/v1/xpay".into(), (0, String::new()));
    let provider = Arc::new(provider);
    let task = tokio::spawn({
        let provider = provider.clone();
        async move { provider.pay_invoice(&invoice(Some(1000))).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while money_calls(&server).is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    let _ = task.await;
    assert!(matches!(
        provider.pay_invoice(&invoice(Some(1000))).await,
        Err(LightningError::PaymentNotDispatched(_))
    ));
    assert_eq!(money_calls(&server).len(), 1);
}
#[tokio::test]
async fn overspend_returns_settlement_but_permanently_disables_new_payments() {
    for method in ["xpay", "xkeysend", "keysend"] {
        let (server, _dir, provider) = setup(if method == "keysend" {
            "v24.11"
        } else {
            "v26.06"
        })
        .await;
        assert!(provider.is_payment_capable().await);
        server.route(method, paid(1000, 24));
        let result = if method == "xpay" {
            provider
                .pay_invoice_with_fee_limit(&invoice(Some(1000)), 23)
                .await
        } else {
            provider
                .keysend_with_fee_limit(PUBKEY, 1000, None, 23)
                .await
        };
        assert_eq!(result.unwrap().fee_msat, Some(24));
        assert!(!provider.is_payment_capable().await);
        assert!(!provider.money_ready().await);
        assert!(provider.is_available().await);
        assert!(matches!(
            provider.keysend(PUBKEY, 1000, None).await,
            Err(LightningError::PaymentNotDispatched(_))
        ));
        assert_eq!(money_calls(&server).len(), 1);
    }
}
#[tokio::test]
async fn sync_warnings_prevent_dispatch_and_readiness() {
    let (server, _dir, provider) = setup("v24.11").await;
    for warning in ["warning_bitcoind_sync", "warning_lightningd_sync"] {
        let mut response: Value = serde_json::from_str(&info("v24.11", "regtest")).unwrap();
        response[warning] = json!("syncing");
        server.route("getinfo", response);
        assert!(!provider.is_payment_capable().await);
        assert!(!provider.money_ready().await);
        assert!(matches!(
            provider.pay_invoice(&invoice(Some(1000))).await,
            Err(LightningError::PaymentNotDispatched(_))
        ));
        assert!(matches!(
            provider.keysend(PUBKEY, 1000, None).await,
            Err(LightningError::PaymentNotDispatched(_))
        ));
    }
    assert!(money_calls(&server).is_empty());
}

#[tokio::test]
async fn malformed_payment_replies_never_claim_settlement_or_allow_retry() {
    for field in [
        "payment_preimage",
        "payment_hash",
        "amount_msat",
        "amount_sent_msat",
        "status",
    ] {
        let (server, _dir, provider) = setup("v24.11").await;
        let mut reply = paid(1000, 0);
        reply[field] = match field {
            "payment_preimage" => json!(hex::encode([43; 32])),
            "payment_hash" => json!("ab".repeat(32)),
            "amount_msat" => json!(999),
            "amount_sent_msat" => json!(999),
            _ => json!("pending"),
        };
        server.route("xpay", reply);
        let inv = invoice(Some(1000));
        let err = provider.pay_invoice(&inv).await.unwrap_err();
        assert!(!matches!(err, LightningError::PaymentNotDispatched(_)));
        assert!(matches!(
            provider.pay_invoice(&inv).await,
            Err(LightningError::PaymentNotDispatched(_))
        ));
        assert_eq!(money_calls(&server).len(), 1);
    }
}
#[tokio::test]
async fn keysend_post_errors_never_trigger_fallback_or_safe_retry_classification() {
    for status in [0, 403, 500] {
        let (server, _dir, provider) = setup("v26.06").await;
        server
            .routes
            .lock()
            .unwrap()
            .insert("/v1/xkeysend".into(), (status, RUNE.into()));
        let err = provider.keysend(PUBKEY, 1000, None).await.unwrap_err();
        assert!(!matches!(err, LightningError::PaymentNotDispatched(_)));
        assert!(!err.to_string().contains(RUNE));
        assert_eq!(money_calls(&server).len(), 1);
        assert_eq!(money_calls(&server)[0].0, "/v1/xkeysend");
    }
}
#[tokio::test]
async fn invalid_keysend_input_never_posts() {
    let (server, _dir, provider) = setup("v26.06").await;
    for (destination, amount) in [("garbage", 1000), (PUBKEY, 0)] {
        assert!(matches!(
            provider.keysend(destination, amount, None).await,
            Err(LightningError::PaymentNotDispatched(_))
        ));
    }
    assert!(money_calls(&server).is_empty());
}
