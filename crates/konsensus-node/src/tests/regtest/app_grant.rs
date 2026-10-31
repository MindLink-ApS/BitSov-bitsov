//! Paid messaging and calls with ordinary, signed app spend approvals.
use super::*;
use axum::http::StatusCode;
use konsensus_api::pairing::device;
use konsensus_core::payloads::call::Phase;
use konsensus_core::{NodeId, OwnerApprovalKey};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

const BUDGET: u64 = 500_000;
const PRICE: u64 = 10_000;
const CALL: &str = "112233445566778899aabbccddeeff00";

/// Enroll a separate approver, then approve the app's exact grant request.
/// The paying pairing never receives an owner device key or console elevation.
async fn approve(app: &mut app::App, root: &OwnerApprovalKey, requested_max: u64) {
    let service = &app.service;
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let owner = service
        .create_ticket_remote_pairing(
            "regtest approver",
            &hex::encode(owner_key.verifying_key().to_bytes()),
            &[9; 32],
        )
        .unwrap();
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let proof = key
        .sign(
            &rng,
            device::registration_message(&service.bound_fingerprint(), &owner.client_id, &public)
                .as_bytes(),
        )
        .unwrap();
    let registration = service
        .request_device_key(
            &owner.client_id,
            &public,
            "regtest approver",
            &hex::encode(proof),
        )
        .unwrap();
    let console = std::fs::read_to_string(
        service
            .dir()
            .join(format!("owner-approval-{}", registration.op_id)),
    )
    .unwrap();
    let confirmation = console
        .lines()
        .find(|line| line.contains(" CODE "))
        .unwrap();
    let signature = root.sign(
        device::owner_approval_message(
            &service.bound_fingerprint(),
            &owner.client_pubkey,
            owner.epoch,
            &public,
        )
        .as_bytes(),
    );
    let device = service
        .approve_device_key(
            &registration.op_id,
            confirmation,
            &hex::encode(signature.to_bytes()),
        )
        .unwrap();

    let (status, pending) = app
        .post(
            "/api/v1/pair/approval-request",
            json!({"kind":"spend_grant", "terms": {
                "budget_msat": BUDGET, "per_call_max_msat": requested_max,
                "window_secs": 3600, "recipient": null,
            }}),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "grant request: {pending}");
    assert!(service.grant_view_for(&app.client).is_none());
    let cap = requested_max.min(6_000);
    assert_eq!(pending["request"]["terms"]["per_call_max_msat"], cap);
    let signature = key
        .sign(
            &rng,
            pending["approval_message"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
    service
        .approve_owner_request(
            &owner.client_id,
            owner.epoch,
            pending["op_id"].as_str().unwrap(),
            &device.key_id,
            &hex::encode(signature),
        )
        .unwrap();
    // Read the stored terms, not just the effective cap reported by the view.
    let stored = service.reload_from_disk().unwrap();
    let grant = stored
        .grants
        .iter()
        .find(|g| g.client_id == app.client)
        .unwrap();
    assert!(grant.owner_approval.is_some());
    assert_eq!(grant.granted_by, format!("device:{}", device.key_id));
    let budget = grant.budget.as_ref().unwrap();
    assert_eq!(budget.budget_msat, BUDGET);
    assert_eq!(budget.per_call_max_msat, cap);
    assert!(service.device_keys_for(&app.client).is_empty());
    assert_eq!(
        app.refresh_token().await,
        json!(["read", "receive", "spend"])
    );
    let (status, view) = app.get("/api/v1/pair/grant", false).await;
    assert_eq!(status, StatusCode::OK, "grant view: {view}");
    assert_eq!(view["grant"]["budget_msat"], BUDGET);
    assert_eq!(view["grant"]["per_call_max_msat"], cap);
    assert_eq!(view["grant"]["used_msat"], 0);
}

async fn pair(minutes: u16, caller_max: u64) -> paid_call::Pair {
    let roots = [(); 2].map(|_| {
        let mut seed = [0; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        OwnerApprovalKey::from_seed(&seed, &[9; 32]).unwrap()
    });
    let calls = |block_msat| app::CallOptions {
        block_msat,
        max_minutes: minutes,
        offer_msat: PRICE,
        chat_msat: 1_000,
    };
    let mut pair = paid_call::Pair::start(
        calls(7_000),
        calls(PRICE),
        roots.each_ref().map(|root| Some(root.verifying_key())),
        // Keep the production fee policy: direct-channel detection must remove
        // its usual 5,000 msat allowance without an explicit zero-fee request.
        Default::default(),
    )
    .await;
    approve(&mut pair.caller, &roots[0], caller_max).await;
    approve(&mut pair.callee, &roots[1], BUDGET).await;
    pair
}

async fn signal(app: &app::App, peer: &NodeId, kind: u16, body: Value) -> (StatusCode, Value) {
    let amount = if matches!(kind, 400 | 404) {
        PRICE
    } else {
        1_000
    };
    let mut request = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(),
        "recipient": peer.to_hex(), "kind":kind, "plaintext":body.to_string(),
        "max_total_msat":amount,
    });
    if kind == 400 {
        request["max_block_msat"] = json!(PRICE);
        request["max_hold_msat"] = json!(u64::from(app.state.max_call_minutes) * PRICE);
    }
    app.post("/api/v1/messages/compose", request, false).await
}

fn offer() -> Value {
    json!({"v":1, "call_id":CALL, "media":"audio", "sdp":paid_call::SDP})
}

/// Independent settled ledger and channel snapshots, excluding setup liquidity.
struct Books {
    capacity: [u64; 2],
    used: [u64; 2],
    payments: [usize; 2],
}

impl Books {
    async fn snapshot(pair: &paid_call::Pair) -> Self {
        Self {
            capacity: [capacity(pair.a.node()), capacity(pair.b.node())],
            used: [pair.caller.used(), pair.callee.used()],
            payments: [
                pair.a.list_payments(100).await.unwrap().len(),
                pair.b.list_payments(100).await.unwrap().len(),
            ],
        }
    }

    async fn reconcile(&self, pair: &paid_call::Pair, sent_a: &[u64], sent_b: &[u64]) {
        let totals = [sent_a.iter().sum::<u64>(), sent_b.iter().sum::<u64>()];
        let expected = [
            self.capacity[0] - totals[0] + totals[1],
            self.capacity[1] - totals[1] + totals[0],
        ];
        wait("exact app-grant channel deltas", || async {
            [capacity(pair.a.node()), capacity(pair.b.node())] == expected
        })
        .await;
        for (index, (wallet, app, sent, received)) in [
            (&pair.a, &pair.caller, sent_a, sent_b),
            (&pair.b, &pair.callee, sent_b, sent_a),
        ]
        .into_iter()
        .enumerate()
        {
            let payments = wallet.list_payments(100).await.unwrap();
            assert_eq!(
                payments.len(),
                self.payments[index] + sent.len() + received.len()
            );
            let (status, grant) = app.get("/api/v1/pair/grant", false).await;
            assert_eq!(status, StatusCode::OK, "{grant}");
            assert_eq!(
                grant["grant"]["used_msat"],
                self.used[index] + totals[index]
            );
            assert_eq!(app.used(), self.used[index] + totals[index]);
        }
    }

    async fn unchanged(&self, pair: &paid_call::Pair) {
        self.reconcile(pair, &[], &[]).await;
        for (app, peer) in [(&pair.caller, &pair.callee), (&pair.callee, &pair.caller)] {
            assert!(app
                .service
                .call_spend_status(&peer.state.identity.node_id().to_hex(), CALL)
                .is_none());
            for grant in app.service.reload_from_disk().unwrap().grants {
                if let Some(budget) = grant.budget {
                    assert!(budget.pending.is_empty(), "refusal left a pending debit");
                    assert!(
                        budget.call_reservations.is_empty(),
                        "refusal left a call hold"
                    );
                }
            }
        }
    }
}

async fn receipt(pair: &paid_call::Pair, body: &Value, amount: u64, from_a: bool) {
    assert_eq!(body["delivered"], true, "{body}");
    assert_eq!(body["amount_msat"], amount, "{body}");
    let hash = body["payment_hash"].as_str().unwrap();
    for (wallet, outgoing) in [(&pair.a, from_a), (&pair.b, !from_a)] {
        settle(wallet, hash).await;
        let payment = wallet.get_payment_status(hash).await.unwrap();
        assert_eq!(payment.amount_msat, amount);
        assert_eq!(
            payment.direction,
            if outgoing {
                PaymentDirection::Outgoing
            } else {
                PaymentDirection::Incoming
            }
        );
        if outgoing {
            assert_eq!(payment.fee_msat, Some(0), "direct-channel payment");
        }
    }
}

async fn stop(pair: paid_call::Pair) {
    // Keep the chain and directories alive through handler and wallet shutdown.
    pair.caller.stop().await;
    pair.callee.stop().await;
    pair.a.shutdown().await.unwrap();
    pair.b.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_app_grant_e2e.sh"]
async fn paid_message_and_reply() {
    let mut pair = pair(3, BUDGET).await;
    let before = Books::snapshot(&pair).await;
    // Both owners listed their peer during setup, so no admission is owed.
    let message = pair
        .caller
        .compose(&mut pair.callee, "app grant message")
        .await;
    receipt(&pair, &message, 1_000, true).await;
    let reply = pair
        .callee
        .compose(&mut pair.caller, "app grant reply")
        .await;
    receipt(&pair, &reply, 1_000, false).await;
    before.reconcile(&pair, &[1_000], &[1_000]).await;
    println!("APP GRANT PASS message_reply amount_msat=1000 routing_fee_msat=0");
    stop(pair).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_app_grant_e2e.sh"]
async fn paid_call_and_unused_hold_release() {
    let mut pair = pair(3, BUDGET).await;
    let before = Books::snapshot(&pair).await;
    let aid = *pair.caller.state.identity.node_id();
    let bid = *pair.callee.state.identity.node_id();
    let (status, body) = signal(&pair.caller, &bid, 400, offer()).await;
    assert_eq!(status, StatusCode::OK, "offer: {body}");
    receipt(&pair, &body, 10_000, true).await;
    recv_kind(&mut pair.callee, &aid, 400).await;
    let hold = pair
        .caller
        .service
        .call_spend_status(&bid.to_hex(), CALL)
        .unwrap();
    assert_eq!(hold.reserved_msat, 30_000);
    assert_eq!(hold.remaining_msat, 30_000);
    assert_eq!(hold.spent_msat, 0);
    assert_eq!(hold.per_block_msat, 10_000);
    assert_eq!(hold.per_block_fee_msat, 0);
    assert_eq!(hold.max_call_minutes, 3);
    assert!(!hold.closed);
    assert_eq!(pair.caller.used(), before.used[0] + 40_000);
    let (status, body) = signal(
        &pair.callee,
        &aid,
        401,
        json!({"v":1, "call_id":CALL, "sdp":paid_call::SDP}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "answer: {body}");
    receipt(&pair, &body, 1_000, false).await;
    recv_kind(&mut pair.caller, &bid, 401).await;
    let mut hashes = std::collections::BTreeSet::new();
    let mut anchors = [0; 2];
    for ((app, peer), anchor) in [(&pair.caller, &bid), (&pair.callee, &aid)]
        .into_iter()
        .zip(&mut anchors)
    {
        let entry = app
            .state
            .storage
            .call_get(peer, CALL)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.phase, Phase::Live);
        assert_eq!(entry.paid_until_ms, None, "answer alone buys no block");
        *anchor = entry.deadline_ms - 30_000;
    }
    for seq in 0..2 {
        if seq > 0 {
            let due = pair
                .caller
                .state
                .storage
                .call_get(&bid, CALL)
                .await
                .unwrap()
                .unwrap()
                .next_block_due_ms()
                .unwrap();
            tokio::time::sleep(Duration::from_millis(
                due.saturating_sub(paid_call::now_ms()) + 20,
            ))
            .await;
        }
        let (status, body) =
            signal(&pair.caller, &bid, 404, json!({"call_id":CALL, "seq":seq})).await;
        assert_eq!(status, StatusCode::OK, "block {seq}: {body}");
        receipt(&pair, &body, 10_000, true).await;
        let received = recv_kind(&mut pair.callee, &aid, 404).await;
        assert_eq!(
            hex::encode(received.envelope.payment_proof.payment_hash),
            body["payment_hash"]
        );
        assert!(hashes.insert(body["payment_hash"].as_str().unwrap().to_owned()));
        for ((app, peer), anchor) in [(&pair.caller, &bid), (&pair.callee, &aid)]
            .into_iter()
            .zip(anchors)
        {
            let entry = app
                .state
                .storage
                .call_get(peer, CALL)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(entry.phase, Phase::Live);
            assert_eq!(entry.next_block_seq, seq + 1);
            assert_eq!(
                entry.paid_until_ms,
                Some(anchor + u64::from(seq + 1) * 60_000)
            );
        }
        let hold = pair
            .caller
            .service
            .call_spend_status(&bid.to_hex(), CALL)
            .unwrap();
        assert_eq!(hold.spent_msat, u64::from(seq + 1) * 10_000);
        assert_eq!(hold.remaining_msat, 30_000 - hold.spent_msat);
        assert_eq!(hold.released_msat, 0);
        assert_eq!(pair.caller.used(), before.used[0] + 40_000);
    }
    let (status, body) = signal(
        &pair.caller,
        &bid,
        403,
        json!({"v":1, "call_id":CALL, "reason":"hangup"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "hangup: {body}");
    receipt(&pair, &body, 1_000, true).await;
    let hangup = recv_kind(&mut pair.callee, &aid, 403).await;
    let hangup: Value = serde_json::from_str(hangup.plaintext.as_deref().unwrap()).unwrap();
    assert_eq!(hangup["reason"], "hangup");
    wait("app call hold released", || async {
        pair.caller
            .service
            .call_spend_status(&bid.to_hex(), CALL)
            .unwrap()
            .closed
    })
    .await;
    let hold = pair
        .caller
        .service
        .call_spend_status(&bid.to_hex(), CALL)
        .unwrap();
    assert_eq!(hold.spent_msat, 20_000);
    assert_eq!(hold.remaining_msat, 0);
    assert_eq!(hold.released_msat, 10_000);
    for (app, peer) in [(&pair.caller, &bid), (&pair.callee, &aid)] {
        let entry = app
            .state
            .storage
            .call_get(peer, CALL)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.phase, Phase::Ended);
    }
    before
        .reconcile(&pair, &[10_000, 10_000, 10_000, 1_000], &[1_000])
        .await;
    println!("APP GRANT PASS paid_call paid_blocks=2 block_seconds=60 spent_msat=31000 released_msat=10000 routing_fee_msat=0");
    stop(pair).await;
}

async fn refused(minutes: u16, cap: u64, reason: &str) {
    let pair = pair(minutes, cap).await;
    let before = Books::snapshot(&pair).await;
    let bid = pair.callee.state.identity.node_id();
    let (status, body) = signal(&pair.caller, bid, 400, offer()).await;
    assert_eq!(status, StatusCode::CONFLICT, "offer refusal: {body}");
    assert_eq!(body["code"], "budget_exceeded");
    assert_eq!(body["reason"], reason);
    if reason == "total" {
        assert_eq!(body["remaining_msat"], 500_000);
    }
    before.unchanged(&pair).await;
    println!("APP GRANT PASS refusal_{reason} paid_msat=0 open_holds=0");
    stop(pair).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_app_grant_e2e.sh"]
async fn sixty_minute_hold_exceeds_total_budget() {
    refused(60, BUDGET, "total").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_app_grant_e2e.sh"]
async fn tighter_owner_limit_refuses_call() {
    refused(3, 1_000, "per_call").await;
}
