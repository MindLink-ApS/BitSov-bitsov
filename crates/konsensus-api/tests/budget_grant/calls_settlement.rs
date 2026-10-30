use super::*;
use konsensus_core::payloads::call as rules;
use konsensus_storage::Storage;

// The invoice responder persists the callee binding before publishing its
// invoice. SQLx needs another worker while this synchronous callback waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bound_block_invoice_draws_once_across_delivery_and_operation_replay() {
    bound_invoice_accounting(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overpayment_rejection_never_redraws_and_releases_the_unused_hold_once() {
    bound_invoice_accounting(true).await;
}

async fn bound_invoice_accounting(overpayment: bool) {
    let (mut fx, token) = prepared().await;
    assert_eq!(send(&fx, &token, 400, 7000, 0).await.0, StatusCode::OK);
    answer(&fx).await;
    let peer = fx.peer;
    let caller = *fx.state.identity.node_id();
    let entry = fx.state.storage.call_get(&peer, CALL).await.unwrap().unwrap();
    let callee = Arc::new(EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[9; 32]));
    callee.call_put(&caller, CALL, &rules::CallEntry {
        side: rules::Side::Callee, ..entry
    }).await.unwrap();
    let invoice_store = callee.clone();
    let transport = Arc::new(ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            let bolt11 = create_test_bolt11(amount);
            let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
            futures::executor::block_on(async {
                let entry = invoice_store.call_get(&caller, CALL).await.unwrap().unwrap();
                rules::validate_block_invoice(&entry, 0, chrono::Utc::now().timestamp_millis() as u64).unwrap();
                invoice_store.record_call_block_invoice(&caller, CALL, 0,
                    &hex::decode(invoice.payment_hash().to_string()).unwrap().try_into().unwrap(),
                    entry.deadline_ms + rules::CALL_BLOCK_RESUME_MS).await.unwrap();
            });
            Some(konsensus_api::state::InvoiceResponseData {
                payment_hash: invoice.payment_hash().to_string(), recipient: peer, bolt11,
            })
        }));
    fx.state = Arc::new(AppState { transport: transport.clone(), ..(*fx.state).clone() });
    let operation_id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_operation(&fx, &token, 404, 7000, 0, CALL, &operation_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = konsensus_core::MessageId::from_hex(body["message_id"].as_str().unwrap()).unwrap();
    let envelope = fx.state.storage.get_message(&id).await.unwrap().unwrap();
    envelope.payment_proof.verify_preimage().unwrap();
    assert!(callee.has_call_block_invoice(&caller, CALL, 0, &envelope.payment_proof.payment_hash).await.unwrap());
    let purposes: Vec<_> = transport.raw_frames.lock().unwrap().iter().filter_map(|bytes| {
        match konsensus_message::wire::Frame::from_bytes(bytes).unwrap() {
            konsensus_message::wire::Frame::RequestInvoice { purpose, .. } => Some(purpose),
            _ => None,
        }
    }).collect();
    assert_eq!(purposes, vec![format!("konsensus:call_block:{CALL}:0")]);
    if overpayment {
        // The bound invoice was payable when issued, but delivery occurs after
        // the resume window. The node receive-loop tests cover the durable
        // audit and emit this terminal rejection for exactly this refusal.
        let mut entry = callee.call_get(&caller, CALL).await.unwrap().unwrap();
        entry.deadline_ms = chrono::Utc::now().timestamp_millis() as u64 - rules::CALL_BLOCK_RESUME_MS - 1;
        callee.call_put(&caller, CALL, &entry).await.unwrap();
    }
    let plaintext = json!({"v": 1, "call_id": CALL, "seq": 0}).to_string();
    let incoming = konsensus_api::calls::prepare_incoming_block(callee.as_ref(), &caller,
        Some(&plaintext), &envelope.payment_proof.payment_hash).await.unwrap();
    assert_eq!(incoming.refusal().is_some(), overpayment);
    if overpayment {
        drop(incoming);
        assert!(fx.state.storage.reject_pending(&id, &peer, &caller, "call_block_overpayment", true).await.unwrap());
        let entry = fx.state.storage.call_get(&peer, CALL).await.unwrap();
        konsensus_api::calls::receive_block_grant(fx.state.storage.as_ref(),
            &konsensus_crypto::PlaintextCacheCipher::new(&[7; 32]), &caller, &peer, &id,
            chrono::Utc::now().timestamp_millis() as u64 + 60_000).await.unwrap();
        assert_eq!(fx.state.storage.call_get(&peer, CALL).await.unwrap(), entry);
    } else {
        incoming.commit(&envelope.id).await.unwrap();
        assert!(konsensus_api::calls::call_media_admitted(callee.as_ref(), &caller, CALL,
            chrono::Utc::now().timestamp_millis() as u64).await);
    }
    for _ in 0..2 {
        let (status, replay) = send_operation(&fx, &token, 404, 7000, 0, CALL, &operation_id).await;
        if overpayment { assert_eq!(replay["state"], "failed_paid", "{replay}"); }
        else { assert_eq!(status, StatusCode::OK, "{replay}"); }
        assert_ne!(send(&fx, &token, 404, 7000, 0).await.0, StatusCode::OK);
        konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
        let hold = fx.service.call_spend_status(&peer.to_hex(), CALL).unwrap();
        assert_eq!((hold.spent_msat, hold.remaining_msat, hold.released_msat), (7000, 413_000, 0));
        assert_eq!((fx.wallet.money(), fx.wallet.left(), fx.used()), (2, 8000, 421_000));
    }
    if !overpayment {
        assert!(fx.state.storage.acknowledge_pending(&id, &peer, &caller).await.unwrap());
    }
    let deadline = fx.state.storage.call_get(&peer, CALL).await.unwrap().unwrap().deadline_ms;
    // Expiry plus repeated reconciliation must release the unused reservation,
    // while retaining the settled principal even for an audited overpayment.
    for _ in 0..2 {
        konsensus_api::calls::expire_calls(fx.state.storage.as_ref(), deadline + 1).await.unwrap();
        konsensus_api::calls::reconcile_call_spend(&fx.state, deadline + 1).await.unwrap();
    }
    let hold = fx.service.call_spend_status(&peer.to_hex(), CALL).unwrap();
    assert!(hold.closed);
    assert_eq!((hold.spent_msat, hold.remaining_msat, hold.released_msat), (7000, 0, 413_000));
    assert_eq!((fx.wallet.money(), fx.wallet.left(), fx.used()), (2, 8000, 8000));
    let budget = fx.service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert!(budget.pending.is_empty());
    assert!(budget.operation_links.is_empty());
}

#[tokio::test]
async fn delayed_paid_block_grant_reopens_call_with_its_original_hold() {
    for (age, variant) in [
        (1000, "sent"),
        (rules::CALL_BLOCK_RESUME_MS + 1000, "sent"),
        (1000, "legacy"),
        (1000, "queued"),
        (1000, "settled"),
    ] {
        let (mut fx, token) = prepared().await;
        fx.state = Arc::new(AppState {
            plaintext_cipher: Some(Arc::new(konsensus_crypto::PlaintextCacheCipher::new(
                &[7; 32],
            ))),
            ..(*fx.state).clone()
        });
        assert_eq!(send(&fx, &token, 400, 7000, 0).await.0, StatusCode::OK);
        answer(&fx).await;
        let (status, body) = send(&fx, &token, 404, 7000, 0).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let id = konsensus_core::MessageId::from_hex(body["message_id"].as_str().unwrap()).unwrap();
        if variant == "legacy" {
            // Rows written before the restack recover the binding from cache.
            let mut op = fx
                .state
                .storage
                .get_outbox_operation_by_message(&id)
                .await
                .unwrap()
                .unwrap();
            let mut recovery: Value = serde_json::from_slice(&op.recovery).unwrap();
            recovery.as_object_mut().unwrap().remove("call_block");
            op.recovery = serde_json::to_vec(&recovery).unwrap();
            fx.state.storage.update_outbox_operation(&op).await.unwrap();
        }
        if variant == "queued" {
            // Crash after materialization, before the first delivery attempt.
            fx.state
                .storage
                .remove_pending_delivery(&id, &fx.peer)
                .await
                .unwrap();
            fx.state
                .storage
                .queue_pending_delivery(&id, &fx.peer)
                .await
                .unwrap();
            assert!(!fx
                .state
                .storage
                .is_pending_dispatched(&id, &fx.peer, fx.state.identity.node_id())
                .await
                .unwrap());
        }
        if variant == "settled" {
            // Crash after call commit, before settled_envelope materializes the queue.
            fx.state
                .storage
                .remove_pending_delivery(&id, &fx.peer)
                .await
                .unwrap();
            let mut op = fx
                .state
                .storage
                .get_outbox_operation_by_message(&id)
                .await
                .unwrap()
                .unwrap();
            // Materialization writes message and queue atomically; neither
            // exists at this crash point, while the journal draft survives.
            fx.state.storage.delete_message(&id).await.unwrap();
            op.state = "paying".into();
            // The encrypted draft already assigned its stable message id.
            op.settled_msat = 0;
            let mut recovery: Value = serde_json::from_slice(&op.recovery).unwrap();
            recovery["envelope_ready"] = json!(false);
            op.recovery = serde_json::to_vec(&recovery).unwrap();
            fx.state.storage.update_outbox_operation(&op).await.unwrap();
        }
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut entry = fx
            .state
            .storage
            .call_get(&fx.peer, CALL)
            .await
            .unwrap()
            .unwrap();
        assert!(
            entry.pending.is_none(),
            "settled locally, awaiting callee delivery/grant"
        );
        entry.deadline_ms = now - age;
        entry.paid_until_ms = Some(now - rules::CALL_BLOCK_GRACE_MS - age);
        fx.state
            .storage
            .call_put(&fx.peer, CALL, &entry)
            .await
            .unwrap();
        if matches!(variant, "sent" | "legacy") {
            fx.state
                .storage
                .mark_pending_sent(&id, &fx.peer)
                .await
                .unwrap();
        }
        konsensus_api::calls::maintain_calls(&fx.state, now)
            .await
            .unwrap();
        if variant == "settled" {
            konsensus_api::handlers::messages::reconcile_operations(&fx.state)
                .await
                .unwrap();
        }
        fx.state
            .storage
            .mark_pending_sent(&id, &fx.peer)
            .await
            .unwrap_or_else(|error| panic!("{variant}: {error}"));
        // Even the 61-second-old local expiry can receive an honest delayed
        // grant with 19 seconds left: the callee's original block-zero
        // deadline + resume window + block. Use 10 seconds, not a fresh full
        // minute that would exceed N1b's grant ceiling in that case.
        for _ in 0..2 {
            konsensus_api::calls::receive_block_grant(
                fx.state.storage.as_ref(),
                &konsensus_crypto::PlaintextCacheCipher::new(&[7; 32]),
                fx.state.identity.node_id(),
                &fx.peer,
                &id,
                now + 10_000,
            )
            .await
            .unwrap();
            konsensus_api::calls::maintain_calls(&fx.state, now)
                .await
                .unwrap();
        }
        let entry = fx
            .state
            .storage
            .call_get(&fx.peer, CALL)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((entry.phase, entry.next_block_seq), (Phase::Live, 1));
        let hold = fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .unwrap();
        assert!(
            !hold.closed,
            "a delayed paid grant must not reopen a call with a closed hold"
        );
        assert_eq!(
            (hold.spent_msat, hold.remaining_msat, hold.released_msat),
            (7000, 413_000, 0)
        );
        assert_eq!((fx.wallet.money(), fx.used()), (2, 421_000));
        let next = rules::CallEntry {
            paid_until_ms: Some(now + 10_000),
            deadline_ms: now + 20_000,
            ..entry
        };
        fx.state
            .storage
            .call_put(&fx.peer, CALL, &next)
            .await
            .unwrap();
        assert_eq!(send(&fx, &token, 404, 7000, 1).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn delayed_grant_hold_releases_after_receipt_rejection_or_bounded_tail() {
    for outcome in ["receipt", "rejection", "expiry"] {
        let (fx, token) = prepared().await;
        assert_eq!(send(&fx, &token, 400, 7000, 0).await.0, StatusCode::OK);
        answer(&fx).await;
        let (status, body) = send(&fx, &token, 404, 7000, 0).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let id = konsensus_core::MessageId::from_hex(body["message_id"].as_str().unwrap()).unwrap();
        fx.state
            .storage
            .mark_pending_sent(&id, &fx.peer)
            .await
            .unwrap();
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut entry = fx
            .state
            .storage
            .call_get(&fx.peer, CALL)
            .await
            .unwrap()
            .unwrap();
        let age = if outcome == "expiry" {
            rules::CALL_BLOCK_RESUME_MS + rules::CALL_BLOCK_MS + rules::CALL_BLOCK_GRACE_MS + 1
        } else {
            1000
        };
        entry.deadline_ms = now - age;
        entry.paid_until_ms = Some(now - age - rules::CALL_BLOCK_GRACE_MS);
        fx.state
            .storage
            .call_put(&fx.peer, CALL, &entry)
            .await
            .unwrap();
        if outcome == "receipt" {
            fx.state
                .storage
                .remove_pending_delivery(&id, &fx.peer)
                .await
                .unwrap();
        } else if outcome == "rejection" {
            // A terminal rejection must release even if queue cleanup was interrupted.
            let mut op = fx
                .state
                .storage
                .get_outbox_operation_by_message(&id)
                .await
                .unwrap()
                .unwrap();
            op.state = "failed_paid".into();
            fx.state.storage.update_outbox_operation(&op).await.unwrap();
        }
        for _ in 0..2 {
            konsensus_api::calls::maintain_calls(&fx.state, now)
                .await
                .unwrap();
        }
        let hold = fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .unwrap();
        assert!(hold.closed, "{outcome}");
        assert_eq!(
            (hold.spent_msat, hold.remaining_msat, hold.released_msat),
            (7000, 0, 413_000)
        );
        assert_eq!((fx.wallet.money(), fx.used()), (2, 8000));
    }
}

#[tokio::test]
async fn late_settlement_within_resume_window_draws_once_and_keeps_hold_usable() {
    late_settlement(true).await;
}

#[tokio::test]
async fn late_settlement_outside_resume_window_draws_once_and_releases_unused_hold() {
    late_settlement(false).await;
}

async fn late_settlement(resume: bool) {
    let (mut fx, token) = prepared().await;
    assert_eq!(send(&fx, &token, 400, 7000, 0).await.0, StatusCode::OK);
    answer(&fx).await;
    let peer = fx.peer;
    let transport = ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            let bolt11 = create_test_bolt11(amount);
            let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
            Some(konsensus_api::state::InvoiceResponseData {
                payment_hash: invoice.payment_hash().to_string(),
                recipient: peer,
                bolt11,
            })
        });
    fx.state.peer_ln_pubkeys.lock().await.remove(&peer);
    fx.state = Arc::new(AppState {
        transport: Arc::new(transport),
        ..(*fx.state).clone()
    });
    fx.wallet.set(UNKNOWN);
    let operation_id = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_operation(&fx, &token, 404, 7000, 0, CALL, &operation_id).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "payment_unknown");
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let mut entry = fx
        .state
        .storage
        .call_get(&peer, CALL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.pending.as_ref().unwrap().kind, 404);
    // Advance expiry while a dispatched payment awaits reconciliation.
    entry.deadline_ms = now
        - if resume {
            1000
        } else {
            rules::CALL_BLOCK_RESUME_MS + 1000
        };
    fx.state
        .storage
        .call_put(&peer, CALL, &entry)
        .await
        .unwrap();
    konsensus_api::calls::maintain_calls(&fx.state, now)
        .await
        .unwrap();
    let ended = fx
        .state
        .storage
        .call_get(&peer, CALL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (ended.phase, ended.end_reason),
        (Phase::Ended, Some(HangupReason::Unpaid))
    );
    let held = fx.service.call_spend_status(&peer.to_hex(), CALL).unwrap();
    assert_eq!(
        held.closed, !resume,
        "a resumable pending block must retain the unused hold"
    );
    assert_eq!(held.remaining_msat, if resume { 420_000 } else { 7000 });
    fx.wallet.set(SETTLE);
    fx.wallet.recover_preimage.store(true, Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&fx.state)
        .await
        .unwrap();
    for _ in 0..2 {
        // Retry delivery and both recovery sweeps: none may fund another draw.
        let (status, replay) = send_operation(&fx, &token, 404, 7000, 0, CALL, &operation_id).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        konsensus_api::handlers::messages::reconcile_operations(&fx.state)
            .await
            .unwrap();
        konsensus_api::calls::maintain_calls(
            &fx.state,
            chrono::Utc::now().timestamp_millis() as u64,
        )
        .await
        .unwrap();
    }
    let entry = fx
        .state
        .storage
        .call_get(&fx.peer, CALL)
        .await
        .unwrap()
        .unwrap();
    let hold = fx
        .service
        .call_spend_status(&fx.peer.to_hex(), CALL)
        .unwrap();
    assert_eq!(hold.spent_msat, 7000);
    assert_eq!((fx.wallet.money(), fx.wallet.left()), (2, 8000));
    if resume {
        assert_eq!((entry.phase, entry.next_block_seq), (Phase::Live, 1));
        assert!(!hold.closed);
        assert_eq!(
            (hold.remaining_msat, hold.released_msat, fx.used()),
            (413_000, 0, 421_000)
        );
        // The reopened call can fund the next sequence from the original hold.
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let next = rules::CallEntry {
            paid_until_ms: Some(now + 10_000),
            deadline_ms: now + 20_000,
            ..entry
        };
        fx.state
            .storage
            .call_put(&fx.peer, CALL, &next)
            .await
            .unwrap();
        fx.state
            .peer_ln_pubkeys
            .lock()
            .await
            .insert(peer, invoice_payee());
        assert_eq!(send(&fx, &token, 404, 7000, 1).await.0, StatusCode::OK);
        assert_eq!(
            fx.service
                .call_spend_status(&fx.peer.to_hex(), CALL)
                .unwrap()
                .spent_msat,
            14_000
        );
    } else {
        assert_eq!(entry.phase, Phase::Ended);
        assert!(hold.closed);
        assert_eq!(
            (hold.remaining_msat, hold.released_msat, fx.used()),
            (0, 413_000, 8000)
        );
        assert!(fx.service.reload_from_disk().unwrap().grants[0]
            .budget
            .as_ref()
            .unwrap()
            .pending
            .is_empty());
        // The paid envelope remains journaled for delivery and callee-side
        // overpayment auditing even though it cannot reopen the caller.
        let op = fx
            .state
            .storage
            .get_outbox_operation(&operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(op.settled_msat, 7000);
        assert!(op.payment_hash.is_some());
    }
}

#[tokio::test]
async fn invoice_refused_near_deadline_returns_the_draw_without_spending() {
    let (mut fx, token) = prepared().await;
    assert_eq!(send(&fx, &token, 400, 7000, 0).await.0, StatusCode::OK);
    answer(&fx).await;
    let peer = fx.peer;
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let mut caller = fx
        .state
        .storage
        .call_get(&peer, CALL)
        .await
        .unwrap()
        .unwrap();
    caller.deadline_ms = now + 10_000;
    fx.state
        .storage
        .call_put(&peer, CALL, &caller)
        .await
        .unwrap();
    let callee = rules::CallEntry {
        side: rules::Side::Callee,
        ..caller
    };
    let requests = fx.state.invoice_requests.clone();
    let transport = Arc::new(
        ConnectedStubTransport::new(vec![peer], requests.clone()).with_invoice_responder(
            move |id, _| {
                assert!(rules::validate_block_invoice(
                    &callee,
                    0,
                    chrono::Utc::now().timestamp_millis() as u64
                )
                .is_err());
                let requests = requests.clone();
                tokio::spawn(async move {
                    if let Some(tx) = requests.lock().await.remove(&id) {
                        let _ = tx.send(Err(konsensus_api::state::InvoiceResponseError {
                            recipient: peer,
                            reason: konsensus_api::invoice_refusal::CALL_BLOCK_UNPAYABLE.into(),
                        }));
                    }
                });
                None
            },
        ),
    );
    fx.state.peer_ln_pubkeys.lock().await.remove(&peer);
    fx.state = Arc::new(AppState {
        transport: transport.clone(),
        ..(*fx.state).clone()
    });
    let (status, body) = send(&fx, &token, 404, 7000, 0).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "call_block_unpayable", "{body}");
    assert_eq!(
        (fx.wallet.money(), fx.wallet.left(), fx.used()),
        (1, 1000, 421_000)
    );
    let hold = fx.service.call_spend_status(&peer.to_hex(), CALL).unwrap();
    assert_eq!(
        (hold.spent_msat, hold.remaining_msat, hold.closed),
        (0, 420_000, false)
    );
    let budget = fx.service.reload_from_disk().unwrap().grants[0]
        .budget
        .clone()
        .unwrap();
    assert_eq!(budget.pending.len(), 1, "only the parent hold remains");
    assert!(budget.operation_links.is_empty());
    assert!(transport.sent_envelopes.lock().unwrap().is_empty());
    assert!(transport
        .raw_frames
        .lock()
        .unwrap()
        .iter()
        .any(|frame| matches!(
            konsensus_message::wire::Frame::from_bytes(frame),
            Ok(konsensus_message::wire::Frame::RequestInvoice { .. })
        )));
}
