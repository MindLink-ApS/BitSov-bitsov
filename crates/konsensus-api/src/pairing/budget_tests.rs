use super::*;

// A call reserves 240 minutes plus a per-block fee ceiling, once. Splitting
// that hold into journaled payments must never charge the grant a second time.
#[test]
fn call_reservation_draw_release_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let peer = "aa".repeat(32);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, "call", 20, 5, 240).unwrap();
    let hold = service.reserve_call_spend(&client, 1, terms.clone(), 10_000).unwrap();
    assert_eq!(service.reserve_call_spend(&client, 1, terms, 10_000).unwrap(), hold);
    let link = crate::spend_budget::OperationReservationLink {
        operation_id: "block-0".into(), execution_id: "attempt".into(), readmission: false,
    };
    let debit = service.draw_call_spend(&client, 1, &peer, "call", 0, 20, 5, link).unwrap();
    service.try_resolve_spend(&debit, &peer, 22).unwrap();
    service.try_resolve_spend(&debit, &peer, 22).unwrap();
    drop(service);
    let service = PairingService::open(dir.path(), "identity".into(), true).unwrap();
    let view = service.call_spend_status(&peer, "call").unwrap();
    assert_eq!((view.reserved_msat, view.spent_msat, view.remaining_msat, view.per_block_msat), (6000, 22, 5978, 20));
    service.close_call_spend(&hold).unwrap();
    service.close_call_spend(&hold).unwrap();
    let budget = service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert_eq!(budget.used_msat, 22);
    assert!(budget.pending.is_empty());
    assert_eq!(budget.breaker_status(chrono::Utc::now().timestamp()).payments_last_hour, 1);
}

#[test]
fn call_reservation_caps_liquidity_price_and_unknown_payment() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let peer = "aa".repeat(32);
    let terms = |price| crate::spend_budget::CallSpendTerms::new(&peer, "call", price, 5, 240).unwrap();
    assert!(service.reserve_call_spend(&client, 1, terms(50), 20_000).is_err());
    assert!(service.reserve_call_spend(&client, 1, terms(20), 5999).is_err());
    let hold = service.reserve_call_spend(&client, 1, terms(20), 6000).unwrap();
    let link = crate::spend_budget::OperationReservationLink {
        operation_id: "block-0".into(), execution_id: "attempt".into(), readmission: false,
    };
    assert!(service.draw_call_spend(&client, 1, &peer, "call", 0, 21, 5, link.clone()).is_err());
    let debit = service.draw_call_spend(&client, 1, &peer, "call", 0, 20, 5, link.clone()).unwrap();
    assert!(service.draw_call_spend(&client, 1, &peer, "call", 0, 20, 5, link).is_err());
    service.close_call_spend(&hold).unwrap();
    assert_eq!(service.reload_from_disk().unwrap().grants[0].budget.as_ref().unwrap().used_msat, 25);
    drop(service);
    let service = PairingService::open(dir.path(), "identity".into(), true).unwrap();
    service.try_resolve_spend(&debit, &peer, 22).unwrap();
    service.try_resolve_spend(&debit, &peer, 22).unwrap();
    service.close_call_spend(&hold).unwrap();
    let budget = service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert_eq!(budget.used_msat, 22);
    assert!(budget.pending.is_empty());
}

#[test]
fn concurrent_calls_cannot_reserve_the_same_budget_or_liquidity() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let peer = "aa".repeat(32);
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let reserve = |id| {
            barrier.wait();
            service.reserve_call_spend(&client, 1,
                crate::spend_budget::CallSpendTerms::new(&peer, id, 20, 5, 240).unwrap(), 10_000)
        };
        let a = scope.spawn(move || reserve("a"));
        let b = scope.spawn(move || reserve("b"));
        assert_eq!([a.join().unwrap(), b.join().unwrap()].iter().filter(|r| r.is_ok()).count(), 1);
    });
    assert_eq!(service.reload_from_disk().unwrap().grants[0].budget.as_ref().unwrap().used_msat, 6000);
}

#[test]
fn seventy_blocks_use_one_breaker_entry_and_cannot_exceed_call_duration() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let peer = "aa".repeat(32);
    let hold = service.reserve_call_spend(&client, 1,
        crate::spend_budget::CallSpendTerms::new(&peer, "call", 30, 5, 240).unwrap(), 10_000).unwrap();
    for seq in 0..70 {
        let link = crate::spend_budget::OperationReservationLink {
            operation_id: format!("block-{seq}"), execution_id: "attempt".into(), readmission: false,
        };
        let debit = service.draw_call_spend(&client, 1, &peer, "call", seq, 30, 5, link).unwrap();
        service.try_resolve_spend(&debit, &peer, 32).unwrap();
    }
    let link = crate::spend_budget::OperationReservationLink {
        operation_id: "too-late".into(), execution_id: "attempt".into(), readmission: false,
    };
    assert!(service.draw_call_spend(&client, 1, &peer, "call", 240, 30, 5, link).is_err());
    let budget = service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert_eq!(budget.used_msat, 8400);
    let status = budget.breaker_status(chrono::Utc::now().timestamp());
    assert_eq!((status.payments_last_hour, status.unresolved_payments), (1, 1));
    service.close_call_spend(&hold).unwrap();
    assert_eq!(service.reload_from_disk().unwrap().grants[0].budget.as_ref().unwrap().used_msat, 2240);
}

fn first_contact_service(dir: &Path) -> PairingService {
    let service = PairingService::open(dir, "identity".into(), true).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    let client = service
        .create_verified_remote_pairing(
            "app",
            &hex::encode(key.verifying_key().to_bytes()),
            &[13; 32],
        )
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    let mut inner = service.lock();
    inner.file.grants.push(SpendGrant {
        owner_approval: None,
        op_id: "grant".into(),
        client_id: client.client_id,
        scopes: vec![Scope::Spend],
        granted_at: now,
        expires_at: now + 600,
        identity_fingerprint: "identity".into(),
        epoch: client.epoch,
        granted_by: "cli".into(),
        budget: Some(GrantBudget::from_terms(&GrantTerms::new(10_000))),
    });
    service.persist(&mut inner.file).unwrap();
    drop(inner);
    service
}

#[test]
fn first_contact_expiry_is_observable_but_never_spendable() {
    use crate::spend_budget::FirstContactApprovalState as State;
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let recipient = "aa".repeat(32);
    service
        .grant_first_contact(&client, "grant", &recipient, 4000, None)
        .unwrap();
    // Age the actual node record to its boundary; Tokio's clock cannot age
    // Unix timestamps, and waiting five minutes would hide boundary mistakes.
    service
        .lock()
        .first_contact
        .get_mut(&client)
        .unwrap()
        .grant
        .expires_at = chrono::Utc::now().timestamp();
    assert_eq!(
        service
            .first_contact_approval_status(&client, 1, "grant", &recipient)
            .unwrap()
            .state,
        State::Expired
    );
    assert!(service.take_first_contact(&client, 1, &recipient).is_none());
    assert_eq!(
        service
            .first_contact_approval_status(&client, 1, "grant", &recipient)
            .unwrap()
            .state,
        State::Expired
    );
    assert!(service
        .first_contact_approval_status(&client, 2, "grant", &recipient)
        .is_none());
    // Expiry and revocation of the underlying op cannot be masked by a read.
    service.revoke_grants(Some(&client)).unwrap();
    assert!(service
        .first_contact_approval_status(&client, 1, "grant", &recipient)
        .is_none());
}

#[test]
fn simultaneous_first_contact_consumers_get_exactly_one_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let service = std::sync::Arc::new(first_contact_service(dir.path()));
    let client = service.snapshot().clients[0].client_id.clone();
    let recipient = "aa".repeat(32);
    service
        .grant_first_contact(&client, "grant", &recipient, 4000, None)
        .unwrap();
    let barrier = std::sync::Barrier::new(3);
    std::thread::scope(|scope| {
        let consume = || {
            barrier.wait();
            service.take_first_contact(&client, 1, &recipient)
        };
        let a = scope.spawn(consume);
        let b = scope.spawn(consume);
        barrier.wait();
        let approvals = [a.join().unwrap(), b.join().unwrap()];
        assert_eq!(approvals.iter().filter(|a| a.is_some()).count(), 1);
        for approval in approvals.into_iter().flatten() {
            service.reserve_first_contact(approval, None).unwrap();
        }
    });
    let budget = service.reload_from_disk().unwrap().grants[0]
        .budget
        .clone()
        .unwrap();
    assert_eq!(budget.used_msat, 4000);
    assert_eq!(budget.pending.len(), 1);
}

fn expiry_during_reservation_persistence(live_reads: usize) {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), "identity".into(), true).unwrap();
    let now = chrono::Utc::now().timestamp();
    let expiry = now + 60;
    {
        let mut inner = service.lock();
        inner.file.clients.push(PairedClient {
            client_id: "client".into(),
            name: "test".into(),
            client_pubkey: "00".repeat(32),
            remote_transport_pubkey: None,
            scopes: default_pairing_scopes(),
            epoch: 1,
            identity_fingerprint: "identity".into(),
            created_at: now,
            last_seen: None,
        });
        inner.file.grants.push(SpendGrant {
            owner_approval: None,
            op_id: "grant".into(),
            client_id: "client".into(),
            scopes: vec![Scope::Spend],
            granted_at: now,
            expires_at: expiry,
            identity_fingerprint: "identity".into(),
            epoch: 1,
            granted_by: "cli".into(),
            budget: Some(GrantBudget::from_terms(&GrantTerms::new(1000))),
        });
        service.persist(&mut inner.file).unwrap();
    }
    let mut reads = 0;
    let result = service.reserve_spend_with_clock(
        "client",
        1,
        vec![Charge {
            recipient: "aa".repeat(32),
            amount_msat: 1000,
        }],
        || {
            reads += 1;
            if reads <= live_reads {
                expiry - 1
            } else {
                expiry
            }
        },
    );
    assert!(service.reload_from_disk().unwrap().grants.is_empty());
    assert_eq!(
        result,
        Err(BudgetRefusal::NoGrant),
        "expired reservation must not authorize dispatch"
    );
}

#[test]
fn expiry_during_reservation_persistence_refuses_the_debit() {
    expiry_during_reservation_persistence(1);
}

#[test]
fn expiry_during_temp_file_sync_is_pruned_before_publish() {
    expiry_during_reservation_persistence(2);
}

#[test]
fn expiry_during_rename_sync_is_pruned_before_return() {
    expiry_during_reservation_persistence(3);
}

#[test]
fn local_device_grant_dispatch_and_staging_keep_deadlines_and_deployment_gates() {
    let dir = tempfile::tempdir().unwrap();
    let owner = first_contact_service(dir.path());
    let client = owner.snapshot().clients[0].clone();
    let now = chrono::Utc::now().timestamp();
    let peer = "aa".repeat(32);
    {
        let mut inner = owner.lock();
        let grant = &mut inner.file.grants[0];
        grant.granted_by = "device:test".into();
        let budget = grant.budget.as_mut().unwrap();
        budget.recipients_only = true;
        budget.per_recipient_msat.insert(peer.clone(), 1000);
        budget.per_act_max_by_recipient.insert(peer.clone(), 1000);
        budget.recipient_expires_at.insert(peer.clone(), now + 60);
        owner.persist(&mut inner.file).unwrap();
    }
    drop(owner);
    let service = PairingService::open(dir.path(), "identity".into(), false)
        .unwrap()
        .with_local_owner_device()
        .with_owner_approval_key(ed25519_dalek::SigningKey::from_bytes(&[14; 32]).verifying_key());
    let binding = auth::PairingBinding {
        client_id: client.client_id.clone(),
        epoch: client.epoch,
        fingerprint: "identity".into(),
    };
    assert_eq!(
        service.live_spend_grant_id(&binding).as_deref(),
        Some("grant")
    );
    let reservation = service
        .reserve_spend(
            &client.client_id,
            client.epoch,
            vec![Charge {
                recipient: peer,
                amount_msat: 1,
            }],
        )
        .unwrap();
    assert_eq!(
        service
            .with_spend_authority_at(&reservation, || now, || 42)
            .unwrap(),
        42
    );
    assert!(matches!(
        service.with_spend_authority_at(
            &reservation,
            || now + 60,
            || panic!("expired envelope dispatched")
        ),
        Err(BudgetRefusal::NoGrant)
    ));
    for (source, recipients_only) in [("cli", true), ("device:test", false)] {
        let mut inner = service.lock();
        inner.file.grants[0].granted_by = source.into();
        inner.file.grants[0]
            .budget
            .as_mut()
            .unwrap()
            .recipients_only = recipients_only;
        drop(inner);
        assert!(service.live_spend_grant_id(&binding).is_none());
        assert!(matches!(
            service.with_spend_authority_at(
                &reservation,
                || now,
                || panic!("forbidden grant dispatched")
            ),
            Err(BudgetRefusal::NoGrant)
        ));
    }
}

#[test]
fn payment_dedupe_and_allowlist_survive_restart_and_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].clone();
    let peer = "aa".repeat(32);
    {
        let mut inner = service.lock();
        inner.file.grants[0]
            .budget
            .as_mut()
            .unwrap()
            .payee_allowlist = Some([peer.clone()].into());
        service.persist(&mut inner.file).unwrap();
    }
    let charges = vec![Charge {
        recipient: peer.clone(),
        amount_msat: 1000,
    }];
    let ids = vec!["hash:payment".into(), "request:retry".into()];
    let reservation = service
        .reserve_payment(
            &client.client_id,
            client.epoch,
            charges.clone(),
            ids.clone(),
        )
        .unwrap();
    service.resolve_spend(&reservation, &peer, 500);
    drop(service);
    let service = PairingService::open(dir.path(), "identity".into(), true).unwrap();
    for id in &ids {
        assert_eq!(
            service.reserve_payment(
                &client.client_id,
                client.epoch,
                charges.clone(),
                vec![id.clone()]
            ),
            Err(BudgetRefusal::DuplicatePayment)
        );
    }
    let stored = service.reload_from_disk().unwrap();
    let budget = stored.grants[0].budget.as_ref().unwrap();
    assert_eq!(budget.used_msat, 500);
    assert!(budget.pending.is_empty());
    assert_eq!(budget.payment_ids.len(), 2);
    assert!(matches!(
        service.reserve_payment(
            &client.client_id,
            client.epoch,
            vec![Charge {
                recipient: "bb".repeat(32),
                amount_msat: 1000
            }],
            vec!["request:new".into()]
        ),
        Err(BudgetRefusal::PayeeNotAllowed { .. })
    ));
    // Refused payments did not consume their IDs; a corrected request can proceed.
    service
        .reserve_payment(
            &client.client_id,
            client.epoch,
            charges,
            vec!["request:new".into()],
        )
        .unwrap();
    assert_eq!(
        service.reload_from_disk().unwrap().grants[0]
            .budget
            .as_ref()
            .unwrap()
            .used_msat,
        1500
    );
}

#[test]
fn payment_dedupe_rolls_back_with_failed_persistence_and_never_evicts() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].clone();
    let charges = vec![Charge {
        recipient: "aa".repeat(32),
        amount_msat: 1000,
    }];
    // A directory in the temporary-file slot forces a real write failure.
    let blocked = service.file_path.with_extension("json.tmp");
    std::fs::create_dir(&blocked).unwrap();
    assert!(matches!(
        service.reserve_payment(
            &client.client_id,
            client.epoch,
            charges.clone(),
            vec!["request:retry".into()]
        ),
        Err(BudgetRefusal::Ledger(_))
    ));
    assert_eq!(
        service.snapshot().grants[0]
            .budget
            .as_ref()
            .unwrap()
            .used_msat,
        0
    );
    std::fs::remove_dir(blocked).unwrap();
    service
        .reserve_payment(
            &client.client_id,
            client.epoch,
            charges.clone(),
            vec!["request:retry".into()],
        )
        .unwrap();
    {
        let mut inner = service.lock();
        let budget = inner.file.grants[0].budget.as_mut().unwrap();
        budget
            .payment_ids
            .extend((0..4095).map(|n| format!("request:{n}")));
        service.persist(&mut inner.file).unwrap();
    }
    assert!(matches!(
        service.reserve_payment(
            &client.client_id,
            client.epoch,
            charges.clone(),
            vec!["request:overflow".into()]
        ),
        Err(BudgetRefusal::Ledger(_))
    ));
    assert_eq!(
        service.reserve_payment(
            &client.client_id,
            client.epoch,
            charges,
            vec!["request:retry".into()]
        ),
        Err(BudgetRefusal::DuplicatePayment)
    );
    assert_eq!(
        service.reload_from_disk().unwrap().grants[0]
            .budget
            .as_ref()
            .unwrap()
            .used_msat,
        1000
    );
}

fn breaker_service(dir: &Path, minute: u64, failures: u64, velocity: u64) -> PairingService {
    let service = first_contact_service(dir);
    let mut inner = service.lock();
    let b = inner.file.grants[0].budget.as_mut().unwrap();
    b.breakers.max_payments_per_minute = minute;
    b.breakers.max_payments_per_hour = 100;
    b.breakers.max_consecutive_failures = failures;
    b.breakers.max_msat_per_10_minutes = velocity;
    service.persist(&mut inner.file).unwrap();
    drop(inner);
    service
}

#[test]
fn concurrent_breaker_reservations_cannot_overshoot_rate_or_velocity() {
    for (minute, velocity, reason) in [
        (1, 10_000, "rate_limit_minute"),
        (100, 1_000, "velocity_limit"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let service = breaker_service(dir.path(), minute, 100, velocity);
        let client = service.snapshot().clients[0].clone();
        let barrier = std::sync::Barrier::new(9);
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        service.reserve_spend(
                            &client.client_id,
                            client.epoch,
                            vec![Charge {
                                recipient: "aa".repeat(32),
                                amount_msat: 1_000,
                            }],
                        )
                    })
                })
                .collect();
            barrier.wait();
            let outcomes: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
            assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
            assert!(outcomes
                .iter()
                .filter_map(|r| r.as_ref().err())
                .all(|e| e.reason() == reason));
        });
        let b = service.reload_from_disk().unwrap().grants[0]
            .budget
            .clone()
            .unwrap();
        assert_eq!(b.used_msat, 1000);
        assert_eq!(
            b.breaker_status(chrono::Utc::now().timestamp())
                .payments_last_minute,
            1
        );
    }
}

#[test]
fn failures_latch_pause_through_restart_success_and_owner_reset() {
    let dir = tempfile::tempdir().unwrap();
    let service = breaker_service(dir.path(), 100, 2, 10_000);
    let client = service.snapshot().clients[0].clone();
    let peer = "aa".repeat(32);
    let pay = || {
        vec![Charge {
            recipient: peer.clone(),
            amount_msat: 1000,
        }]
    };
    let a = service
        .reserve_spend(&client.client_id, client.epoch, pay())
        .unwrap();
    let b = service
        .reserve_spend(&client.client_id, client.epoch, pay())
        .unwrap();
    assert_eq!(
        service
            .reserve_spend(&client.client_id, client.epoch, pay())
            .unwrap_err()
            .reason(),
        "failure_limit_pending"
    );
    service.resolve_spend(&a, &peer, 0);
    service.resolve_spend(&a, &peer, 0); // duplicate must not increment the streak
    assert!(!service.grant_views()[0].breakers.paused);
    service.resolve_spend(&b, &peer, 0);
    assert!(service.grant_views()[0].breakers.paused);
    drop(service);
    let service = PairingService::open(dir.path(), "identity".into(), true).unwrap();
    assert_eq!(
        service
            .reserve_spend(&client.client_id, client.epoch, pay())
            .unwrap_err()
            .reason(),
        "grant_paused"
    );
    service.resolve_spend(&b, &peer, 1000); // duplicate success cannot unpause
    assert!(service.grant_views()[0].breakers.paused);
    service
        .reset_grant_breakers(&client.client_id, "grant")
        .unwrap();
    let a = service
        .reserve_spend(&client.client_id, client.epoch, pay())
        .unwrap();
    service.resolve_spend(&a, &peer, 0);
    let a = service
        .reserve_spend(&client.client_id, client.epoch, pay())
        .unwrap();
    service.resolve_spend(&a, &peer, 500);
    assert_eq!(service.grant_views()[0].breakers.consecutive_failures, 0);
    assert_eq!(service.grant_views()[0].used_msat, 500);
}

#[test]
fn breaker_crash_and_failed_writes_keep_unknown_outcomes_charged() {
    let dir = tempfile::tempdir().unwrap();
    let service = breaker_service(dir.path(), 100, 1, 10_000);
    let client = service.snapshot().clients[0].clone();
    let peer = "aa".repeat(32);
    let pay = || {
        vec![Charge {
            recipient: peer.clone(),
            amount_msat: 1000,
        }]
    };
    let blocked = service.file_path.with_extension("json.tmp");
    let before = service.snapshot().grants[0].budget.clone();
    std::fs::create_dir(&blocked).unwrap();
    assert!(matches!(
        service.reserve_spend(&client.client_id, client.epoch, pay()),
        Err(BudgetRefusal::Ledger(_))
    ));
    assert_eq!(service.snapshot().grants[0].budget, before);
    std::fs::remove_dir(&blocked).unwrap();
    let a = service
        .reserve_spend(&client.client_id, client.epoch, pay())
        .unwrap();
    let before = service.snapshot().grants[0].budget.clone();
    std::fs::create_dir(&blocked).unwrap();
    assert!(service.try_resolve_spend(&a, &peer, 0).is_err());
    assert_eq!(service.snapshot().grants[0].budget, before);
    assert!(service
        .reset_grant_breakers(&client.client_id, "grant")
        .is_err());
    assert_eq!(service.snapshot().grants[0].budget, before);
    std::fs::remove_dir(&blocked).unwrap();
    drop(service); // crash before the failure outcome could be persisted
    let service = PairingService::open(dir.path(), "identity".into(), true).unwrap();
    assert_eq!(
        service
            .reserve_spend(&client.client_id, client.epoch, pay())
            .unwrap_err()
            .reason(),
        "failure_limit_pending"
    );
    assert_eq!(service.grant_views()[0].breakers.payments_last_minute, 1);
    service.resolve_spend(&a, &peer, 0);
    assert!(service.grant_views()[0].breakers.paused);
    drop(service);
    let sidecar = PairingService::open(dir.path(), "identity".into(), false).unwrap();
    assert!(matches!(
        sidecar.reset_grant_breakers(&client.client_id, "grant"),
        Err(PairingError::OwnerChannelUnavailable)
    ));
}

#[test]
fn failure_slots_bound_fanout_and_pause_stops_queued_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let service = breaker_service(dir.path(), 100, 2, 10_000);
    let client = service.snapshot().clients[0].clone();
    let charge = |key: &str| Charge {
        recipient: key.repeat(32),
        amount_msat: 1000,
    };
    let r = service
        .reserve_spend(&client.client_id, client.epoch, vec![charge("aa")])
        .unwrap();
    assert_eq!(
        service
            .reserve_spend(
                &client.client_id,
                client.epoch,
                vec![charge("bb"), charge("cc")]
            )
            .unwrap_err()
            .reason(),
        "failure_limit_pending"
    );
    let queued = service
        .reserve_spend(&client.client_id, client.epoch, vec![charge("bb")])
        .unwrap();
    service.resolve_spend(&r, &"aa".repeat(32), 0);
    // Model a threshold lowered in approved terms while an earlier reservation
    // remains queued. A successful late result must not unlatch the pause.
    {
        let mut inner = service.lock();
        let budget = inner.file.grants[0].budget.as_mut().unwrap();
        budget.breakers.max_consecutive_failures = 1;
        budget.record_outcome(1000, 0, chrono::Utc::now().timestamp());
        service.persist(&mut inner.file).unwrap();
    }
    assert_eq!(
        service.with_spend_authority(&queued, || panic!("paused grant dispatched")),
        Err(BudgetRefusal::GrantPaused)
    );
    service.resolve_spend(&queued, &"bb".repeat(32), 500);
    assert!(service.grant_views()[0].breakers.paused);
}

#[test]
fn legacy_relation_cap_applies_on_first_reservation_without_rewriting_terms() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let recipient = "aa".repeat(32);
    {
        let mut inner = service.lock();
        let budget = inner.file.grants[0].budget.as_mut().unwrap();
        *budget = GrantBudget::relations();
        budget.open_envelope(
            &recipient,
            200_000,
            20_000,
            chrono::Utc::now().timestamp() + 600,
        );
        // The pre-upgrade relation format used the aggregate budget as its cap.
        budget.per_call_max_msat = budget.budget_msat;
        service.persist(&mut inner.file).unwrap();
    }
    drop(service);
    let service = PairingService::open(dir.path(), "identity".into(), true).unwrap();
    let stored_cap = service.snapshot().grants[0]
        .budget
        .as_ref()
        .unwrap()
        .per_call_max_msat;
    assert_eq!(
        stored_cap, 200_000,
        "opening a legacy grant must not rewrite its terms"
    );
    let charge = |amount_msat| {
        vec![Charge {
            recipient: recipient.clone(),
            amount_msat,
        }]
    };
    assert!(matches!(
        service.reserve_spend(&client, 1, charge(7_000)),
        Err(BudgetRefusal::PerCall { max_msat: 6_000 })
    ));
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 0);
    assert_eq!(
        service.grant_view_for(&client).unwrap().message_per_payment_max_msat,
        6_000
    );
    service.reserve_spend(&client, 1, charge(6_000)).unwrap();
    let stored = service.reload_from_disk().unwrap().grants[0]
        .budget
        .clone()
        .unwrap();
    assert_eq!(stored.per_call_max_msat, stored_cap);
    assert_eq!(stored.used_msat, 6_000);
}

#[test]
fn console_first_contact_and_readmission_share_six_sat_call_cap() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let recipient = "aa".repeat(32);
    assert!(matches!(
        service.grant_first_contact(&client, "grant", &recipient, 7_000, None),
        Err(BudgetRefusal::PerCall { max_msat: 6_000 })
    ));
    // Nightly run 40155311812: the three-node quote was 2_001 + 2_001 plus two
    // default 5_000 msat fee floors. That 14_002 msat all-in call is over the cap.
    assert!(matches!(
        service.grant_first_contact(&client, "grant", &recipient, 14_002, None),
        Err(BudgetRefusal::PerCall { max_msat: 6_000 })
    ));
    service
        .grant_first_contact(&client, "grant", &recipient, 6_000, None)
        .unwrap();
    let parent = service
        .reserve_spend(
            &client,
            1,
            vec![Charge {
                recipient: recipient.clone(),
                amount_msat: 4_000,
            }],
        )
        .unwrap();
    // Both the message repricing and admission must fit the original call.
    assert!(matches!(
        service.reserve_quoted_readmission(&parent, &recipient, 5_000, 2_000, 4_000, None),
        Err(BudgetRefusal::PerCall { max_msat: 6_000 })
    ));
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 4_000);
    let (total, _) = service
        .reserve_quoted_readmission(&parent, &recipient, 4_000, 2_000, 4_000, None)
        .unwrap();
    assert_eq!(total, 6_000);
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 6_000);
}

#[test]
fn console_fanout_cap_checks_the_whole_call_before_any_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let charges = |amount_msat| {
        vec![
            Charge {
                recipient: "aa".repeat(32),
                amount_msat,
            },
            Charge {
                recipient: "bb".repeat(32),
                amount_msat,
            },
        ]
    };
    assert!(matches!(
        service.reserve_spend(&client, 1, charges(3_500)),
        Err(BudgetRefusal::PerCall { max_msat: 6_000 })
    ));
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 0);
    service.reserve_spend(&client, 1, charges(3_000)).unwrap();
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 6_000);
}

#[test]
fn call_parent_cannot_be_resolved_as_a_payment() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let peer = "aa".repeat(32);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, "parent", 20, 5, 240).unwrap();
    let hold = service.reserve_call_spend(&client, 1, terms, 10_000).unwrap();
    assert!(service.try_resolve_spend(&hold, &peer, 0).is_err());
    assert_eq!(service.reload_from_disk().unwrap().grants[0].budget.as_ref().unwrap().used_msat, 6000);
    service.close_call_spend(&hold).unwrap();
    assert_eq!(service.reload_from_disk().unwrap().grants[0].budget.as_ref().unwrap().used_msat, 0);
}

#[test]
fn declined_call_is_neutral_to_payment_failure_breaker() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let peer = "aa".repeat(32);
    for n in 0..4 {
        let terms = crate::spend_budget::CallSpendTerms::new(&peer, &format!("declined-{n}"), 20, 5, 240).unwrap();
        let hold = service.reserve_call_spend(&client, 1, terms, 10_000).unwrap();
        service.close_call_spend(&hold).unwrap();
    }
    let budget = service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert_eq!(budget.breaker_status(chrono::Utc::now().timestamp()).consecutive_failures, 0);
    assert!(!budget.is_paused());
}

#[test]
fn finished_call_drops_paid_sequences_and_does_not_fill_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let peer = "aa".repeat(32);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, "finished", 20, 5, 240).unwrap();
    let hold = service.reserve_call_spend(&client, 1, terms, 10_000).unwrap();
    let debit = service.draw_call_spend(&client, 1, &peer, "finished", 0, 20, 5,
        crate::spend_budget::OperationReservationLink {
            operation_id: "block".into(), execution_id: "attempt".into(), readmission: false,
        }).unwrap();
    service.try_resolve_spend(&debit, &peer, 22).unwrap();
    service.close_call_spend(&hold).unwrap();
    let mut inner = service.lock();
    let budget = inner.file.grants[0].budget.as_mut().unwrap();
    let tombstone = budget.call_reservations[&hold.id].clone();
    assert!(tombstone.paid_sequences.is_empty());
    for n in 0..1024 {
        let mut call = tombstone.clone();
        call.terms.call_id = format!("old-{n}");
        budget.call_reservations.insert(format!("old-{n}"), call);
    }
    service.persist(&mut inner.file).unwrap();
    drop(inner);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, "new", 20, 5, 240).unwrap();
    service.reserve_call_spend(&client, 1, terms, 10_000).unwrap();
    assert!(service.reload_from_disk().unwrap().grants[0].budget.as_ref().unwrap().call_reservations.len() <= 257);
}

#[test]
fn finished_tombstones_age_out_but_unresolved_draws_survive_and_legacy_shape_returns() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let peer = "aa".repeat(32);
    let original = serde_json::to_value(service.snapshot().grants[0].budget.as_ref().unwrap()).unwrap();
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, "late", 20, 5, 1).unwrap();
    let hold = service.reserve_call_spend(&client, 1, terms, 10_000).unwrap();
    let debit = service.draw_call_spend(&client, 1, &peer, "late", 0, 20, 5,
        crate::spend_budget::OperationReservationLink { operation_id: "block".into(), execution_id: "attempt".into(), readmission: false }).unwrap();
    service.close_call_spend(&hold).unwrap();
    let later = chrono::Utc::now().timestamp() + 86401;
    service.prune_call_spend(later).unwrap();
    assert_eq!(service.call_spend_status(&peer, "late").unwrap().remaining_msat, 25);
    service.try_resolve_spend(&debit, &peer, 22).unwrap();
    service.prune_call_spend(later).unwrap();
    let budget = service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert_eq!(budget.used_msat, 22);
    let pruned = serde_json::to_value(budget).unwrap();
    // All top-level fields are again from the pre-call GrantBudget schema;
    // no call metadata remains in pending or operation links either.
    assert_eq!(pruned.as_object().unwrap().keys().collect::<Vec<_>>(), original.as_object().unwrap().keys().collect::<Vec<_>>());
    assert_eq!(pruned["pending"], serde_json::json!({}));
    assert_eq!(pruned["operation_links"], serde_json::json!({}));
}


#[test]
fn call_terms_keep_legacy_duration_and_bound_new_reservations() {
    use crate::spend_budget::CallSpendTerms;
    let terms = CallSpendTerms::new("peer", "call", 20, 5, 240).unwrap();
    let mut legacy = serde_json::to_value(&terms).unwrap();
    legacy.as_object_mut().unwrap().remove("max_call_minutes");
    let loaded: CallSpendTerms = serde_json::from_value(legacy).unwrap();
    assert_eq!((loaded.max_call_minutes, loaded.reserved_msat), (240, 6000));
    for invalid in [0, 241, u16::MAX] {
        assert!(CallSpendTerms::new("peer", "call", 20, 5, invalid).is_err());
    }
    assert!(CallSpendTerms::new("peer", "call", u64::MAX, 1, 60).is_err());
    assert!(CallSpendTerms::new("peer", "call", u64::MAX / 2, 0, 60).is_err());
}
