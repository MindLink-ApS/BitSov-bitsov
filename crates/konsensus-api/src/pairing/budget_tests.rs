use super::*;

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

// An on-disk grant from before per-act approval wording, including grants
// which already carried normal rolling circuit breakers.
fn pre_act_service(dir: &Path, per_call: u64, unlimited_breakers: bool) -> PairingService {
    let service = first_contact_service(dir);
    {
        let mut inner = service.lock();
        let budget = inner.file.grants[0].budget.as_mut().unwrap();
        budget.budget_msat = 200_000;
        budget.per_call_max_msat = per_call;
        for recipient in ["aa".repeat(32), "bb".repeat(32)] {
            budget.per_recipient_msat.insert(recipient, 100_000);
        }
        if unlimited_breakers {
            budget.breakers = crate::spend_budget::BreakerLimits::legacy();
        }
        service.persist(&mut inner.file).unwrap();
    }
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&service.file_path).unwrap()).unwrap();
    file["grants"][0]["budget"]
        .as_object_mut()
        .unwrap()
        .remove("per_act_limits");
    std::fs::write(&service.file_path, serde_json::to_vec(&file).unwrap()).unwrap();
    drop(service);
    PairingService::open(dir, "identity".into(), true).unwrap()
}

#[test]
fn stored_grants_keep_whole_call_room_limit_with_any_breakers() {
    for unlimited in [false, true] {
        for (stored_cap, cap) in [(4_000, 4_000), (200_000, 6_000)] {
            let dir = tempfile::tempdir().unwrap();
            let service = pre_act_service(dir.path(), stored_cap, unlimited);
            let client = service.snapshot().clients[0].client_id.clone();
            let before = service.snapshot().grants[0].budget.clone();
            let result = service.reserve_spend(
                &client,
                1,
                vec![
                    Charge {
                        recipient: "aa".repeat(32),
                        amount_msat: cap,
                    },
                    Charge {
                        recipient: "bb".repeat(32),
                        amount_msat: 1,
                    },
                ],
            );
            assert!(
                matches!(result, Err(BudgetRefusal::PerCall { max_msat }) if max_msat == cap),
                "{result:?}"
            );
            assert_eq!(service.reload_from_disk().unwrap().grants[0].budget, before);
        }
    }
}

#[test]
fn stored_grants_keep_first_contact_within_whole_call_limit() {
    for unlimited in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let service = pre_act_service(dir.path(), 4_000, unlimited);
        let client = service.snapshot().clients[0].client_id.clone();
        let recipient = "aa".repeat(32);
        let caps = service.grant_view_for(&client).unwrap().act_caps;
        assert_eq!(caps.first_contact_max_all_in_msat, 4_000);
        assert_eq!(caps.readmission_max_all_in_msat, 4_000);
        assert_eq!(caps.whole_call_max_all_in_msat, Some(4_000));
        assert!(matches!(
            service.grant_first_contact(&client, "grant", &recipient, 4_001, None),
            Err(BudgetRefusal::PerCall { max_msat: 4_000 })
        ));
        service
            .grant_first_contact(&client, "grant", &recipient, 4_000, None)
            .unwrap();
        let approval = service.take_first_contact(&client, 1, &recipient).unwrap();
        service.reserve_first_contact(approval, None).unwrap();
        assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 4_000);
    }
}

#[test]
fn stored_grants_count_readmission_and_settled_room_members_in_whole_call_limit() {
    for unlimited in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let service = pre_act_service(dir.path(), 4_000, unlimited);
        let client = service.snapshot().clients[0].client_id.clone();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let parent = service
            .reserve_spend(
                &client,
                1,
                vec![
                    Charge {
                        recipient: a.clone(),
                        amount_msat: 1_000,
                    },
                    Charge {
                        recipient: b.clone(),
                        amount_msat: 1_000,
                    },
                ],
            )
            .unwrap();
        let before = service.snapshot().grants[0].budget.clone();
        assert!(matches!(
            service.reserve_quoted_readmission(
                &parent,
                &a,
                2_000,
                1_001,
                CallReservationTotals::messages(2_000),
                None,
            ),
            Err(BudgetRefusal::PerCall { max_msat: 4_000 })
        ));
        assert_eq!(service.reload_from_disk().unwrap().grants[0].budget, before);
        let (total, admission) = service
            .reserve_quoted_readmission(
                &parent,
                &a,
                2_000,
                1_000,
                CallReservationTotals::messages(2_000),
                None,
            )
            .unwrap();
        assert_eq!(total.all_in_msat, 4_000);
        service.resolve_spend(&parent, &a, 2_000);
        service.resolve_spend(&admission, &a, 1_000);
        let before = service.snapshot().grants[0].budget.clone();
        assert!(matches!(
            service.reserve_quoted_readmission(&parent, &b, 1_000, 1, total, None,),
            Err(BudgetRefusal::PerCall { max_msat: 4_000 })
        ));
        assert_eq!(service.reload_from_disk().unwrap().grants[0].budget, before);
    }
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
        service.grant_view_for(&client).unwrap().per_call_max_msat,
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
fn admission_has_its_own_all_in_cap() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let recipient = "aa".repeat(32);
    service
        .grant_first_contact(&client, "grant", &recipient, 9_000, None)
        .unwrap();
    let approval = service.take_first_contact(&client, 1, &recipient).unwrap();
    let first = service.reserve_first_contact(approval, None).unwrap();
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 9_000);
    service.resolve_spend(&first, &recipient, 0);
    service
        .grant_first_contact(&client, "grant", &recipient, 9_000, None)
        .unwrap();
    let parent = service
        .reserve_spend(
            &client,
            1,
            vec![Charge {
                recipient: recipient.clone(),
                amount_msat: 2_000,
            }],
        )
        .unwrap();
    assert!(matches!(
        service.reserve_quoted_readmission(
            &parent,
            &recipient,
            6_001,
            1_000,
            CallReservationTotals::messages(2_000),
            None
        ),
        Err(BudgetRefusal::PerCall { .. })
    ));
    let (total, _) = service
        .reserve_quoted_readmission(
            &parent,
            &recipient,
            2_000,
            7_000,
            CallReservationTotals::messages(2_000),
            None,
        )
        .unwrap();
    assert_eq!(total.all_in_msat, 9_000);
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 9_000);
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
        service.reserve_spend(&client, 1, charges(6_001)),
        Err(BudgetRefusal::PerCall { max_msat: 6_000 })
    ));
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 0);
    service.reserve_spend(&client, 1, charges(4_000)).unwrap();
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 8_000);
}

#[test]
fn legacy_unlimited_breakers_keep_the_total_room_call_cap_after_restart() {
    for (stored_cap, total_cap) in [(200_000, 6_000), (4_000, 4_000)] {
        let dir = tempfile::tempdir().unwrap();
        let service = pre_act_service(dir.path(), stored_cap, true);
        let client = service.snapshot().clients[0].client_id.clone();
        let before = service.snapshot().grants[0].budget.clone().unwrap();
        let charges = (0..256)
            .map(|n| Charge {
                recipient: format!("{n:064x}"),
                amount_msat: total_cap,
            })
            .collect();
        assert!(matches!(service.reserve_spend(&client, 1, charges),
            Err(BudgetRefusal::PerCall { max_msat }) if max_msat == total_cap));
        let after = service.reload_from_disk().unwrap().grants[0]
            .budget
            .clone()
            .unwrap();
        assert_eq!(
            after, before,
            "a rejected room call must not reserve any member or rewrite terms"
        );
        service
            .reserve_spend(
                &client,
                1,
                vec![
                    Charge {
                        recipient: "aa".repeat(32),
                        amount_msat: total_cap / 2,
                    },
                    Charge {
                        recipient: "bb".repeat(32),
                        amount_msat: total_cap / 2,
                    },
                ],
            )
            .unwrap();
        assert_eq!(
            service.grant_view_for(&client).unwrap().used_msat,
            total_cap
        );
    }
}

#[test]
fn legacy_room_repricing_keeps_the_message_total_across_settled_members() {
    let dir = tempfile::tempdir().unwrap();
    let service = pre_act_service(dir.path(), 200_000, true);
    let client = service.snapshot().clients[0].client_id.clone();
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let parent = service
        .reserve_spend(
            &client,
            1,
            vec![
                Charge {
                    recipient: a.clone(),
                    amount_msat: 1_000,
                },
                Charge {
                    recipient: b.clone(),
                    amount_msat: 1_000,
                },
            ],
        )
        .unwrap();
    let before = service.snapshot().grants[0].budget.clone().unwrap();
    assert!(matches!(
        service.reserve_quoted_readmission(
            &parent,
            &a,
            6_000,
            1_000,
            CallReservationTotals::messages(2_000),
            None
        ),
        Err(BudgetRefusal::PerCall { max_msat: 6_000 })
    ));
    assert_eq!(
        service.reload_from_disk().unwrap().grants[0]
            .budget
            .as_ref(),
        Some(&before)
    );
    // Messages and admission must share the old grant's 6,000-msat ceiling.
    let (total, admission) = service
        .reserve_quoted_readmission(
            &parent,
            &a,
            4_000,
            1_000,
            CallReservationTotals::messages(2_000),
            None,
        )
        .unwrap();
    assert_eq!(total.all_in_msat, 6_000);
    service.resolve_spend(&parent, &a, 4_000);
    service.resolve_spend(&admission, &a, 1_000);
    let before = service.snapshot().grants[0].budget.clone().unwrap();
    // A has settled and left pending, but its message and admission still count.
    assert!(matches!(
        service.reserve_quoted_readmission(&parent, &b, 2_000, 1_000, total, None),
        Err(BudgetRefusal::PerCall { max_msat: 6_000 })
    ));
    assert_eq!(
        service.reload_from_disk().unwrap().grants[0]
            .budget
            .as_ref(),
        Some(&before)
    );
}

#[test]
fn payment_class_helpers_use_owner_limit_and_reject_messaging_grants() {
    let dir = tempfile::tempdir().unwrap();
    let service = first_contact_service(dir.path());
    let client = service.snapshot().clients[0].client_id.clone();
    let recipient = "aa".repeat(32);
    let charges = |amount_msat| {
        vec![Charge {
            recipient: recipient.clone(),
            amount_msat,
        }]
    };
    {
        let mut inner = service.lock();
        let budget = inner.file.grants[0].budget.as_mut().unwrap();
        budget.allow_liquidity_fees = true;
        budget.per_call_max_msat = 8_000;
    }
    assert!(matches!(
        service.reserve_liquidity_fee(&client, 1, charges(8_001)),
        Err(BudgetRefusal::PerCall { max_msat: 8_000 })
    ));
    let liquidity = service
        .reserve_liquidity_fee(&client, 1, charges(7_000))
        .unwrap();
    service.resolve_spend(&liquidity, &recipient, 0);
    let sponsor = service
        .reserve_spend_linked(&client, 1, charges(8_000), |_| Ok(()))
        .unwrap();
    service.resolve_spend(&sponsor, &recipient, 0);
    // Even a legacy messaging grant with the LSP flag is not payment authority.
    {
        let mut inner = service.lock();
        inner.file.grants[0]
            .budget
            .as_mut()
            .unwrap()
            .recipients_only = true;
    }
    assert!(matches!(
        service.reserve_liquidity_fee(&client, 1, charges(1_000)),
        Err(BudgetRefusal::MessagingGrant)
    ));
    let mut journal_written = false;
    assert!(matches!(
        service.reserve_spend_linked(&client, 1, charges(1_000), |_| {
            journal_written = true;
            Ok(())
        }),
        Err(BudgetRefusal::MessagingGrant)
    ));
    assert!(!journal_written);
    assert_eq!(service.grant_view_for(&client).unwrap().used_msat, 0);
}
