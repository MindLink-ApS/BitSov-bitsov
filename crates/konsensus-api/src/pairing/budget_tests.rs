use super::*;

fn first_contact_service(dir: &Path) -> PairingService {
    let service = PairingService::open(dir, "identity".into(), true).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    let client = service.create_verified_remote_pairing("app", &hex::encode(key.verifying_key().to_bytes()), &[13; 32]).unwrap();
    let now = chrono::Utc::now().timestamp();
    let mut inner = service.lock();
    inner.file.grants.push(SpendGrant {
        op_id: "grant".into(), client_id: client.client_id,
        scopes: vec![Scope::Spend], granted_at: now, expires_at: now + 600,
        identity_fingerprint: "identity".into(), epoch: client.epoch,
        granted_by: "cli".into(), budget: Some(GrantBudget::from_terms(&GrantTerms::new(10_000))),
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
    service.grant_first_contact(&client, "grant", &recipient, 4000, None).unwrap();
    // Age the actual node record to its boundary; Tokio's clock cannot age
    // Unix timestamps, and waiting five minutes would hide boundary mistakes.
    service.lock().first_contact.get_mut(&client).unwrap().grant.expires_at = chrono::Utc::now().timestamp();
    assert_eq!(service.first_contact_approval_status(&client, 1, "grant", &recipient).unwrap().state, State::Expired);
    assert!(service.take_first_contact(&client, 1, &recipient).is_none());
    assert_eq!(service.first_contact_approval_status(&client, 1, "grant", &recipient).unwrap().state, State::Expired);
    assert!(service.first_contact_approval_status(&client, 2, "grant", &recipient).is_none());
    // Expiry and revocation of the underlying op cannot be masked by a read.
    service.revoke_grants(Some(&client)).unwrap();
    assert!(service.first_contact_approval_status(&client, 1, "grant", &recipient).is_none());
}

#[test]
fn simultaneous_first_contact_consumers_get_exactly_one_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let service = std::sync::Arc::new(first_contact_service(dir.path()));
    let client = service.snapshot().clients[0].client_id.clone();
    let recipient = "aa".repeat(32);
    service.grant_first_contact(&client, "grant", &recipient, 4000, None).unwrap();
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
    let budget = service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
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
        .with_local_owner_device();
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
