use super::*;

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
