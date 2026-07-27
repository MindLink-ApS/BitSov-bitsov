use konsensus_storage::{
    AcceptedInviteRecord, InviteIssuedRecord, InviteState, SqliteStorage, Storage, StorageError,
};

#[tokio::test]
async fn invites_sqlite_round_trip_preserves_i64_mapped_fields() {
    let storage = SqliteStorage::in_memory().await.expect("sqlite in-memory");

    let record = InviteIssuedRecord {
        id: uuid::Uuid::new_v4(),
        invitee_pubkey: [0xAB; 32],
        expiry_unix: i64::MAX as u64,
        channel_size_hint_sats: Some(u32::MAX),
        addr: "127.0.0.1:9735".to_string(),
        max_fee_rate_sat_per_vb: Some(u32::MAX),
        channel_open_intent_expiry_unix: Some(i64::MAX as u64),
        nonce: [0xCD; 16],
        state: InviteState::Opening,
        created_at: i64::MAX as u64,
        accepted_at: Some(i64::MAX as u64),
        revoked_at: None,
    };

    storage
        .add_invite_issued(&record)
        .await
        .expect("insert invite_issued row");

    let loaded = storage
        .find_invite_issued(&record.id)
        .await
        .expect("load invite_issued row")
        .expect("invite_issued row exists");

    assert_eq!(loaded, record);
}

#[tokio::test]
async fn invites_sqlite_find_rejects_invalid_blob_lengths() {
    let storage = SqliteStorage::in_memory().await.expect("sqlite in-memory");

    let id = uuid::Uuid::new_v4();
    let malformed_invitee_pubkey = vec![0x11; 31];

    sqlx::query(
        "INSERT INTO invites_issued \
         (id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.as_bytes().as_slice())
    .bind(malformed_invitee_pubkey)
    .bind(1_i64)
    .bind(None::<i64>)
    .bind("127.0.0.1:9735")
    .bind(None::<i64>)
    .bind(None::<i64>)
    .bind([0x22; 16].as_slice())
    .bind("pending")
    .bind(1_i64)
    .bind(None::<i64>)
    .bind(None::<i64>)
    .execute(storage.pool())
    .await
    .expect("insert malformed invite_issued row");

    let err = storage
        .find_invite_issued(&id)
        .await
        .expect_err("invalid invitee_pubkey length should fail conversion");

    match err {
        StorageError::Conversion(message) => {
            assert!(
                message.contains("invalid invites_issued.invitee_pubkey length"),
                "unexpected conversion message: {message}"
            );
        }
        other => panic!("unexpected error type: {other:?}"),
    }
}

#[tokio::test]
async fn accepted_invite_sqlite_round_trip_add_and_find() {
    let storage = SqliteStorage::in_memory()
        .await
        .expect("sqlite in-memory");

    let record = AcceptedInviteRecord {
        nonce: [0x11; 16],
        inviter_pubkey: [0x22; 32],
        expiry_unix: 1_900_000_000,
        accepted_at: 1_800_000_000,
    };

    storage
        .add_accepted_invite(&record)
        .await
        .expect("insert accepted_invite row");

    let loaded = storage
        .find_accepted_invite(&record.nonce)
        .await
        .expect("load accepted_invite row")
        .expect("accepted invite should exist");

    assert_eq!(loaded, record);
}
