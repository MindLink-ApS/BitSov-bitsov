//! Sender-side path-3 session ledger.
//!
//! Chat compose reserves the admission price against `blvm_on_chain_sessions`
//! and files the sequence in `blvm_pending_outbound_debits`. Peer ACK deletes
//! the pending row and keeps the spend. A terminal refusal, or a pending row
//! that is still unacked past the cutoff, puts the price back.

use konsensus_core::{MessageId, NodeId};
use sqlx::Row;

use crate::error::StorageError;

/// One open prepaid session for a recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlvmOutboundSession {
    pub recipient: NodeId,
    pub payment_request_id: String,
    pub tx_hash: [u8; 32],
    pub amount_sats: u64,
    pub debit_counter: u64,
    pub spent_msat: u64,
}

/// Sequence assigned to one outbound chat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlvmOutboundReservation {
    pub payment_request_id: String,
    pub tx_hash: [u8; 32],
    pub amount_sats: u64,
    pub session_debit_seq: u64,
}

/// What a sweep does with one old pending debit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleDebitAction {
    /// The peer already acknowledged. Drop the pending row and keep the spend.
    Commit,
    /// Never acknowledged. Return the price to the session.
    Rollback,
}

/// `acked` keeps the spend. Every other state, including no outbox row, releases it.
pub fn stale_action(outbox_state: Option<&str>) -> StaleDebitAction {
    if outbox_state == Some("acked") {
        StaleDebitAction::Commit
    } else {
        StaleDebitAction::Rollback
    }
}

pub(crate) fn as_i64(value: u64, what: &str) -> Result<i64, StorageError> {
    i64::try_from(value)
        .map_err(|_| StorageError::Conversion(format!("blvm {what} overflows i64")))
}

pub(crate) fn exhausted(required_msat: u64, remaining_msat: u64) -> StorageError {
    StorageError::Conversion(format!(
        "blvm session balance exhausted: need {required_msat} msat, {remaining_msat} remaining"
    ))
}

fn decode_hash(hex_hash: &str) -> Result<[u8; 32], StorageError> {
    let bytes = hex::decode(hex_hash).map_err(|e| StorageError::Conversion(e.to_string()))?;
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| StorageError::Conversion("blvm tx hash is not 32 bytes".into()))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn reservation_from(
    payment_request_id: String,
    tx_hash_hex: &str,
    amount_sats: i64,
    seq: i64,
) -> Result<BlvmOutboundReservation, StorageError> {
    Ok(BlvmOutboundReservation {
        payment_request_id,
        tx_hash: decode_hash(tx_hash_hex)?,
        amount_sats: u64::try_from(amount_sats)
            .map_err(|_| StorageError::Conversion("blvm amount_sats is negative".into()))?,
        session_debit_seq: u64::try_from(seq)
            .map_err(|_| StorageError::Conversion("blvm debit sequence is negative".into()))?,
    })
}

fn cap_or_exhausted(amount_sats: i64, spent_msat: i64, debit_msat: i64) -> Result<(), StorageError> {
    let cap = i128::from(amount_sats)
        .checked_mul(1000)
        .ok_or_else(|| StorageError::Conversion("blvm session amount overflows".into()))?;
    let next = i128::from(spent_msat) + i128::from(debit_msat);
    if debit_msat <= 0 || next > cap {
        let remaining = u64::try_from((cap - i128::from(spent_msat)).max(0)).unwrap_or(0);
        let required = u64::try_from(debit_msat).unwrap_or(u64::MAX);
        return Err(exhausted(required, remaining));
    }
    Ok(())
}

pub(crate) async fn upsert_sqlite(
    pool: &sqlx::SqlitePool,
    session: &BlvmOutboundSession,
) -> Result<(), StorageError> {
    let recipient = session.recipient.to_hex();
    refuse_open_session(
        count_sqlite(pool, &recipient).await?,
        spent_sqlite(pool, &recipient).await?,
    )?;
    sqlx::query(
        "INSERT INTO blvm_on_chain_sessions \
         (recipient_node_id, payment_request_id, tx_hash, amount_sats, debit_counter, spent_msat, opened_at_ms) \
         VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(recipient_node_id) DO UPDATE SET \
         payment_request_id = excluded.payment_request_id, tx_hash = excluded.tx_hash, \
         amount_sats = excluded.amount_sats, debit_counter = excluded.debit_counter, \
         spent_msat = excluded.spent_msat, opened_at_ms = excluded.opened_at_ms",
    )
    .bind(&recipient)
    .bind(&session.payment_request_id)
    .bind(hex::encode(session.tx_hash))
    .bind(as_i64(session.amount_sats, "amount_sats")?)
    .bind(as_i64(session.debit_counter, "debit_counter")?)
    .bind(as_i64(session.spent_msat, "spent_msat")?)
    .bind(now_ms().to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn reserve_sqlite(
    pool: &sqlx::SqlitePool,
    recipient: &NodeId,
    message_id: &MessageId,
    debit_msat: u64,
) -> Result<Option<BlvmOutboundReservation>, StorageError> {
    let recipient_hex = recipient.to_hex();
    let debit = as_i64(debit_msat, "debit_msat")?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT payment_request_id, tx_hash, amount_sats, debit_counter, spent_msat \
         FROM blvm_on_chain_sessions WHERE recipient_node_id = ?",
    )
    .bind(&recipient_hex)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    let payment_request_id: String = row.try_get(0)?;
    let tx_hash: String = row.try_get(1)?;
    let amount_sats: i64 = row.try_get(2)?;
    let seq: i64 = row.try_get(3)?;
    let spent: i64 = row.try_get(4)?;
    if let Err(e) = cap_or_exhausted(amount_sats, spent, debit) {
        tx.rollback().await?;
        return Err(e);
    }
    let updated = sqlx::query(
        "UPDATE blvm_on_chain_sessions SET debit_counter = debit_counter + 1, spent_msat = spent_msat + ? \
         WHERE recipient_node_id = ? AND debit_counter = ? AND spent_msat = ?",
    )
    .bind(debit)
    .bind(&recipient_hex)
    .bind(seq)
    .bind(spent)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated != 1 {
        tx.rollback().await?;
        return Err(StorageError::Conversion(
            "blvm outbound session changed during reserve".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO blvm_pending_outbound_debits \
         (message_id, recipient_node_id, payment_request_id, tx_hash, session_debit_seq, debit_msat, recorded_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(message_id.to_hex())
    .bind(&recipient_hex)
    .bind(&payment_request_id)
    .bind(&tx_hash)
    .bind(seq)
    .bind(debit)
    .bind(now_ms().to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(reservation_from(payment_request_id, &tx_hash, amount_sats, seq)?))
}

pub(crate) async fn commit_sqlite(
    pool: &sqlx::SqlitePool,
    message_id: &MessageId,
) -> Result<bool, StorageError> {
    let removed = sqlx::query("DELETE FROM blvm_pending_outbound_debits WHERE message_id = ?")
        .bind(message_id.to_hex())
        .execute(pool)
        .await?
        .rows_affected();
    Ok(removed == 1)
}

pub(crate) async fn rollback_sqlite(
    pool: &sqlx::SqlitePool,
    message_id: &MessageId,
) -> Result<bool, StorageError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT recipient_node_id, debit_msat FROM blvm_pending_outbound_debits WHERE message_id = ?",
    )
    .bind(message_id.to_hex())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    let recipient: String = row.try_get(0)?;
    let debit: i64 = row.try_get(1)?;
    let updated = sqlx::query(
        "UPDATE blvm_on_chain_sessions SET spent_msat = spent_msat - ? \
         WHERE recipient_node_id = ? AND spent_msat >= ?",
    )
    .bind(debit)
    .bind(&recipient)
    .bind(debit)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated != 1 {
        tx.rollback().await?;
        return Err(StorageError::Conversion(
            "blvm outbound debit does not match the session".into(),
        ));
    }
    sqlx::query("DELETE FROM blvm_pending_outbound_debits WHERE message_id = ?")
        .bind(message_id.to_hex())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

pub(crate) async fn rollback_stale_sqlite(
    pool: &sqlx::SqlitePool,
    older_than_ms: i64,
) -> Result<u64, StorageError> {
    let rows = sqlx::query(
        "SELECT message_id, recorded_at FROM blvm_pending_outbound_debits ORDER BY recorded_at LIMIT 100",
    )
    .fetch_all(pool)
    .await?;
    let mut rolled_back = 0u64;
    for row in rows {
        let message_id: String = row.try_get(0)?;
        let recorded_at: String = row.try_get(1)?;
        let recorded = recorded_at.parse::<i64>().unwrap_or(i64::MAX);
        if recorded >= older_than_ms {
            continue;
        }
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM outbox_operations WHERE message_id = ? LIMIT 1",
        )
        .bind(&message_id)
        .fetch_optional(pool)
        .await?;
        let id = MessageId::from_hex(&message_id)
            .map_err(|e| StorageError::Conversion(e.to_string()))?;
        match stale_action(state.as_deref()) {
            StaleDebitAction::Commit => {
                commit_sqlite(pool, &id).await?;
            }
            StaleDebitAction::Rollback => {
                if rollback_sqlite(pool, &id).await? {
                    rolled_back += 1;
                }
            }
        }
    }
    Ok(rolled_back)
}

pub(crate) async fn upsert_postgres(
    pool: &sqlx::PgPool,
    session: &BlvmOutboundSession,
) -> Result<(), StorageError> {
    let recipient = session.recipient.to_hex();
    refuse_open_session(
        count_postgres(pool, &recipient).await?,
        spent_postgres(pool, &recipient).await?,
    )?;
    sqlx::query(
        "INSERT INTO blvm_on_chain_sessions \
         (recipient_node_id, payment_request_id, tx_hash, amount_sats, debit_counter, spent_msat, opened_at_ms) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT(recipient_node_id) DO UPDATE SET \
         payment_request_id = excluded.payment_request_id, tx_hash = excluded.tx_hash, \
         amount_sats = excluded.amount_sats, debit_counter = excluded.debit_counter, \
         spent_msat = excluded.spent_msat, opened_at_ms = excluded.opened_at_ms",
    )
    .bind(&recipient)
    .bind(&session.payment_request_id)
    .bind(hex::encode(session.tx_hash))
    .bind(as_i64(session.amount_sats, "amount_sats")?)
    .bind(as_i64(session.debit_counter, "debit_counter")?)
    .bind(as_i64(session.spent_msat, "spent_msat")?)
    .bind(now_ms().to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn reserve_postgres(
    pool: &sqlx::PgPool,
    recipient: &NodeId,
    message_id: &MessageId,
    debit_msat: u64,
) -> Result<Option<BlvmOutboundReservation>, StorageError> {
    let recipient_hex = recipient.to_hex();
    let debit = as_i64(debit_msat, "debit_msat")?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT payment_request_id, tx_hash, amount_sats, debit_counter, spent_msat \
         FROM blvm_on_chain_sessions WHERE recipient_node_id = $1",
    )
    .bind(&recipient_hex)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    let payment_request_id: String = row.try_get(0)?;
    let tx_hash: String = row.try_get(1)?;
    // Postgres INTEGER is int4. The SQLite reader uses i64.
    let amount_sats = i64::from(row.try_get::<i32, _>(2)?);
    let seq = i64::from(row.try_get::<i32, _>(3)?);
    let spent = i64::from(row.try_get::<i32, _>(4)?);
    if let Err(e) = cap_or_exhausted(amount_sats, spent, debit) {
        tx.rollback().await?;
        return Err(e);
    }
    let updated = sqlx::query(
        "UPDATE blvm_on_chain_sessions SET debit_counter = debit_counter + 1, spent_msat = spent_msat + $1 \
         WHERE recipient_node_id = $2 AND debit_counter = $3 AND spent_msat = $4",
    )
    .bind(debit)
    .bind(&recipient_hex)
    .bind(seq)
    .bind(spent)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated != 1 {
        tx.rollback().await?;
        return Err(StorageError::Conversion(
            "blvm outbound session changed during reserve".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO blvm_pending_outbound_debits \
         (message_id, recipient_node_id, payment_request_id, tx_hash, session_debit_seq, debit_msat, recorded_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(message_id.to_hex())
    .bind(&recipient_hex)
    .bind(&payment_request_id)
    .bind(&tx_hash)
    .bind(seq)
    .bind(debit)
    .bind(now_ms().to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(reservation_from(payment_request_id, &tx_hash, amount_sats, seq)?))
}

pub(crate) async fn commit_postgres(
    pool: &sqlx::PgPool,
    message_id: &MessageId,
) -> Result<bool, StorageError> {
    let removed = sqlx::query("DELETE FROM blvm_pending_outbound_debits WHERE message_id = $1")
        .bind(message_id.to_hex())
        .execute(pool)
        .await?
        .rows_affected();
    Ok(removed == 1)
}

pub(crate) async fn rollback_postgres(
    pool: &sqlx::PgPool,
    message_id: &MessageId,
) -> Result<bool, StorageError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT recipient_node_id, debit_msat FROM blvm_pending_outbound_debits WHERE message_id = $1",
    )
    .bind(message_id.to_hex())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    let recipient: String = row.try_get(0)?;
    let debit = i64::from(row.try_get::<i32, _>(1)?);
    let updated = sqlx::query(
        "UPDATE blvm_on_chain_sessions SET spent_msat = spent_msat - $1 \
         WHERE recipient_node_id = $2 AND spent_msat >= $3",
    )
    .bind(debit)
    .bind(&recipient)
    .bind(debit)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated != 1 {
        tx.rollback().await?;
        return Err(StorageError::Conversion(
            "blvm outbound debit does not match the session".into(),
        ));
    }
    sqlx::query("DELETE FROM blvm_pending_outbound_debits WHERE message_id = $1")
        .bind(message_id.to_hex())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

pub(crate) async fn rollback_stale_postgres(
    pool: &sqlx::PgPool,
    older_than_ms: i64,
) -> Result<u64, StorageError> {
    let rows = sqlx::query(
        "SELECT message_id, recorded_at FROM blvm_pending_outbound_debits ORDER BY recorded_at LIMIT 100",
    )
    .fetch_all(pool)
    .await?;
    let mut rolled_back = 0u64;
    for row in rows {
        let message_id: String = row.try_get(0)?;
        let recorded_at: String = row.try_get(1)?;
        let recorded = recorded_at.parse::<i64>().unwrap_or(i64::MAX);
        if recorded >= older_than_ms {
            continue;
        }
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM outbox_operations WHERE message_id = $1 LIMIT 1",
        )
        .bind(&message_id)
        .fetch_optional(pool)
        .await?;
        let id = MessageId::from_hex(&message_id)
            .map_err(|e| StorageError::Conversion(e.to_string()))?;
        match stale_action(state.as_deref()) {
            StaleDebitAction::Commit => {
                commit_postgres(pool, &id).await?;
            }
            StaleDebitAction::Rollback => {
                if rollback_postgres(pool, &id).await? {
                    rolled_back += 1;
                }
            }
        }
    }
    Ok(rolled_back)
}

pub(crate) async fn get_sqlite(
    pool: &sqlx::SqlitePool,
    recipient: &NodeId,
) -> Result<Option<BlvmOutboundSession>, StorageError> {
    let row = sqlx::query(
        "SELECT payment_request_id, tx_hash, amount_sats, debit_counter, spent_msat \
         FROM blvm_on_chain_sessions WHERE recipient_node_id = ?",
    )
    .bind(recipient.to_hex())
    .fetch_optional(pool)
    .await?;
    match row {
        None => Ok(None),
        Some(row) => session_from_parts(
            recipient,
            row.try_get(0)?,
            row.try_get(1)?,
            row.try_get(2)?,
            row.try_get(3)?,
            row.try_get(4)?,
        ),
    }
}

pub(crate) async fn delete_sqlite(
    pool: &sqlx::SqlitePool,
    recipient: &NodeId,
) -> Result<bool, StorageError> {
    let recipient_hex = recipient.to_hex();
    let mut tx = pool.begin().await?;
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT spent_msat FROM blvm_on_chain_sessions WHERE recipient_node_id = ?",
    )
    .bind(&recipient_hex)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(spent) = exists else {
        tx.rollback().await?;
        return Ok(false);
    };
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM blvm_pending_outbound_debits WHERE recipient_node_id = ?",
    )
    .bind(&recipient_hex)
    .fetch_one(&mut *tx)
    .await?;
    if spent > 0 || pending > 0 {
        tx.rollback().await?;
        return Err(StorageError::Conversion(
            "blvm outbound session already spending".into(),
        ));
    }
    sqlx::query("DELETE FROM blvm_on_chain_sessions WHERE recipient_node_id = ?")
        .bind(&recipient_hex)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

pub(crate) async fn get_postgres(
    pool: &sqlx::PgPool,
    recipient: &NodeId,
) -> Result<Option<BlvmOutboundSession>, StorageError> {
    let row = sqlx::query(
        "SELECT payment_request_id, tx_hash, amount_sats, debit_counter, spent_msat \
         FROM blvm_on_chain_sessions WHERE recipient_node_id = $1",
    )
    .bind(recipient.to_hex())
    .fetch_optional(pool)
    .await?;
    match row {
        None => Ok(None),
        Some(row) => session_from_parts(
            recipient,
            row.try_get(0)?,
            row.try_get(1)?,
            i64::from(row.try_get::<i32, _>(2)?),
            i64::from(row.try_get::<i32, _>(3)?),
            i64::from(row.try_get::<i32, _>(4)?),
        ),
    }
}

pub(crate) async fn delete_postgres(
    pool: &sqlx::PgPool,
    recipient: &NodeId,
) -> Result<bool, StorageError> {
    let recipient_hex = recipient.to_hex();
    let mut tx = pool.begin().await?;
    let exists: Option<i32> = sqlx::query_scalar(
        "SELECT spent_msat FROM blvm_on_chain_sessions WHERE recipient_node_id = $1",
    )
    .bind(&recipient_hex)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(spent) = exists else {
        tx.rollback().await?;
        return Ok(false);
    };
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM blvm_pending_outbound_debits WHERE recipient_node_id = $1",
    )
    .bind(&recipient_hex)
    .fetch_one(&mut *tx)
    .await?;
    if spent > 0 || pending > 0 {
        tx.rollback().await?;
        return Err(StorageError::Conversion(
            "blvm outbound session already spending".into(),
        ));
    }
    sqlx::query("DELETE FROM blvm_on_chain_sessions WHERE recipient_node_id = $1")
        .bind(&recipient_hex)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

fn session_from_parts(
    recipient: &NodeId,
    payment_request_id: String,
    tx_hash_hex: String,
    amount_sats: i64,
    debit_counter: i64,
    spent_msat: i64,
) -> Result<Option<BlvmOutboundSession>, StorageError> {
    let tx_hash = decode_hash(&tx_hash_hex)?;
    Ok(Some(BlvmOutboundSession {
        recipient: *recipient,
        payment_request_id,
        tx_hash,
        amount_sats: u64::try_from(amount_sats)
            .map_err(|_| StorageError::Conversion("blvm amount_sats is negative".into()))?,
        debit_counter: u64::try_from(debit_counter)
            .map_err(|_| StorageError::Conversion("blvm debit sequence is negative".into()))?,
        spent_msat: u64::try_from(spent_msat)
            .map_err(|_| StorageError::Conversion("blvm spent_msat is negative".into()))?,
    }))
}

fn refuse_open_session(pending: i64, spent_msat: Option<i64>) -> Result<(), StorageError> {
    if pending > 0 {
        return Err(StorageError::Conversion(
            "blvm outbound session has pending debits".into(),
        ));
    }
    if spent_msat.unwrap_or(0) > 0 {
        return Err(StorageError::Conversion(
            "blvm outbound session already spending".into(),
        ));
    }
    Ok(())
}

async fn count_sqlite(pool: &sqlx::SqlitePool, recipient: &str) -> Result<i64, StorageError> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM blvm_pending_outbound_debits WHERE recipient_node_id = ?",
    )
    .bind(recipient)
    .fetch_one(pool)
    .await?)
}

async fn spent_sqlite(pool: &sqlx::SqlitePool, recipient: &str) -> Result<Option<i64>, StorageError> {
    Ok(sqlx::query_scalar(
        "SELECT spent_msat FROM blvm_on_chain_sessions WHERE recipient_node_id = ?",
    )
    .bind(recipient)
    .fetch_optional(pool)
    .await?)
}

async fn count_postgres(pool: &sqlx::PgPool, recipient: &str) -> Result<i64, StorageError> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM blvm_pending_outbound_debits WHERE recipient_node_id = $1",
    )
    .bind(recipient)
    .fetch_one(pool)
    .await?)
}

async fn spent_postgres(pool: &sqlx::PgPool, recipient: &str) -> Result<Option<i64>, StorageError> {
    let spent: Option<i32> = sqlx::query_scalar(
        "SELECT spent_msat FROM blvm_on_chain_sessions WHERE recipient_node_id = $1",
    )
    .bind(recipient)
    .fetch_optional(pool)
    .await?;
    Ok(spent.map(i64::from))
}
