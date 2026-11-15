//! Append-only recovery records for local call media attachments.

use crate::StorageError;
use konsensus_core::NodeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMediaDetach {
    pub peer: NodeId,
    pub call_id: String,
    pub generation: u64,
    pub only_unpaid: bool,
    pub may_hangup_live: bool,
    /// Whether the latest durable event records a teardown policy.
    pub has_stop_policy: bool,
}

pub(crate) type IntentRow = (i64, String, String, i32, i32, i32);

pub(crate) fn decode_intent(row: IntentRow) -> Result<PendingMediaDetach, StorageError> {
    Ok(PendingMediaDetach {
        generation: u64::try_from(row.0)
            .map_err(|_| StorageError::Conversion("invalid attachment generation".into()))?,
        peer: NodeId::from_hex(&row.1).map_err(|e| StorageError::Conversion(e.to_string()))?,
        call_id: row.2,
        only_unpaid: row.3 != 0,
        may_hangup_live: row.4 != 0,
        has_stop_policy: row.5 != 0,
    })
}

pub(crate) fn decode_intents(rows: Vec<IntentRow>) -> Vec<PendingMediaDetach> {
    rows.into_iter()
        .filter_map(|row| {
            let generation = row.0;
            match decode_intent(row) {
                Ok(intent) => Some(intent),
                Err(error) => {
                    tracing::warn!(generation, %error, "call media pending row unavailable");
                    None
                }
            }
        })
        .collect()
}
