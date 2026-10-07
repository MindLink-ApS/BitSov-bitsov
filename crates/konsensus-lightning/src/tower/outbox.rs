//! Durable per-tower deliveries. SQLite transactions/triggers keep the hard
//! pending-state counter atomic with inserts, acknowledgements and pruning.
use super::blob::SealedBlob;
use konsensus_core::tower::{TowerChannelStatus, TowerDeliveryStatus};
use ldk_node::tower_hook::JusticeCandidate;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{io, path::Path, sync::Mutex};

pub const MAX_PENDING_PER_CHANNEL: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Queued,
    Sent,
    Acked,
    Expired,
}

#[derive(Clone, Debug)]
pub struct Delivery {
    pub channel_id: String,
    pub breach_txid: String,
    pub blob: SealedBlob,
    pub state: DeliveryState,
}

pub struct Outbox {
    db: Mutex<Connection>,
}
fn storage(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

pub fn candidate_key(candidate: &JusticeCandidate) -> io::Result<String> {
    let first = candidate
        .ladder
        .first()
        .and_then(|t| t.input.first())
        .ok_or_else(|| storage("empty tower candidate"))?;
    if candidate.ladder.iter().any(|tx| {
        tx.input.len() != 1
            || tx.input[0].witness.is_empty()
            || tx.input[0].previous_output != first.previous_output
    }) {
        return Err(storage("invalid signed tower ladder"));
    }
    Ok(first.previous_output.txid.to_string())
}

impl Outbox {
    pub fn open(path: &Path) -> io::Result<Self> {
        let db = Connection::open(path).map_err(storage)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        db.execute_batch(&format!("
            PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS counters(channel TEXT PRIMARY KEY, pending INTEGER NOT NULL CHECK(pending >= 0));
            CREATE TABLE IF NOT EXISTS states(channel TEXT NOT NULL, txid TEXT NOT NULL, blob BLOB,
                pending INTEGER NOT NULL CHECK(pending IN (0,1)), PRIMARY KEY(channel,txid));
            CREATE TABLE IF NOT EXISTS deliveries(channel TEXT NOT NULL, txid TEXT NOT NULL, tower TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('queued','sent','acked','expired')),
                PRIMARY KEY(channel,txid,tower), FOREIGN KEY(channel,txid) REFERENCES states ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS delivery_work ON deliveries(tower,state,channel,txid);
            CREATE TRIGGER IF NOT EXISTS state_limit BEFORE INSERT ON states WHEN NEW.pending=1 BEGIN
                SELECT RAISE(ABORT, 'tower outbox hard limit reached') WHERE
                    COALESCE((SELECT pending FROM counters WHERE channel=NEW.channel),0) >= {MAX_PENDING_PER_CHANNEL};
            END;
            CREATE TRIGGER IF NOT EXISTS state_limit_update BEFORE UPDATE OF pending ON states WHEN OLD.pending=0 AND NEW.pending=1 BEGIN
                SELECT RAISE(ABORT, 'tower outbox hard limit reached') WHERE
                    COALESCE((SELECT pending FROM counters WHERE channel=NEW.channel),0) >= {MAX_PENDING_PER_CHANNEL};
            END;
            CREATE TRIGGER IF NOT EXISTS state_insert AFTER INSERT ON states BEGIN
                INSERT INTO counters VALUES(NEW.channel,NEW.pending)
                ON CONFLICT(channel) DO UPDATE SET pending=pending+NEW.pending;
            END;
            CREATE TRIGGER IF NOT EXISTS state_delete AFTER DELETE ON states BEGIN
                UPDATE counters SET pending=pending-OLD.pending WHERE channel=OLD.channel;
            END;
            CREATE TRIGGER IF NOT EXISTS state_update AFTER UPDATE OF pending ON states BEGIN
                UPDATE counters SET pending=pending+NEW.pending-OLD.pending WHERE channel=NEW.channel;
            END;
        ")).map_err(storage)?;
        Ok(Self { db: Mutex::new(db) })
    }

    /// Idempotent per full txid, never per truncated hint. New configured towers
    /// receive candidates still held by W1; previously acked/expired rows never reset.
    /// False means no eligible tower. The W1 source remains untouched in all cases.
    pub fn enqueue(
        &self,
        candidate: &JusticeCandidate,
        counterparty: &str,
        towers: &[String],
    ) -> io::Result<bool> {
        let eligible: std::collections::BTreeSet<_> = towers
            .iter()
            .filter(|t| t.as_str() != counterparty)
            .collect();
        if eligible.is_empty() {
            return Ok(false);
        }
        let key = candidate_key(candidate)?;
        let channel = candidate.channel_id.to_string();
        let mut db = self.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
        let exists = tx
            .query_row(
                "SELECT 1 FROM states WHERE channel=?1 AND txid=?2",
                params![channel, key],
                |_| Ok(()),
            )
            .optional()
            .map_err(storage)?
            .is_some();
        let mut missing = Vec::new();
        for tower in eligible {
            if tx
                .query_row(
                    "SELECT 1 FROM deliveries WHERE channel=?1 AND txid=?2 AND tower=?3",
                    params![channel, key, tower],
                    |_| Ok(()),
                )
                .optional()
                .map_err(storage)?
                .is_none()
            {
                missing.push(tower);
            }
        }
        if missing.is_empty() {
            return Ok(true);
        }
        let blob = SealedBlob::encrypt(
            candidate.ladder[0].input[0].previous_output.txid,
            &candidate.ladder,
        )?;
        let bytes = serde_json::to_vec(&blob).map_err(storage)?;
        if exists {
            tx.execute(
                "UPDATE states SET blob=COALESCE(blob,?3),pending=1 WHERE channel=?1 AND txid=?2",
                params![channel, key, bytes],
            )
            .map_err(storage)?;
        } else {
            tx.execute(
                "INSERT INTO states VALUES(?1,?2,?3,1)",
                params![channel, key, bytes],
            )
            .map_err(storage)?;
        }
        for tower in missing {
            tx.execute(
                "INSERT INTO deliveries VALUES(?1,?2,?3,'queued')",
                params![channel, key, tower],
            )
            .map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(true)
    }

    pub fn pending_count(&self, channel: &str) -> io::Result<usize> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT pending FROM counters WHERE channel=?1",
                [channel],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?
            .unwrap_or(0))
    }

    pub fn contains(&self, channel: &str, key: &str) -> io::Result<bool> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT 1 FROM states WHERE channel=?1 AND txid=?2",
                params![channel, key],
                |_| Ok(()),
            )
            .optional()
            .map_err(storage)?
            .is_some())
    }

    /// Sent rows remain retryable after restart; only acked rows leave this view.
    pub fn deliveries(&self, tower: &str, limit: usize) -> io::Result<Vec<Delivery>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT d.channel,d.txid,s.blob,d.state FROM deliveries d JOIN states s USING(channel,txid)
            WHERE d.tower=?1 AND d.state IN ('queued','sent') ORDER BY d.channel,d.txid LIMIT ?2").map_err(storage)?;
        let rows = stmt
            .query_map(params![tower, limit.min(1000)], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(storage)?;
        rows.map(|r| {
            let (channel_id, breach_txid, bytes, state) = r.map_err(storage)?;
            Ok(Delivery {
                channel_id,
                breach_txid,
                blob: serde_json::from_slice(&bytes).map_err(storage)?,
                state: if state == "queued" {
                    DeliveryState::Queued
                } else {
                    DeliveryState::Sent
                },
            })
        })
        .collect()
    }

    /// TODO(W2b): invoke only from the authenticated transport send path.
    pub fn mark_sent(&self, channel: &str, key: &str, tower: &str) -> io::Result<()> {
        let db = self.db.lock().unwrap();
        let n = db.execute("UPDATE deliveries SET state='sent' WHERE channel=?1 AND txid=?2 AND tower=?3 AND state IN ('queued','sent')", params![channel,key,tower]).map_err(storage)?;
        if n == 0 {
            return Err(storage("unknown or non-pending tower delivery"));
        }
        Ok(())
    }

    /// TODO(W2b): validate tower identity/session/sequence before calling. There
    /// is intentionally no HTTP mutation route or caller manufacturing acks in W2a.
    pub fn ack(&self, channel: &str, key: &str, tower: &str) -> io::Result<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
        let n = tx.execute("UPDATE deliveries SET state='acked' WHERE channel=?1 AND txid=?2 AND tower=?3 AND state IN ('sent','acked')", params![channel,key,tower]).map_err(storage)?;
        if n == 0 {
            return Err(storage("ack without a sent tower delivery"));
        }
        tx.execute(
            "UPDATE states SET pending=0,blob=NULL WHERE channel=?1 AND txid=?2 AND NOT EXISTS
            (SELECT 1 FROM deliveries WHERE channel=?1 AND txid=?2 AND state IN ('queued','sent'))",
            params![channel, key],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    pub fn fully_acked(&self, channel: &str, key: &str) -> io::Result<bool> {
        self.db.lock().unwrap().query_row("SELECT COUNT(*)>0 AND SUM(state!='acked')=0 FROM deliveries WHERE channel=?1 AND txid=?2", params![channel,key], |r| r.get(0)).map_err(storage)
    }

    /// Startup config reconciliation: removed towers no longer count as guards.
    /// New towers are populated by enqueue while W1 still holds the source.
    /// TODO(W2b): backfill historical already-drained states into new sessions.
    pub fn retain_towers(&self, configured: &[String]) -> io::Result<()> {
        let old: Vec<String> = {
            let db = self.db.lock().unwrap();
            let mut stmt = db
                .prepare("SELECT DISTINCT tower FROM deliveries")
                .map_err(storage)?;
            let rows = stmt.query_map([], |r| r.get(0)).map_err(storage)?;
            rows.collect::<Result<_, _>>().map_err(storage)?
        };
        for tower in old {
            if !configured.contains(&tower) {
                let mut db = self.db.lock().unwrap();
                let tx = db
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(storage)?;
                // Configuration removal is not paid-session expiry. Drop the old
                // obligation, so re-adding this peer can queue a retained W1 source.
                tx.execute("DELETE FROM deliveries WHERE tower=?1", [&tower])
                    .map_err(storage)?;
                tx.execute("UPDATE states SET pending=0,blob=NULL WHERE NOT EXISTS
                    (SELECT 1 FROM deliveries d WHERE d.channel=states.channel AND d.txid=states.txid AND d.state IN ('queued','sent'))", []).map_err(storage)?;
                tx.commit().map_err(storage)?;
            }
        }
        Ok(())
    }

    /// Explicit service expiry, never commitment age. Ack receipts cease to
    /// count as guarding; compact state metadata remains to report lost coverage.
    /// TODO(W2b): scope to authenticated sessions and apply paid-period + grace.
    pub fn expire_tower(&self, tower: &str) -> io::Result<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            "UPDATE deliveries SET state='expired' WHERE tower=?1",
            [tower],
        )
        .map_err(storage)?;
        tx.execute("UPDATE states SET pending=0,blob=NULL WHERE NOT EXISTS
            (SELECT 1 FROM deliveries d WHERE d.channel=states.channel AND d.txid=states.txid AND d.state IN ('queued','sent'))", []).map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// Caller must supply confirmed/resolved closure proof (runtime uses LDK archive).
    /// TODO(W2b): durably enqueue remote deletes before pruning local receipts.
    pub fn prune_closed_channel(&self, channel: &str) -> io::Result<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage)?;
        tx.execute("DELETE FROM states WHERE channel=?1", [channel])
            .map_err(storage)?;
        tx.execute("DELETE FROM counters WHERE channel=?1", [channel])
            .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    pub fn channel_status(&self, channel: &str) -> io::Result<TowerChannelStatus> {
        let db = self.db.lock().unwrap();
        let (total_states, guarded_states): (usize,usize) = db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(EXISTS(SELECT 1 FROM deliveries d WHERE d.channel=s.channel AND d.txid=s.txid AND state='acked')),0)
             FROM states s WHERE s.channel=?1", [channel], |r| Ok((r.get(0)?,r.get(1)?))).map_err(storage)?;
        let mut stmt = db.prepare("SELECT tower,SUM(state='queued'),SUM(state='sent'),SUM(state='acked'),SUM(state='expired') FROM deliveries WHERE channel=?1 GROUP BY tower ORDER BY tower").map_err(storage)?;
        let towers = stmt
            .query_map([channel], |r| {
                Ok(TowerDeliveryStatus {
                    node_id: r.get(0)?,
                    queued: r.get(1)?,
                    sent: r.get(2)?,
                    acked: r.get(3)?,
                    expired: r.get(4)?,
                })
            })
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        Ok(TowerChannelStatus {
            channel_id: channel.into(),
            total_states,
            guarded_states,
            unguarded_states: total_states - guarded_states,
            towers,
            ..Default::default()
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bitcoin::{
        absolute, hashes::Hash, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
        TxIn, TxOut, Txid, Witness,
    };
    use ldk_node::lightning::ln::types::ChannelId;

    pub(crate) fn candidate(n: u8) -> JusticeCandidate {
        JusticeCandidate {
            channel_id: ChannelId([1; 32]),
            commitment_number: n as u64,
            value: 10_000,
            ladder: vec![Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([n; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::from_slice(&[&[1u8]]),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(9_000),
                    script_pubkey: ScriptBuf::new(),
                }],
            }],
        }
    }

    #[test]
    fn tower_outbox_restart_only_ack_drains_and_counterparty_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.sqlite");
        let c = candidate(2);
        let channel = c.channel_id.to_string();
        let key = candidate_key(&c).unwrap();
        let out = Outbox::open(&path).unwrap();
        out.enqueue(&c, "peer", &["peer".into(), "a".into(), "b".into()])
            .unwrap();
        assert!(out.deliveries("peer", 10).unwrap().is_empty());
        assert_eq!(out.pending_count(&channel).unwrap(), 1);
        assert!(out.ack(&channel, &key, "a").is_err()); // unsolicited ack
        out.mark_sent(&channel, &key, "a").unwrap();
        drop(out);
        let out = Outbox::open(&path).unwrap();
        assert_eq!(
            out.deliveries("a", 10).unwrap()[0].state,
            DeliveryState::Sent
        );
        assert!(!out.fully_acked(&channel, &key).unwrap());
        out.ack(&channel, &key, "a").unwrap();
        assert_eq!(out.pending_count(&channel).unwrap(), 1);
        let s = out.channel_status(&channel).unwrap();
        assert_eq!((s.guarded_states, s.unguarded_states), (1, 0));
        out.mark_sent(&channel, &key, "b").unwrap();
        out.ack(&channel, &key, "b").unwrap();
        out.ack(&channel, &key, "b").unwrap();
        assert!(out.fully_acked(&channel, &key).unwrap());
        assert_eq!(out.pending_count(&channel).unwrap(), 0);
        out.enqueue(&c, "peer", &["a".into(), "b".into()]).unwrap();
        assert_eq!(out.pending_count(&channel).unwrap(), 0);
        assert!(out.deliveries("a", 10).unwrap().is_empty());
    }

    #[test]
    fn tower_outbox_hard_limit_atomic_restart_expiry_and_close() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.sqlite");
        let out = Outbox::open(&path).unwrap();
        let c = candidate(2);
        let channel = c.channel_id.to_string();
        out.enqueue(&c, "peer", &["a".into()]).unwrap();
        // Seed the production bound through the same insert trigger (no crypto needed).
        {
            let db = out.db.lock().unwrap();
            for n in 1..MAX_PENDING_PER_CHANNEL {
                db.execute(
                    "INSERT INTO states(channel, txid, blob, pending) VALUES (?1, ?2, NULL, 1)",
                    params![channel, format!("fixture-{n}")],
                )
                .unwrap();
            }
        }
        assert!(out.enqueue(&candidate(3), "peer", &["a".into()]).is_err());
        assert_eq!(
            out.pending_count(&channel).unwrap(),
            MAX_PENDING_PER_CHANNEL
        );
        drop(out);
        let out = Outbox::open(&path).unwrap();
        assert!(out.enqueue(&candidate(3), "peer", &["a".into()]).is_err());
        // Expiry is explicit service expiry, never age of a commitment/blob.
        out.expire_tower("a").unwrap();
        assert!(!out
            .fully_acked(&channel, &candidate_key(&c).unwrap())
            .unwrap());
        assert_eq!(out.channel_status(&channel).unwrap().guarded_states, 0);
        out.prune_closed_channel(&channel).unwrap();
        assert_eq!(out.pending_count(&channel).unwrap(), 0);
        assert_eq!(out.channel_status(&channel).unwrap().total_states, 0);
    }

    #[test]
    fn tower_outbox_expiry_before_last_ack_frees_capacity_and_config_change_requeues() {
        let dir = tempfile::tempdir().unwrap();
        let out = Outbox::open(&dir.path().join("outbox.sqlite")).unwrap();
        let c = candidate(2);
        let channel = c.channel_id.to_string();
        let key = candidate_key(&c).unwrap();
        out.enqueue(&c, "peer", &["a".into(), "b".into()]).unwrap();
        out.mark_sent(&channel, &key, "a").unwrap();
        out.mark_sent(&channel, &key, "b").unwrap();
        out.expire_tower("a").unwrap();
        out.ack(&channel, &key, "b").unwrap();
        assert_eq!(out.pending_count(&channel).unwrap(), 0);
        assert!(!out.fully_acked(&channel, &key).unwrap());
        let blob: Option<Vec<u8>> = out
            .db
            .lock()
            .unwrap()
            .query_row("SELECT blob FROM states", [], |r| r.get(0))
            .unwrap();
        assert!(blob.is_none());
        // Replace B by C; old receipts cannot claim active coverage.
        out.retain_towers(&["c".into()]).unwrap();
        out.enqueue(&c, "peer", &["c".into()]).unwrap();
        assert_eq!(out.channel_status(&channel).unwrap().guarded_states, 0);
        assert_eq!(out.deliveries("c", 10).unwrap().len(), 1);
        assert_eq!(out.pending_count(&channel).unwrap(), 1);
        out.mark_sent(&channel, &key, "c").unwrap();
        out.ack(&channel, &key, "c").unwrap();
        assert!(out.fully_acked(&channel, &key).unwrap());
        // Configuration A -> B -> A is not a service-expiry tombstone.
        out.retain_towers(&["a".into()]).unwrap();
        out.enqueue(&c, "peer", &["a".into()]).unwrap();
        assert_eq!(out.deliveries("a", 10).unwrap().len(), 1);
    }

    #[test]
    fn tower_outbox_only_counterparty_has_no_guard_or_drain() {
        let dir = tempfile::tempdir().unwrap();
        let out = Outbox::open(&dir.path().join("outbox.sqlite")).unwrap();
        let c = candidate(2);
        assert!(!out.enqueue(&c, "peer", &["peer".into()]).unwrap());
        assert!(!out
            .fully_acked(&c.channel_id.to_string(), &candidate_key(&c).unwrap())
            .unwrap());
    }
}
