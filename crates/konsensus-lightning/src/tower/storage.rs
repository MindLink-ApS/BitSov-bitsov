//! Blind, bounded service store. No node/channel identities or amounts enter here.
use super::{
    blob::{SealedBlob, MAX_BLOB_BYTES},
    server::ServiceConfig,
};
use konsensus_core::tower::TowerServeStatus;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub const GRACE_SECONDS: u64 = 7 * 24 * 3600;
const RESERVE: u64 = 256 * 1024;
const ROW_BUDGET: u64 = 32 * 1024;
const SESSION_BUDGET: u64 = 16 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Chain(#[from] konsensus_core::traits::chain::ChainError),
    #[error("{0}")]
    Rejected(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;
type ExistingBlob = (u64, Vec<u8>, Vec<u8>, Option<String>);

pub struct TowerStorage {
    pub(super) db: Connection,
    config: ServiceConfig,
}
pub(super) struct Record {
    pub id: i64,
    pub blob: SealedBlob,
    pub breach: Option<String>,
    pub height: Option<u64>,
    pub hash: Option<String>,
}
fn record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    let hint: Vec<u8> = row.get(1)?;
    let nonce: Vec<u8> = row.get(2)?;
    Ok(Record {
        id: row.get(0)?,
        blob: SealedBlob {
            hint: hint.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
            nonce: nonce
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            ciphertext: row.get(3)?,
        },
        breach: row.get(4)?,
        height: row.get(5)?,
        hash: row.get(6)?,
    })
}
impl TowerStorage {
    pub fn open(path: &Path, config: &ServiceConfig) -> Result<Self> {
        config.validate()?;
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        // Rollback journal (not an unbounded WAL). Reserve journal record/header
        // overhead as well as its page images within the total disk ceiling.
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA auto_vacuum=INCREMENTAL;
            CREATE TABLE IF NOT EXISTS sessions(id BLOB PRIMARY KEY CHECK(length(id)=32), retention INTEGER NOT NULL, arrivals TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS blobs(id INTEGER PRIMARY KEY, session BLOB NOT NULL REFERENCES sessions(id), hint BLOB NOT NULL CHECK(length(hint)=16), seq INTEGER NOT NULL, nonce BLOB NOT NULL CHECK(length(nonce)=24), cipher BLOB NOT NULL CHECK(length(cipher)<=4072), received INTEGER NOT NULL,
                breach TEXT, height INTEGER, hash TEXT, confirmed INTEGER, fired INTEGER, UNIQUE(session,hint));
            CREATE INDEX IF NOT EXISTS hints ON blobs(hint);
            CREATE INDEX IF NOT EXISTS fired ON blobs(breach) WHERE breach IS NOT NULL;
            CREATE TABLE IF NOT EXISTS broadcasts(txid TEXT PRIMARY KEY, breach TEXT NOT NULL, tier INTEGER NOT NULL, height INTEGER NOT NULL, sent INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS scan(id INTEGER PRIMARY KEY CHECK(id=1), start INTEGER NOT NULL, height INTEGER NOT NULL, hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS totals(id INTEGER PRIMARY KEY CHECK(id=1), seen INTEGER NOT NULL, broadcast INTEGER NOT NULL);
            INSERT OR IGNORE INTO totals VALUES(1,0,0);")?;
        let page_size: u64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let pages = (config.max_storage_mb * 1024 * 1024 - 64 * 1024) / (2 * (page_size + 8));
        let current: u64 = db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        if current > pages {
            return Err(Error::Rejected("tower storage exceeds configured disk cap"));
        }
        db.pragma_update(None, "max_page_count", pages)?;
        Ok(Self {
            db,
            config: config.clone(),
        })
    }
    fn charged(&self) -> Result<u64> {
        Ok(self.db.query_row(
            "SELECT (SELECT count(*) FROM blobs)*?1+(SELECT count(*) FROM sessions)*?2",
            params![ROW_BUDGET, SESSION_BUDGET],
            |r| r.get(0),
        )?)
    }
    fn quota(&self) -> u64 {
        self.config.max_storage_mb * 1024 * 1024 / 2 - RESERVE
    }

    /// Internal admission only. TODO(W3b): settled-credit admission, Noise sessions,
    /// KIND_TOWER_* and 402 policy. No production route invokes this API in W3a.
    /// TODO(W3b): transport must enforce 10 sessions/IP/hour and 100 handshakes/IP/min.
    #[allow(dead_code)]
    pub(crate) fn accept(
        &mut self,
        session: [u8; 32],
        seq: u64,
        blob: &SealedBlob,
        now: u64,
        retention_until: u64,
    ) -> Result<()> {
        if blob.ciphertext.len() + 24 > MAX_BLOB_BYTES
            || blob.ciphertext.len() < 16
            || seq > i64::MAX as u64
            || retention_until > i64::MAX as u64 - GRACE_SECONDS
            || now > i64::MAX as u64
            || now >= retention_until.saturating_add(GRACE_SECONDS)
        {
            return Err(Error::Rejected("invalid tower blob or retention"));
        }
        if self.status()?.full {
            return Err(Error::Rejected("tower_full"));
        }
        let quota = self.quota();
        let charged = self.charged()?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let arrivals: Option<String> = tx
            .query_row(
                "SELECT arrivals FROM sessions WHERE id=?1",
                [session.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let new_session = arrivals.is_none();
        let mut arrivals: Vec<u64> = serde_json::from_str(arrivals.as_deref().unwrap_or("[]"))?;
        arrivals.retain(|t| t.saturating_add(3600) > now);
        if arrivals.len() >= 600 {
            return Err(Error::Rejected("tower session blob rate exceeded"));
        }
        let existing: Option<ExistingBlob> = tx
            .query_row(
                "SELECT seq,nonce,cipher,breach FROM blobs WHERE session=?1 AND hint=?2",
                params![session.as_slice(), blob.hint.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        if let Some((old, nonce, cipher, breach)) = &existing {
            if seq < *old
                || ((seq == *old || breach.is_some())
                    && (nonce != &blob.nonce || cipher != &blob.ciphertext))
            {
                return Err(Error::Rejected("stale or fired tower update"));
            }
        }
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM blobs WHERE session=?1",
            [session.as_slice()],
            |r| r.get(0),
        )?;
        if existing.is_none() && count >= self.config.max_blobs_per_session {
            return Err(Error::Rejected("tower session blob cap reached"));
        }
        let extra = if existing.is_none() { ROW_BUDGET } else { 0 }
            + if new_session { SESSION_BUDGET } else { 0 };
        if charged + extra > quota {
            return Err(Error::Rejected("tower_full"));
        }
        arrivals.push(now);
        tx.execute("INSERT INTO sessions VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET retention=max(retention,excluded.retention),arrivals=excluded.arrivals",params![session.as_slice(),retention_until,serde_json::to_string(&arrivals)?])?;
        tx.execute("INSERT INTO blobs(session,hint,seq,nonce,cipher,received) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(session,hint) DO UPDATE SET seq=excluded.seq,nonce=excluded.nonce,cipher=excluded.cipher,received=excluded.received",params![session.as_slice(),blob.hint.as_slice(),seq,blob.nonce.as_slice(),blob.ciphertext,now])?;
        tx.commit()?;
        Ok(())
    }
    #[allow(dead_code)]
    pub(crate) fn delete(&mut self, session: [u8; 32], hints: &[[u8; 16]]) -> Result<()> {
        let tx = self.db.transaction()?;
        for hint in hints {
            tx.execute(
                "DELETE FROM blobs WHERE session=?1 AND hint=?2",
                params![session.as_slice(), hint.as_slice()],
            )?;
        }
        // Keep bounded rate history after delete; delete/reinsert cannot reset admission.
        tx.commit()?;
        self.cleanup()?;
        Ok(())
    }
    pub(super) fn prune(&mut self, now: u64, height: u64) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM blobs WHERE session IN (SELECT id FROM sessions WHERE retention+?1<=?2) OR (height IS NOT NULL AND fired IS NOT NULL AND fired+1000<=?3)",params![GRACE_SECONDS,now,height])?;
        tx.execute(
            "DELETE FROM sessions WHERE id NOT IN (SELECT session FROM blobs) AND retention+?1<=?2",
            params![GRACE_SECONDS, now],
        )?;
        tx.commit()?;
        self.cleanup()?;
        Ok(())
    }
    fn cleanup(&self) -> Result<()> {
        self.db.execute("DELETE FROM broadcasts WHERE breach NOT IN (SELECT breach FROM blobs WHERE breach IS NOT NULL)",[])?;
        self.db.execute_batch("PRAGMA incremental_vacuum(32)")?;
        Ok(())
    }
    pub(super) fn matches(&self, hint: &[u8; 16]) -> Result<Vec<Record>> {
        Ok(self
            .db
            .prepare("SELECT id,hint,nonce,cipher,breach,height,hash FROM blobs WHERE hint=?1")?
            .query_map([hint.as_slice()], record)?
            .collect::<std::result::Result<_, _>>()?)
    }
    pub(super) fn active(&self) -> Result<Vec<Record>> {
        Ok(self.db.prepare("SELECT id,hint,nonce,cipher,breach,height,hash FROM blobs WHERE breach IS NOT NULL")?.query_map([],record)?.collect::<std::result::Result<_,_>>()?)
    }
    pub fn status(&self) -> Result<TowerServeStatus> {
        let mut status = self.db.query_row("SELECT (SELECT count(*) FROM sessions),(SELECT count(*) FROM blobs),(SELECT coalesce(sum(length(cipher)+24+16),0) FROM blobs),seen,broadcast FROM totals",[],|r|Ok(TowerServeStatus { enabled:true, sessions:r.get(0)?, blobs:r.get(1)?, blob_bytes:r.get(2)?, breaches_seen:r.get(3)?, breaches_broadcast:r.get(4)?, ..Default::default() }))?;
        let pages: u64 = self.db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let page_size: u64 = self.db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        status.storage_bytes = pages * page_size;
        status.max_storage_bytes = self.config.max_storage_mb * 1024 * 1024;
        status.full = self.charged()? + ROW_BUDGET + SESSION_BUDGET > self.quota()
            || status.storage_bytes + RESERVE >= status.max_storage_bytes / 2;
        Ok(status)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::Hash, Txid};

    fn blob(n: u8) -> SealedBlob {
        SealedBlob::encrypt(Txid::from_byte_array([n; 32]), &[]).unwrap()
    }
    #[test]
    fn tower_storage_durable_replace_delete_expiry_and_rate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serve.sqlite");
        let config = ServiceConfig {
            max_blobs_per_session: 2,
            ..Default::default()
        };
        let mut store = TowerStorage::open(&path, &config).unwrap();
        store.accept([1; 32], 1, &blob(1), 100, 100).unwrap();
        store.accept([1; 32], 2, &blob(1), 101, 100).unwrap();
        assert_eq!(store.status().unwrap().blobs, 1);
        store.accept([1; 32], 3, &blob(2), 102, 100).unwrap();
        assert!(store.accept([1; 32], 4, &blob(3), 103, 100).is_err());
        drop(store);
        let mut store = TowerStorage::open(&path, &config).unwrap();
        assert_eq!(store.matches(&[1; 16]).unwrap().len(), 1);
        store.delete([1; 32], &[[1; 16]]).unwrap();
        assert_eq!(store.status().unwrap().blobs, 1);
        store.prune(100 + GRACE_SECONDS - 1, 0).unwrap();
        assert_eq!(store.status().unwrap().blobs, 1);
        store.prune(100 + GRACE_SECONDS, 0).unwrap();
        assert_eq!(store.status().unwrap().blobs, 0);
        for seq in 0..600 {
            store
                .accept([2; 32], seq, &blob(4), 700_000, 800_000)
                .unwrap();
        }
        store.delete([2; 32], &[[4; 16]]).unwrap();
        assert!(store
            .accept([2; 32], 601, &blob(4), 700_001, 800_000)
            .is_err());
        drop(store);
        let mut store = TowerStorage::open(&path, &config).unwrap();
        assert!(store
            .accept([2; 32], 602, &blob(4), 700_002, 800_000)
            .is_err());
        store
            .accept([2; 32], 603, &blob(4), 703_601, 800_000)
            .unwrap();
    }
    #[test]
    fn tower_storage_full_and_oversize_refused() {
        let dir = tempfile::tempdir().unwrap();
        let config = ServiceConfig {
            max_storage_mb: 1,
            ..Default::default()
        };
        let mut store = TowerStorage::open(&dir.path().join("serve.sqlite"), &config).unwrap();
        let mut oversized = blob(1);
        oversized.ciphertext = vec![0; MAX_BLOB_BYTES];
        assert!(store.accept([1; 32], 1, &oversized, 1, 100).is_err());
        let mut accepted = 0;
        for n in 0..100 {
            if store.accept([n; 32], 1, &blob(n), 1, 100).is_err() {
                break;
            }
            accepted += 1;
        }
        assert!(accepted > 0 && accepted < 100);
        assert!(store.status().unwrap().full);
        assert!(store.accept([250; 32], 1, &blob(250), 1, 100).is_err());
        assert!(store.status().unwrap().storage_bytes <= 1024 * 1024);
        store.delete([0; 32], &[[0; 16]]).unwrap();
        store.accept([0; 32], 2, &blob(250), 1, 100).unwrap();
    }
}
