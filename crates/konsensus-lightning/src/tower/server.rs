//! Decision-neutral tower service. Broadcasts only the client's sealed transactions.
use super::{
    blob::SealedBlob,
    storage::{Error, Result, TowerStorage},
};
use bitcoin::{hashes::Hash, Transaction, Txid};
use konsensus_core::{tower::TowerServeStatus, traits::chain::ChainProvider};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, RwLock},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceConfig {
    pub enabled: bool,
    pub max_storage_mb: u64,
    pub max_blobs_per_session: u64,
}
impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_storage_mb: 10 * 1024,
            max_blobs_per_session: 100_000,
        }
    }
}
impl ServiceConfig {
    pub fn validate(&self) -> std::io::Result<()> {
        if self.max_storage_mb == 0
            || self.max_storage_mb > (i64::MAX as u64 / (1024 * 1024))
            || self.max_blobs_per_session == 0
            || self.max_blobs_per_session > i64::MAX as u64
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid tower service storage limits",
            ));
        }
        Ok(())
    }
}

pub struct TowerServer {
    pub(super) storage: TowerStorage,
}
impl TowerServer {
    /// Disabled means no files, tasks, chain requests, or changes to Lightning.
    pub fn open(config: &ServiceConfig, directory: &Path) -> Result<Option<Self>> {
        config.validate()?;
        if !config.enabled {
            return Ok(None);
        }
        std::fs::create_dir_all(directory)?;
        Ok(Some(Self {
            storage: TowerStorage::open(&directory.join("serve.sqlite"), config)?,
        }))
    }
    pub fn status(&self) -> Result<TowerServeStatus> {
        self.storage.status()
    }

    /// Bounded catch-up through the node's selected chain source. Rewind to the
    /// common ancestor; retain submission receipts across forks and restarts.
    pub async fn sync(&mut self, chain: &dyn ChainProvider, now: u64) -> Result<()> {
        let tip = chain.get_block_height().await?;
        let cursor: Option<(u64, u64, String)> = self
            .storage
            .db
            .query_row("SELECT start,height,hash FROM scan", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        let mut next = match cursor {
            None => {
                // If internal/test admission preceded initial sync, scan all history.
                if self.storage.status()?.blobs == 0 {
                    tip
                } else {
                    0
                }
            }
            Some((start, mut height, hash)) => {
                if height <= tip && chain.get_block_header(height).await?.hash == hash {
                    height + 1
                } else {
                    height = height.min(tip);
                    let ancestor = loop {
                        let old: Option<String> = self
                            .storage
                            .db
                            .query_row("SELECT hash FROM blocks WHERE height=?1", [height], |r| {
                                r.get(0)
                            })
                            .optional()?;
                        match old {
                            Some(old) if chain.get_block_header(height).await?.hash == old => {
                                break Some((height, old))
                            }
                            _ if height == 0 || height <= start => break None,
                            None => break None, // Deep fork: replay from service's starting height.
                            _ => height -= 1,
                        }
                    };
                    let next = ancestor
                        .as_ref()
                        .map(|(h, _)| h + 1)
                        .unwrap_or(start.min(tip));
                    let tx = self.storage.db.transaction()?;
                    tx.execute(
                        "UPDATE blobs SET height=NULL,hash=NULL WHERE height>=?1",
                        [next],
                    )?;
                    tx.execute(
                        "UPDATE blobs SET confirmed=NULL WHERE confirmed>=?1",
                        [next],
                    )?;
                    tx.execute("DELETE FROM blocks WHERE height>=?1", [next])?;
                    if let Some((height, hash)) = ancestor {
                        tx.execute("UPDATE scan SET height=?1,hash=?2", params![height, hash])?;
                    } else {
                        tx.execute("DELETE FROM scan", [])?;
                    }
                    tx.commit()?;
                    next
                }
            }
        };
        let end = tip.min(next.saturating_add(127));
        while next <= end {
            let block = chain.get_block(next).await?;
            if chain.get_block_header(next).await?.hash != block.block_hash().to_string() {
                return Err(Error::Rejected("tower chain changed during scan"));
            }
            let previous: Option<String> = self
                .storage
                .db
                .query_row(
                    "SELECT hash FROM scan WHERE height=?1",
                    [next.saturating_sub(1)],
                    |r| r.get(0),
                )
                .optional()?;
            if next > 0 && previous.is_some_and(|p| p != block.header.prev_blockhash.to_string()) {
                return Err(Error::Rejected("tower chain parent changed during scan"));
            }
            self.scan_block(next, &block)?;
            next += 1;
        }
        // Do not broadcast against stale history while catching up.
        if next > tip {
            self.storage.prune(now, tip)?;
            self.broadcast_due(chain, tip).await?;
        }
        Ok(())
    }
    fn scan_block(&mut self, height: u64, block: &bitcoin::Block) -> Result<()> {
        let hash = block.block_hash().to_string();
        let mut matches = Vec::new();
        for breach in &block.txdata {
            let txid = breach.compute_txid();
            let hint = txid.to_byte_array()[..16].try_into().unwrap();
            for row in self.storage.matches(&hint)? {
                let Ok(ladder) = row.blob.decrypt(txid) else {
                    continue;
                };
                if valid_ladder(breach, &ladder) {
                    matches.push((row.id, txid.to_string()));
                }
            }
        }
        let mut active = self.storage.active()?;
        // Include newly matched rows in same-block confirmation checks.
        for (id, breach) in &matches {
            if !active.iter().any(|r| r.id == *id) {
                let txid: Txid = breach
                    .parse()
                    .map_err(|_| Error::Rejected("invalid breach txid"))?;
                let hint = txid.to_byte_array()[..16].try_into().unwrap();
                if let Some(mut row) = self
                    .storage
                    .matches(&hint)?
                    .into_iter()
                    .find(|r| r.id == *id)
                {
                    row.breach = Some(breach.clone());
                    active.push(row);
                }
            }
        }
        let tx = self.storage.db.transaction()?;
        for (id, breach) in matches {
            let seen: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE breach=?1)",
                [&breach],
                |r| r.get(0),
            )?;
            if !seen {
                tx.execute("UPDATE totals SET seen=seen+1", [])?;
            }
            tx.execute(
                "UPDATE blobs SET breach=?1,height=?2,hash=?3 WHERE id=?4",
                params![breach, height, hash, id],
            )?;
        }
        // Confirmation by full-block scan works without bitcoind txindex.
        for row in active {
            let Some(breach) = row.breach.as_deref().and_then(|s| s.parse().ok()) else {
                continue;
            };
            let Ok(ladder) = row.blob.decrypt(breach) else {
                continue;
            };
            if block
                .txdata
                .iter()
                .any(|t| ladder.iter().any(|j| j.compute_txid() == t.compute_txid()))
            {
                tx.execute(
                    "UPDATE blobs SET confirmed=?1 WHERE id=?2",
                    params![height, row.id],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO blocks VALUES(?1,?2) ON CONFLICT(height) DO UPDATE SET hash=excluded.hash",
            params![height, hash],
        )?;
        tx.execute("INSERT INTO scan VALUES(1,?1,?1,?2) ON CONFLICT(id) DO UPDATE SET height=excluded.height,hash=excluded.hash",params![height,hash])?;
        tx.execute("DELETE FROM blocks WHERE height+1000<?1", [height])?;
        tx.commit()?;
        Ok(())
    }
    async fn broadcast_due(&mut self, chain: &dyn ChainProvider, tip: u64) -> Result<()> {
        for row in self.storage.active()? {
            let (Some(breach), Some(height), Some(hash)) = (row.breach, row.height, row.hash)
            else {
                continue;
            };
            if chain.get_block_header(height).await?.hash != hash {
                continue;
            }
            let confirmed: Option<u64> = self.storage.db.query_row(
                "SELECT confirmed FROM blobs WHERE id=?1",
                [row.id],
                |r| r.get(0),
            )?;
            if confirmed.is_some() {
                continue;
            }
            let txid: Txid = breach
                .parse()
                .map_err(|_| Error::Rejected("invalid stored breach txid"))?;
            let ladder = row.blob.decrypt(txid)?;
            for (tier, justice) in ladder.iter().enumerate() {
                let id = justice.compute_txid().to_string();
                let sent: Option<bool> = self
                    .storage
                    .db
                    .query_row("SELECT sent FROM broadcasts WHERE txid=?1", [&id], |r| {
                        r.get(0)
                    })
                    .optional()?;
                if sent == Some(true) {
                    continue;
                }
                if tier > 0 {
                    let last: Option<u64> = self
                        .storage
                        .db
                        .query_row(
                            "SELECT height FROM broadcasts WHERE txid=?1 AND sent=1",
                            [ladder[tier - 1].compute_txid().to_string()],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if !last.is_some_and(|last| tip >= last.max(height).saturating_add(3)) {
                        break;
                    }
                }
                // Durable intent, then exact byte-for-byte submission. A crash between
                // external acceptance and this receipt may retry the SAME txid; an
                // atomic exactly-once RPC+SQLite commit is impossible. Confirmed and
                // successfully recorded submissions are never repeated on reorg.
                self.storage.db.execute(
                    "INSERT OR IGNORE INTO broadcasts(txid,breach,tier,height) VALUES(?1,?2,?3,?4)",
                    params![id, breach, tier as u64, tip],
                )?;
                chain.broadcast_transaction(justice).await?;
                let db = self.storage.db.transaction()?;
                let first: bool = db.query_row(
                    "SELECT NOT EXISTS(SELECT 1 FROM broadcasts WHERE breach=?1 AND sent=1)",
                    [&breach],
                    |r| r.get(0),
                )?;
                if first {
                    db.execute("UPDATE totals SET broadcast=broadcast+1", [])?;
                }
                db.execute(
                    "UPDATE broadcasts SET sent=1,height=?1 WHERE txid=?2",
                    params![tip, id],
                )?;
                db.commit()?;
                break;
            }
        }
        Ok(())
    }
    pub async fn run(
        mut self,
        chain: Arc<dyn ChainProvider>,
        status: Arc<RwLock<TowerServeStatus>>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            if *shutdown.borrow() {
                break;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let result = tokio::select! {
                result = self.sync(chain.as_ref(),now) => result,
                _ = shutdown.changed() => break,
            };
            let mut snapshot = self.status().unwrap_or_else(|e| TowerServeStatus {
                enabled: true,
                error: Some(e.to_string()),
                ..Default::default()
            });
            if let Err(error) = result {
                snapshot.error = Some(error.to_string());
                tracing::warn!(%error,"tower service scan failed; will retry");
            }
            *status.write().unwrap() = snapshot;
            tokio::select! { _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}, _ = shutdown.changed() => break }
        }
    }
}

fn valid_ladder(breach: &Transaction, ladder: &[Transaction]) -> bool {
    let Some(first) = ladder.first() else {
        return false;
    };
    if ladder.len() > 3 || first.input.len() != 1 || first.output.len() != 1 {
        return false;
    }
    let prev = first.input[0].previous_output;
    let Some(output) = breach.output.get(prev.vout as usize) else {
        return false;
    };
    if prev.txid != breach.compute_txid() {
        return false;
    }
    let mut value = output.value;
    for tx in ladder {
        if tx.input.len() != 1
            || tx.output.len() != 1
            || tx.input[0].previous_output != prev
            || tx.input[0].witness.is_empty()
            || !tx.input[0].sequence.is_rbf()
            || tx.output[0].script_pubkey != first.output[0].script_pubkey
            || tx.output[0].value >= value
            || tx.output[0].value.to_sat() < output.value.to_sat() / 2
        {
            return false;
        }
        value = tx.output[0].value;
    }
    true
}
#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
