use super::*;
use crate::EsploraProvider;
use bitcoin::{
    hashes::{sha256, Hash},
    OutPoint, ScriptBuf,
};
use konsensus_recovery::RecoveryScript;
use serde::Deserialize;

#[derive(Deserialize)]
struct Status {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
}
#[derive(Deserialize)]
struct Utxo {
    txid: Txid,
    vout: u32,
    value: u64,
    status: Status,
}
#[derive(Deserialize)]
struct Outspend {
    spent: bool,
    txid: Option<Txid>,
}

impl EsploraProvider {
    async fn recovery_tip(&self) -> Result<(String, u32), ChainError> {
        let hash = self.get_text("/blocks/tip/hash").await?;
        let v: serde_json::Value = self.get_json(&format!("/block/{hash}")).await?;
        let height = v["height"]
            .as_u64()
            .and_then(|n| n.try_into().ok())
            .ok_or_else(invalid)?;
        Ok((hash, height))
    }
    async fn recovery_depth(&self, status: &Status, tip: u32) -> Result<u32, ChainError> {
        if !status.confirmed {
            return Ok(0);
        }
        let height = status.block_height.ok_or_else(invalid)?;
        let hash = self.get_text(&format!("/block-height/{height}")).await?;
        if Some(&hash) != status.block_hash.as_ref() {
            return Err(invalid());
        }
        depth(tip, height)
    }
    async fn recovery_scan(&self, scripts: &[ScriptBuf]) -> Result<Vec<FoundOutput>, ChainError> {
        let mut outputs = Vec::new();
        let mut statuses = Vec::new();
        for script in scripts {
            // Esplora's scripthash endpoint uses SHA256 in display byte order.
            let hash = sha256::Hash::hash(script.as_bytes());
            let utxos: Vec<Utxo> = self.get_json(&format!("/scripthash/{hash}/utxo")).await?;
            for utxo in utxos {
                let raw = self.get_text(&format!("/tx/{}/hex", utxo.txid)).await?;
                let tx = decode(&raw, utxo.txid)?;
                let txout = tx
                    .output
                    .get(utxo.vout as usize)
                    .ok_or_else(invalid)?
                    .clone();
                if txout.script_pubkey != *script || txout.value.to_sat() != utxo.value {
                    return Err(invalid());
                }
                let outspend: Outspend = self
                    .get_json(&format!("/tx/{}/outspend/{}", utxo.txid, utxo.vout))
                    .await?;
                if outspend.spent {
                    continue;
                }
                outputs.push(FoundOutput {
                    outpoint: OutPoint {
                        txid: utxo.txid,
                        vout: utxo.vout,
                    },
                    txout,
                    confirmations: 0,
                });
                statuses.push(utxo.status);
            }
        }
        // Discovering 2,000 scripts can span several blocks. Authenticate all
        // discovered outputs against a fresh tip in a short final window,
        // rather than requiring the entire HTTP scan to finish within one block.
        // Approval separately rechecks every exact input, including mempool spends.
        let tip = self.recovery_tip().await?;
        for (output, status) in outputs.iter_mut().zip(statuses) {
            output.confirmations = self.recovery_depth(&status, tip.1).await?;
        }
        if self.recovery_tip().await? != tip {
            return Err(invalid());
        }
        outputs.sort_by_key(|o| o.outpoint);
        outputs.dedup_by_key(|o| o.outpoint);
        Ok(outputs)
    }
}
#[async_trait]
impl Scanner for EsploraProvider {
    type Error = ChainError;
    async fn scan(&self, scripts: &[RecoveryScript]) -> Result<Vec<FoundOutput>, ChainError> {
        self.recovery_scan(
            &scripts
                .iter()
                .map(|s| s.script_pubkey.clone())
                .collect::<Vec<_>>(),
        )
        .await
    }
}
#[async_trait]
impl RecoveryChain for EsploraProvider {
    async fn funding_spend(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<ChainTransaction>, ChainError> {
        let spent: Outspend = self
            .get_json(&format!("/tx/{}/outspend/{}", outpoint.txid, outpoint.vout))
            .await?;
        if !spent.spent {
            return Ok(None);
        }
        let tx = self
            .transaction(spent.txid.ok_or_else(invalid)?)
            .await?
            .ok_or_else(invalid)?;
        if !tx
            .transaction
            .input
            .iter()
            .any(|i| i.previous_output == outpoint)
        {
            return Err(invalid());
        }
        Ok((tx.confirmations > 0).then_some(tx))
    }
    async fn transaction(&self, txid: Txid) -> Result<Option<ChainTransaction>, ChainError> {
        // A 404 is inconclusive and stays an error. Never rebroadcast on lookup failure.
        let tip = self.recovery_tip().await?;
        let raw = self.get_text(&format!("/tx/{txid}/hex")).await?;
        let transaction = decode(&raw, txid)?;
        let status: Status = self.get_json(&format!("/tx/{txid}/status")).await?;
        let confirmations = self.recovery_depth(&status, tip.1).await?;
        if self.recovery_tip().await? != tip {
            return Err(invalid());
        }
        Ok(Some(ChainTransaction {
            transaction,
            confirmations,
        }))
    }
    async fn recheck(&self, outputs: &[FoundOutput]) -> Result<bool, ChainError> {
        let scripts: Vec<_> = outputs
            .iter()
            .map(|o| o.txout.script_pubkey.clone())
            .collect();
        let live = self.recovery_scan(&scripts).await?;
        Ok(outputs.iter().all(|o| {
            live.iter()
                .any(|v| v.outpoint == o.outpoint && v.txout == o.txout && v.confirmations > 0)
        }))
    }
    async fn broadcast(&self, tx: &Transaction) -> Result<(), ChainError> {
        let result = self
            .recovery_broadcast(&bitcoin::consensus::encode::serialize_hex(tx))
            .await?;
        if result.trim() != tx.compute_txid().to_string() {
            return Err(invalid());
        }
        Ok(())
    }
}
