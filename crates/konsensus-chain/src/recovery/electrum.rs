use super::*;
use crate::ElectrumProvider;
use bitcoin::{OutPoint, ScriptBuf};
use electrum_client::{Client, ElectrumApi};
use konsensus_recovery::RecoveryScript;

fn failure(_: electrum_client::Error) -> ChainError {
    invalid()
}
fn scan(client: &Client, scripts: &[ScriptBuf]) -> Result<Vec<FoundOutput>, ChainError> {
    let tip = client.block_headers_subscribe().map_err(failure)?;
    let lists = client
        .batch_script_list_unspent(scripts.iter().map(|s| s.as_script()))
        .map_err(failure)?;
    if lists.len() != scripts.len() {
        return Err(invalid());
    }
    let mut outputs = Vec::new();
    for (script, list) in scripts.iter().zip(lists) {
        for item in list {
            let tx = client.transaction_get(&item.tx_hash).map_err(failure)?;
            if tx.compute_txid() != item.tx_hash {
                return Err(invalid());
            }
            let txout = tx.output.get(item.tx_pos).ok_or_else(invalid)?.clone();
            if txout.script_pubkey != *script || txout.value.to_sat() != item.value {
                return Err(invalid());
            }
            outputs.push(FoundOutput {
                outpoint: OutPoint {
                    txid: item.tx_hash,
                    vout: item.tx_pos.try_into().map_err(|_| invalid())?,
                },
                txout,
                confirmations: depth(
                    tip.height.try_into().map_err(|_| invalid())?,
                    item.height.try_into().map_err(|_| invalid())?,
                )?,
            });
        }
    }
    let after = client.block_headers_subscribe().map_err(failure)?;
    if after.height != tip.height || after.header.block_hash() != tip.header.block_hash() {
        return Err(invalid());
    }
    outputs.sort_by_key(|o| o.outpoint);
    outputs.dedup_by_key(|o| o.outpoint);
    Ok(outputs)
}
#[async_trait]
impl Scanner for ElectrumProvider {
    type Error = ChainError;
    async fn scan(&self, scripts: &[RecoveryScript]) -> Result<Vec<FoundOutput>, ChainError> {
        let scripts: Vec<_> = scripts.iter().map(|s| s.script_pubkey.clone()).collect();
        self.query(move |client| scan(&client, &scripts)).await
    }
}
#[async_trait]
impl RecoveryChain for ElectrumProvider {
    async fn funding_spend(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<ChainTransaction>, ChainError> {
        self.query(move |client| {
            let tip = client.block_headers_subscribe().map_err(failure)?;
            let funding = client.transaction_get(&outpoint.txid).map_err(failure)?;
            if funding.compute_txid() != outpoint.txid {
                return Err(invalid());
            }
            let output = funding
                .output
                .get(outpoint.vout as usize)
                .ok_or_else(invalid)?;
            for entry in client
                .script_get_history(&output.script_pubkey)
                .map_err(failure)?
            {
                if entry.height <= 0 {
                    continue;
                }
                let tx = client.transaction_get(&entry.tx_hash).map_err(failure)?;
                if tx.compute_txid() != entry.tx_hash {
                    return Err(invalid());
                }
                if tx.input.iter().any(|i| i.previous_output == outpoint) {
                    if client
                        .block_headers_subscribe()
                        .map_err(failure)?
                        .header
                        .block_hash()
                        != tip.header.block_hash()
                    {
                        return Err(invalid());
                    }
                    return Ok(Some(ChainTransaction {
                        transaction: tx,
                        confirmations: depth(
                            tip.height.try_into().map_err(|_| invalid())?,
                            entry.height as u32,
                        )?,
                    }));
                }
            }
            Ok(None)
        })
        .await
    }
    async fn transaction(&self, txid: Txid) -> Result<Option<ChainTransaction>, ChainError> {
        self.query(move |client| {
            let tip = client.block_headers_subscribe().map_err(failure)?;
            let tx = match client.transaction_get(&txid) {
                Ok(tx) => tx,
                Err(electrum_client::Error::Protocol(v)) if v["code"] == -5 => return Ok(None),
                Err(e) => return Err(failure(e)),
            };
            if tx.compute_txid() != txid {
                return Err(invalid());
            }
            let output = tx.output.first().ok_or_else(invalid)?;
            let history = client
                .script_get_history(&output.script_pubkey)
                .map_err(failure)?;
            let height = history
                .iter()
                .find(|h| h.tx_hash == txid)
                .ok_or_else(invalid)?
                .height;
            let confirmations = depth(
                tip.height.try_into().map_err(|_| invalid())?,
                height.max(0) as u32,
            )?;
            let after = client.block_headers_subscribe().map_err(failure)?;
            if after.header.block_hash() != tip.header.block_hash() {
                return Err(invalid());
            }
            Ok(Some(ChainTransaction {
                transaction: tx,
                confirmations,
            }))
        })
        .await
    }
    async fn recheck(&self, outputs: &[FoundOutput]) -> Result<bool, ChainError> {
        let outputs = outputs.to_vec();
        self.query(move |client| {
            let scripts: Vec<_> = outputs
                .iter()
                .map(|o| o.txout.script_pubkey.clone())
                .collect();
            let live = scan(&client, &scripts)?;
            Ok(outputs.iter().all(|o| {
                live.iter()
                    .any(|v| v.outpoint == o.outpoint && v.txout == o.txout && v.confirmations > 0)
            }))
        })
        .await
    }
    async fn broadcast(&self, tx: &Transaction) -> Result<(), ChainError> {
        let tx = tx.clone();
        self.query(move |client| {
            let txid = client.transaction_broadcast(&tx).map_err(failure)?;
            if txid != tx.compute_txid() {
                return Err(invalid());
            }
            Ok(())
        })
        .await
    }
}
