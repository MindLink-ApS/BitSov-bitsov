use super::*;
use crate::BitcoindProvider;
use bitcoin::{Amount, Denomination, OutPoint, ScriptBuf, TxOut};
use konsensus_recovery::{RecoveryScript, Scanner};
use serde_json::{json, Value};

fn number(v: &Value) -> Result<u32, ChainError> {
    v.as_u64()
        .and_then(|n| n.try_into().ok())
        .ok_or_else(invalid)
}
fn txout(v: &Value) -> Result<TxOut, ChainError> {
    let script = v["scriptPubKey"]["hex"]
        .as_str()
        .or_else(|| v["scriptPubKey"].as_str())
        .ok_or_else(invalid)?;
    let amount = v
        .get("value")
        .or_else(|| v.get("amount"))
        .ok_or_else(invalid)?;
    Ok(TxOut {
        value: Amount::from_float_in(amount.as_f64().ok_or_else(invalid)?, Denomination::Bitcoin)
            .map_err(|_| invalid())?,
        script_pubkey: ScriptBuf::from_hex(script).map_err(|_| invalid())?,
    })
}
impl BitcoindProvider {
    async fn recovery_tip(&self) -> Result<Value, ChainError> {
        let info = self.call("getblockchaininfo", json!([])).await?;
        if info["initialblockdownload"] != false
            || info["blocks"] != info["headers"]
            || info["bestblockhash"].as_str().is_none()
        {
            return Err(invalid());
        }
        Ok(info["bestblockhash"].clone())
    }
}
#[async_trait]
impl Scanner for BitcoindProvider {
    type Error = ChainError;
    async fn scan(&self, scripts: &[RecoveryScript]) -> Result<Vec<FoundOutput>, ChainError> {
        let tip = self.recovery_tip().await?;
        let descriptors: Vec<_> = scripts
            .iter()
            .map(|s| format!("raw({})", s.script_pubkey.to_hex_string()))
            .collect();
        let result = self
            .call("scantxoutset", json!(["start", descriptors]))
            .await?;
        if result["success"] != true || result["bestblock"] != tip {
            return Err(invalid());
        }
        let height = number(&result["height"])?;
        let mut found = Vec::new();
        for item in result["unspents"].as_array().ok_or_else(invalid)? {
            let outpoint = OutPoint {
                txid: item["txid"]
                    .as_str()
                    .ok_or_else(invalid)?
                    .parse()
                    .map_err(|_| invalid())?,
                vout: number(&item["vout"])?,
            };
            let output = txout(item)?;
            if !scripts
                .iter()
                .any(|s| s.script_pubkey == output.script_pubkey)
            {
                return Err(invalid());
            }
            // scantxoutset ignores mempool spends. gettxout must include them.
            let live = self
                .call(
                    "gettxout",
                    json!([outpoint.txid.to_string(), outpoint.vout, true]),
                )
                .await?;
            if live.is_null() {
                continue;
            }
            if live["bestblock"] != tip || txout(&live)? != output {
                return Err(invalid());
            }
            found.push(FoundOutput {
                outpoint,
                txout: output,
                confirmations: depth(height, number(&item["height"])?)?,
            });
        }
        if self.recovery_tip().await? != tip {
            return Err(invalid());
        }
        found.sort_by_key(|o| o.outpoint);
        Ok(found)
    }
}
#[async_trait]
impl RecoveryChain for BitcoindProvider {
    async fn funding_spend(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<ChainTransaction>, ChainError> {
        let tip = self.recovery_tip().await?;
        if !self
            .call(
                "gettxout",
                json!([outpoint.txid.to_string(), outpoint.vout, true]),
            )
            .await?
            .is_null()
        {
            return Ok(None);
        }
        let info = self.call("getblockchaininfo", json!([])).await?;
        let height = number(&info["blocks"])?;
        // The reconnect close is recent. Historical absence is never inferred.
        let floor = height
            .saturating_sub(287)
            .max(info["pruneheight"].as_u64().unwrap_or(0) as u32);
        for block_height in (floor..=height).rev() {
            let hash = self.call("getblockhash", json!([block_height])).await?;
            let raw = self.call("getblock", json!([hash, 0])).await?;
            let bytes = hex::decode(raw.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
            let block: bitcoin::Block =
                bitcoin::consensus::deserialize(&bytes).map_err(|_| invalid())?;
            if block.block_hash().to_string() != hash.as_str().ok_or_else(invalid)? {
                return Err(invalid());
            }
            for transaction in block.txdata {
                if transaction
                    .input
                    .iter()
                    .any(|i| i.previous_output == outpoint)
                {
                    if self.recovery_tip().await? != tip {
                        return Err(invalid());
                    }
                    return Ok(Some(ChainTransaction {
                        transaction,
                        confirmations: depth(height, block_height)?,
                    }));
                }
            }
        }
        Err(ChainError::NotAvailable("funding spent but close not found in recent retained blocks; historical close evidence required".into()))
    }
    async fn transaction(&self, txid: Txid) -> Result<Option<ChainTransaction>, ChainError> {
        let tip = self.recovery_tip().await?;
        let v = match self
            .rpc("getrawtransaction", json!([txid.to_string(), true]))
            .await?
        {
            Ok(v) => v,
            Err(-5) => {
                // Recent closes/sweeps remain recoverable without txindex, including
                // pruned Core. Older retained outputs require a transaction index.
                let info = self.call("getblockchaininfo", json!([])).await?;
                let height = number(&info["blocks"])?;
                let floor = height
                    .saturating_sub(287)
                    .max(info["pruneheight"].as_u64().unwrap_or(0) as u32);
                let mut found = None;
                for height in (floor..=height).rev() {
                    let hash = self.call("getblockhash", json!([height])).await?;
                    let block = self.call("getblock", json!([hash, 1])).await?;
                    if block["tx"]
                        .as_array()
                        .ok_or_else(invalid)?
                        .iter()
                        .any(|v| v.as_str() == Some(txid.to_string().as_str()))
                    {
                        found = Some(
                            self.call("getrawtransaction", json!([txid.to_string(), true, hash]))
                                .await?,
                        );
                        break;
                    }
                }
                match found {
                    Some(v) => v,
                    None => return Err(ChainError::NotAvailable("recovery transaction not in mempool/index or last 288 retained blocks; use txindex for historical recovery".into())),
                }
            }
            Err(_) => return Err(invalid()),
        };
        let transaction = decode(v["hex"].as_str().ok_or_else(invalid)?, txid)?;
        let confirmations = v["confirmations"]
            .as_u64()
            .unwrap_or(0)
            .try_into()
            .map_err(|_| invalid())?;
        if self.recovery_tip().await? != tip {
            return Err(invalid());
        }
        Ok(Some(ChainTransaction {
            transaction,
            confirmations,
        }))
    }
    async fn recheck(&self, outputs: &[FoundOutput]) -> Result<bool, ChainError> {
        let tip = self.recovery_tip().await?;
        for output in outputs {
            let v = self
                .call(
                    "gettxout",
                    json!([output.outpoint.txid.to_string(), output.outpoint.vout, true]),
                )
                .await?;
            if v.is_null() {
                return Ok(false);
            }
            if v["bestblock"] != tip || txout(&v)? != output.txout {
                return Err(invalid());
            }
            if number(&v["confirmations"])? == 0 {
                return Ok(false);
            }
        }
        if self.recovery_tip().await? != tip {
            return Err(invalid());
        }
        Ok(true)
    }
    async fn broadcast(&self, tx: &Transaction) -> Result<(), ChainError> {
        let result = self
            .call(
                "sendrawtransaction",
                json!([bitcoin::consensus::encode::serialize_hex(tx)]),
            )
            .await?;
        if result.as_str() != Some(tx.compute_txid().to_string().as_str()) {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rpc_amounts_preserve_single_satoshis_and_reject_fractional_satoshis() {
        for sats in [1, 330, 546, 10_001, 80_000, 2_100_000_000_000_000u64] {
            let v = json!({"value": sats as f64 / 100_000_000.0, "scriptPubKey":{"hex":"00140000000000000000000000000000000000000000"}});
            assert_eq!(txout(&v).unwrap().value.to_sat(), sats);
        }
        assert!(txout(&json!({"value":0.000000001,"scriptPubKey":"00"})).is_err());
    }
}
