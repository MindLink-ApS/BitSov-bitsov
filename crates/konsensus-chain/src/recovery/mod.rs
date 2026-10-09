//! Recovery uses only public scripts and chain transactions, never channel state.
mod bitcoind;
mod electrum;
mod esplora;

use async_trait::async_trait;
use bitcoin::{Transaction, Txid};
use konsensus_core::traits::chain::ChainError;
use konsensus_recovery::{FoundOutput, Scanner};

/// Active-chain transaction, authenticated by recomputing its txid.
#[derive(Clone, Debug)]
pub struct ChainTransaction {
    pub transaction: Transaction,
    pub confirmations: u32,
}

#[async_trait]
pub trait RecoveryChain: Scanner<Error = ChainError> + Send + Sync {
    /// Confirmed spending transaction for a known channel funding output.
    async fn funding_spend(
        &self,
        outpoint: bitcoin::OutPoint,
    ) -> Result<Option<ChainTransaction>, ChainError>;
    async fn transaction(&self, txid: Txid) -> Result<Option<ChainTransaction>, ChainError>;
    /// Includes mempool spends; fails closed on a changing tip or unknown prevout.
    async fn recheck(&self, outputs: &[FoundOutput]) -> Result<bool, ChainError>;
    async fn broadcast(&self, tx: &Transaction) -> Result<(), ChainError>;
}

fn invalid() -> ChainError {
    ChainError::Backend("invalid or inconsistent recovery chain response".into())
}
fn decode(raw: &str, txid: Txid) -> Result<Transaction, ChainError> {
    let bytes = hex::decode(raw).map_err(|_| invalid())?;
    let tx: Transaction = bitcoin::consensus::deserialize(&bytes).map_err(|_| invalid())?;
    if tx.compute_txid() != txid {
        return Err(invalid());
    }
    Ok(tx)
}
fn depth(tip: u32, height: u32) -> Result<u32, ChainError> {
    if height == 0 {
        return Ok(0);
    }
    tip.checked_sub(height)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confirmation_depth_refuses_future_height() {
        assert_eq!(depth(10, 10).unwrap(), 1);
        assert_eq!(depth(10, 0).unwrap(), 0);
        assert!(depth(10, 11).is_err());
    }
    #[test]
    fn raw_transaction_must_match_requested_txid() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert!(decode(
            &bitcoin::consensus::encode::serialize_hex(&tx),
            "abababababababababababababababababababababababababababababababab"
                .parse()
                .unwrap()
        )
        .is_err());
    }
}

#[cfg(test)]
mod adapters_tests;
