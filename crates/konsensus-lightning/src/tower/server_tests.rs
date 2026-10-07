use super::*;
use crate::tower::blob::SealedBlob;
use async_trait::async_trait;
use bitcoin::{
    hashes::Hash,
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    EcdsaSighashType, ScriptBuf, Txid, Witness,
};
use konsensus_core::traits::chain::{BlockHeader, ChainError, FeeEstimate, TrustLevel};
use ldk_node::lightning::{
    ln::{chan_utils::*, types::ChannelId},
    types::features::ChannelTypeFeatures,
};
use std::result::Result;
use std::sync::Mutex;

// A real LDK commitment and W1-shaped, revocation-signed three-tier candidate.
fn revoked_candidate_at(
    number: u64,
) -> (
    bitcoin::Transaction,
    ldk_node::tower_hook::JusticeCandidate,
    ScriptBuf,
) {
    let secp = Secp256k1::new();
    let secret = |n| SecretKey::from_slice(&[n; 32]).unwrap();
    let pk = |n| PublicKey::from_secret_key(&secp, &secret(n));
    let keys = |n| ChannelPublicKeys {
        funding_pubkey: pk(n),
        revocation_basepoint: pk(n + 1).into(),
        payment_point: pk(n + 2),
        delayed_payment_basepoint: pk(n + 3).into(),
        htlc_basepoint: pk(n + 4).into(),
    };
    let params = ChannelTransactionParameters {
        holder_pubkeys: keys(1),
        holder_selected_contest_delay: 288,
        is_outbound_from_holder: true,
        counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
            pubkeys: keys(10),
            selected_contest_delay: 288,
        }),
        funding_outpoint: Some(ldk_node::lightning::chain::transaction::OutPoint {
            txid: Txid::from_byte_array([42; 32]),
            index: 0,
        }),
        splice_parent_funding_txid: None,
        channel_type_features: ChannelTypeFeatures::only_static_remote_key(),
        channel_value_satoshis: 100_000,
    };
    let commitment = CommitmentTransaction::new(
        number,
        &pk(30),
        80_000,
        10_000,
        253,
        vec![],
        &params.as_holder_broadcastable(),
        &secp,
    );
    let trusted = commitment.trust();
    let breach = trusted.built_transaction().transaction.clone();
    let dest = bitcoin::Address::p2wpkh(
        &bitcoin::CompressedPublicKey(pk(40)),
        bitcoin::Network::Regtest,
    )
    .script_pubkey();
    let redeem = get_revokeable_redeemscript(
        &trusted.keys().revocation_key,
        288,
        &trusted.keys().broadcaster_delayed_payment_key,
    );
    let revocation = derive_private_revocation_key(&secp, &secret(30), &secret(11));
    let mut ladder = Vec::new();
    for rate in [1000, 4000, 16000] {
        let mut tx = trusted
            .build_to_local_justice_tx(rate, dest.clone())
            .unwrap();
        let hash = SighashCache::new(&tx)
            .p2wsh_signature_hash(
                0,
                &redeem,
                bitcoin::Amount::from_sat(80_000),
                EcdsaSighashType::All,
            )
            .unwrap();
        let msg = Message::from_digest(hash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &revocation);
        secp.verify_ecdsa(&msg, &sig, &PublicKey::from_secret_key(&secp, &revocation))
            .unwrap();
        let mut bytes = sig.serialize_der().to_vec();
        bytes.push(1);
        tx.input[0].witness = Witness::from_slice(&[bytes, vec![1], redeem.to_bytes()]);
        ladder.push(tx);
    }
    (
        breach,
        ldk_node::tower_hook::JusticeCandidate {
            channel_id: ChannelId::from_bytes([1; 32]),
            commitment_number: 42,
            ladder,
            value: 80_000,
        },
        dest,
    )
}

#[derive(Default)]
struct Chain {
    blocks: Mutex<Vec<bitcoin::Block>>,
    sent: Mutex<Vec<bitcoin::Transaction>>,
    fail: Mutex<bool>,
    reject: Mutex<Vec<Txid>>,
}
impl Chain {
    fn push(&self, txdata: Vec<bitcoin::Transaction>) {
        let mut blocks = self.blocks.lock().unwrap();
        let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        block.header.prev_blockhash = blocks
            .last()
            .map(|b| b.block_hash())
            .unwrap_or_else(bitcoin::BlockHash::all_zeros);
        block.header.time += blocks.len() as u32;
        block.txdata = txdata;
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(bitcoin::TxMerkleNode::all_zeros);
        blocks.push(block);
    }
}
#[async_trait]
impl ChainProvider for Chain {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::FullValidation
    }
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        Ok(self.blocks.lock().unwrap().len() as u64 - 1)
    }
    async fn get_block_header(&self, h: u64) -> Result<BlockHeader, ChainError> {
        let b = self.get_block(h).await?;
        Ok(BlockHeader {
            height: h,
            hash: b.block_hash().to_string(),
            timestamp: 0,
            bits: 0,
        })
    }
    async fn get_block(&self, h: u64) -> Result<bitcoin::Block, ChainError> {
        self.blocks
            .lock()
            .unwrap()
            .get(h as usize)
            .cloned()
            .ok_or(ChainError::BlockNotFound(h))
    }
    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), ChainError> {
        if *self.fail.lock().unwrap() || self.reject.lock().unwrap().contains(&tx.compute_txid()) {
            return Err(ChainError::Connection("offline".into()));
        }
        self.sent.lock().unwrap().push(tx.clone());
        Ok(())
    }
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        Ok(FeeEstimate {
            target_blocks,
            sat_per_vbyte: 1.0,
        })
    }
    async fn is_tx_confirmed(&self, id: &str, _: u32) -> Result<bool, ChainError> {
        Ok(self
            .blocks
            .lock()
            .unwrap()
            .iter()
            .any(|b| b.txdata.iter().any(|t| t.compute_txid().to_string() == id)))
    }
    async fn is_synced(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn tower_server_revoked_commitment_ladder_restart_reorg_and_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ServiceConfig {
        enabled: true,
        ..Default::default()
    };
    let chain = Chain::default();
    chain.push(vec![]);
    let (breach, candidate, dest) = revoked_candidate_at(42);
    let blob = SealedBlob::encrypt(breach.compute_txid(), &candidate.ladder).unwrap();
    let mut core = TowerServer::open(&cfg, dir.path()).unwrap().unwrap();
    core.storage
        .accept([1; 32], 0, &blob, 1, 1_000_000)
        .unwrap();
    core.sync(&chain, 2).await.unwrap();
    assert!(chain.sent.lock().unwrap().is_empty());
    chain.push(vec![breach.clone()]);
    core.sync(&chain, 3).await.unwrap();
    assert_eq!(*chain.sent.lock().unwrap(), candidate.ladder[..1]);
    assert_eq!(chain.sent.lock().unwrap()[0].output[0].script_pubkey, dest);
    assert_eq!(
        chain.sent.lock().unwrap()[0].input[0].previous_output.txid,
        breach.compute_txid()
    );
    drop(core);
    let mut core = TowerServer::open(&cfg, dir.path()).unwrap().unwrap();
    core.sync(&chain, 4).await.unwrap();
    for _ in 0..2 {
        chain.push(vec![]);
        core.sync(&chain, 4).await.unwrap();
    }
    assert_eq!(chain.sent.lock().unwrap().len(), 1);
    chain.push(vec![]);
    core.sync(&chain, 4).await.unwrap();
    assert_eq!(*chain.sent.lock().unwrap(), candidate.ladder[..2]);
    // Reorg through the breach; same breach is re-mined at a different height.
    chain.blocks.lock().unwrap().truncate(1);
    chain.push(vec![]);
    chain.push(vec![breach]);
    core.sync(&chain, 5).await.unwrap();
    assert_eq!(chain.sent.lock().unwrap().len(), 2);
    for _ in 0..5 {
        chain.push(vec![]);
        core.sync(&chain, 5).await.unwrap();
    }
    assert_eq!(*chain.sent.lock().unwrap(), candidate.ladder);
    assert_eq!(core.status().unwrap().breaches_seen, 1);
    assert_eq!(core.status().unwrap().breaches_broadcast, 1);
    chain.push(vec![candidate.ladder[2].clone()]);
    core.sync(&chain, 6).await.unwrap();
    for _ in 0..4 {
        chain.push(vec![]);
        core.sync(&chain, 6).await.unwrap();
    }
    assert_eq!(chain.sent.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn tower_server_wrong_key_invalid_spend_and_confirmed_ladder_never_broadcast() {
    let (breach, candidate, _) = revoked_candidate_at(42);
    for mode in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ServiceConfig {
            enabled: true,
            ..Default::default()
        };
        let mut core = TowerServer::open(&cfg, dir.path()).unwrap().unwrap();
        let mut txid = breach.compute_txid().to_byte_array();
        let mut ladder = candidate.ladder.clone();
        if mode == 0 {
            txid[31] ^= 1;
        }
        if mode == 1 {
            ladder[0].input[0].previous_output.vout = 999;
        }
        let blob = SealedBlob::encrypt(Txid::from_byte_array(txid), &ladder).unwrap();
        core.storage
            .accept([1; 32], 0, &blob, 1, 1_000_000)
            .unwrap();
        let chain = Chain::default();
        chain.push(vec![]);
        core.sync(&chain, 1).await.unwrap();
        chain.push(if mode == 2 {
            vec![breach.clone(), ladder[0].clone()]
        } else {
            vec![breach.clone()]
        });
        core.sync(&chain, 2).await.unwrap();
        for _ in 0..7 {
            chain.push(vec![]);
            core.sync(&chain, 3).await.unwrap();
        }
        assert!(chain.sent.lock().unwrap().is_empty());
    }
}
#[test]
fn tower_server_off_has_no_filesystem_effect() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent");
    assert!(TowerServer::open(&ServiceConfig::default(), &path)
        .unwrap()
        .is_none());
    assert!(!path.exists());
}

#[tokio::test]
async fn tower_server_rejection_does_not_starve_other_breaches_or_fee_bumps() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ServiceConfig {
        enabled: true,
        ..Default::default()
    };
    let mut core = TowerServer::open(&cfg, dir.path()).unwrap().unwrap();
    let (breach, a, _) = revoked_candidate_at(42);
    let (other, b, _) = revoked_candidate_at(43);
    assert_ne!(breach.compute_txid(), other.compute_txid());
    core.storage
        .accept(
            [1; 32],
            0,
            &SealedBlob::encrypt(breach.compute_txid(), &a.ladder).unwrap(),
            1,
            1_000_000,
        )
        .unwrap();
    core.storage
        .accept(
            [2; 32],
            0,
            &SealedBlob::encrypt(other.compute_txid(), &b.ladder).unwrap(),
            1,
            1_000_000,
        )
        .unwrap();
    let chain = Chain::default();
    chain
        .reject
        .lock()
        .unwrap()
        .push(a.ladder[0].compute_txid());
    chain.push(vec![breach, other]);
    assert!(core.sync(&chain, 2).await.is_err());
    assert_eq!(*chain.sent.lock().unwrap(), vec![b.ladder[0].clone()]);
    drop(core);
    let mut core = TowerServer::open(&cfg, dir.path()).unwrap().unwrap();
    for _ in 0..3 {
        chain.push(vec![]);
        let _ = core.sync(&chain, 3).await;
    }
    assert!(chain.sent.lock().unwrap().contains(&a.ladder[1]));
}

#[tokio::test]
async fn tower_server_old_unfired_breach_is_not_pruned_before_first_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ServiceConfig {
        enabled: true,
        ..Default::default()
    };
    let mut core = TowerServer::open(&cfg, dir.path()).unwrap().unwrap();
    let (breach, candidate, _) = revoked_candidate_at(42);
    core.storage
        .accept(
            [1; 32],
            0,
            &SealedBlob::encrypt(breach.compute_txid(), &candidate.ladder).unwrap(),
            1,
            1_000_000,
        )
        .unwrap();
    let chain = Chain::default();
    chain.push(vec![breach]);
    for _ in 0..1001 {
        chain.push(vec![]);
    }
    for _ in 0..8 {
        core.sync(&chain, 2).await.unwrap();
    }
    assert_eq!(*chain.sent.lock().unwrap(), candidate.ladder[..1]);
    core.storage.prune(3, 2000).unwrap();
    assert_eq!(core.status().unwrap().blobs, 1);
    core.storage.prune(3, 2001).unwrap();
    assert_eq!(core.status().unwrap().blobs, 0);
}

#[tokio::test]
async fn tower_server_expiry_prunes_even_when_chain_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ServiceConfig {
        enabled: true,
        ..Default::default()
    };
    let mut core = TowerServer::open(&cfg, dir.path()).unwrap().unwrap();
    let (breach, candidate, _) = revoked_candidate_at(42);
    core.storage
        .accept(
            [1; 32],
            0,
            &SealedBlob::encrypt(breach.compute_txid(), &candidate.ladder).unwrap(),
            1,
            10,
        )
        .unwrap();
    let chain = konsensus_chain::MockChainProvider::new(); // Full blocks unsupported; no I/O.
    assert!(core
        .sync(&chain, 10 + super::super::storage::GRACE_SECONDS)
        .await
        .is_err());
    assert_eq!(core.status().unwrap().blobs, 0);
}

#[tokio::test]
async fn tower_server_same_hint_multiple_sessions_deduplicates_and_isolates_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ServiceConfig {
        enabled: true,
        ..Default::default()
    };
    let mut core = TowerServer::open(&cfg, dir.path()).unwrap().unwrap();
    let (breach, candidate, _) = revoked_candidate_at(42);
    let mut wrong = breach.compute_txid().to_byte_array();
    wrong[31] ^= 1;
    for (session, key) in [
        (1, Txid::from_byte_array(wrong)),
        (2, breach.compute_txid()),
        (3, breach.compute_txid()),
    ] {
        core.storage
            .accept(
                [session; 32],
                0,
                &SealedBlob::encrypt(key, &candidate.ladder).unwrap(),
                1,
                1_000_000,
            )
            .unwrap();
    }
    let chain = Chain::default();
    chain.push(vec![breach]);
    core.sync(&chain, 2).await.unwrap();
    core.sync(&chain, 3).await.unwrap();
    assert_eq!(*chain.sent.lock().unwrap(), candidate.ladder[..1]);
    assert_eq!(core.status().unwrap().blobs, 3);
    assert_eq!(core.status().unwrap().breaches_seen, 1);
    assert_eq!(core.status().unwrap().breaches_broadcast, 1);
}
