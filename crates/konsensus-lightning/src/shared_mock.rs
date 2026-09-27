//! Explicit local-test backend. Signed regtest invoices and a shared SQLite
//! settlement ledger; no network, channels, real keys, or real funds.
use async_trait::async_trait;
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Secp256k1, SecretKey},
};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct SharedMockProvider {
    db: Mutex<Connection>,
    owner: String,
    signing_key: SecretKey,
}
fn err(e: impl std::fmt::Display) -> LightningError {
    LightningError::PaymentFailed(e.to_string())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl SharedMockProvider {
    pub fn new(path: &Path, owner: &str, initial_balance: u64) -> Result<Self, LightningError> {
        let db = Connection::open(path).map_err(err)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS accounts(owner TEXT PRIMARY KEY, balance INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS invoices(hash TEXT PRIMARY KEY, recipient TEXT NOT NULL, payer TEXT, preimage TEXT NOT NULL, bolt11 TEXT NOT NULL, amount INTEGER NOT NULL, created INTEGER NOT NULL, memo TEXT NOT NULL);").map_err(err)?;
        db.execute(
            "INSERT OR IGNORE INTO accounts VALUES (?1, ?2)",
            params![owner, i64::try_from(initial_balance).map_err(err)?],
        )
        .map_err(err)?;
        let key =
            sha256::Hash::hash(format!("INSECURE SHARED MOCK:{owner}").as_bytes()).to_byte_array();
        Ok(Self {
            db: Mutex::new(db),
            owner: owner.into(),
            signing_key: SecretKey::from_slice(&key).map_err(err)?,
        })
    }
    // Deliberately insecure mock-only derivation. The signed invoice carries
    // the nonce; no pending row is needed to reconstruct a settled preimage.
    fn quote_preimage(key: &SecretKey, secret: &PaymentSecret) -> [u8; 32] {
        let mut material = b"INSECURE SHARED MOCK STATELESS QUOTE:".to_vec();
        material.extend_from_slice(&key.secret_bytes());
        material.extend_from_slice(&secret.0);
        sha256::Hash::hash(&material).to_byte_array()
    }
    fn details(db: &Connection, owner: &str, hash: &str) -> Result<PaymentDetails, LightningError> {
        db.query_row("SELECT recipient,payer,preimage,amount,created,memo FROM invoices WHERE hash=?1 AND (recipient=?2 OR payer=?2)", params![hash, owner], |r| {
            let recipient: String = r.get(0)?;
            let payer: Option<String> = r.get(1)?;
            Ok(PaymentDetails { payment_hash: hash.into(), preimage: if payer.is_some() {Some(r.get(2)?)} else {None}, amount_msat:r.get(3)?, timestamp:r.get(4)?, memo:Some(r.get(5)?), fee_msat: Some(0), direction:if recipient==owner {PaymentDirection::Incoming} else {PaymentDirection::Outgoing}, status:if payer.is_some() {PaymentStatus::Settled} else {PaymentStatus::Pending} })
        }).optional().map_err(err)?.ok_or_else(|| LightningError::PaymentNotFound(hash.into()))
    }
}
#[async_trait]
impl LightningProvider for SharedMockProvider {
    async fn create_invoice(
        &self,
        amount: u64,
        description: &str,
        expiry: u32,
    ) -> Result<Invoice, LightningError> {
        let preimage: [u8; 32] = rand::random();
        let hash = sha256::Hash::hash(&preimage);
        let invoice = InvoiceBuilder::new(Currency::Regtest)
            .description(description.into())
            .payment_hash(hash)
            .payment_secret(PaymentSecret(rand::random()))
            .current_timestamp()
            .min_final_cltv_expiry_delta(18)
            .amount_milli_satoshis(amount)
            .expiry_time(Duration::from_secs(expiry.into()))
            .build_signed(|h| Secp256k1::new().sign_ecdsa_recoverable(h, &self.signing_key))
            .map_err(err)?;
        let bolt11 = invoice.to_string();
        let created_at = now();
        self.db
            .lock()
            .map_err(err)?
            .execute(
                "INSERT INTO invoices VALUES (?1,?2,NULL,?3,?4,?5,?6,?7)",
                params![
                    hash.to_string(),
                    self.owner,
                    hex::encode(preimage),
                    bolt11,
                    i64::try_from(amount).map_err(err)?,
                    created_at,
                    description
                ],
            )
            .map_err(err)?;
        Ok(Invoice {
            bolt11,
            payment_hash: hash.to_string(),
            amount_msat: amount,
            description: description.into(),
            expiry_secs: expiry,
            created_at,
        })
    }
    async fn create_stateless_invoice(
        &self, amount: u64, description: &str, expiry: u32,
    ) -> Result<Invoice, LightningError> {
        let secret = PaymentSecret(rand::random());
        let preimage = Self::quote_preimage(&self.signing_key, &secret);
        let hash = sha256::Hash::hash(&preimage);
        let signed = InvoiceBuilder::new(Currency::Regtest)
            .description(description.into())
            .payment_hash(hash)
            .payment_secret(secret)
            .current_timestamp()
            .min_final_cltv_expiry_delta(18)
            .amount_milli_satoshis(amount)
            .expiry_time(Duration::from_secs(expiry.into()))
            .build_signed(|h| Secp256k1::new().sign_ecdsa_recoverable(h, &self.signing_key))
            .map_err(err)?;
        Ok(Invoice {
            bolt11: signed.to_string(), payment_hash: hash.to_string(), amount_msat: amount,
            description: description.into(), expiry_secs: expiry,
            created_at: signed.duration_since_epoch().as_secs(),
        })
    }
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        let invoice: Bolt11Invoice = bolt11.parse().map_err(err)?;
        if invoice.currency() != Currency::Regtest || invoice.is_expired() {
            return Err(LightningError::PaymentNotDispatched(
                "shared mock accepts only live regtest invoices".into(),
            ));
        }
        let hash = invoice.payment_hash().to_string();
        let mut db = self.db.lock().map_err(err)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(err)?;
        let existing: Option<(String, Option<String>, String, i64)> = tx
            .query_row(
                "SELECT recipient,payer,bolt11,amount FROM invoices WHERE hash=?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ).optional().map_err(err)?;
        let mut stateless_preimage = None;
        let (recipient, payer, stored, amount) = if let Some(record) = existing {
            record
        } else {
            let payee = invoice.recover_payee_pub_key();
            let owners = tx.prepare("SELECT owner FROM accounts").map_err(err)?
                .query_map([], |r| r.get::<_, String>(0)).map_err(err)?
                .collect::<Result<Vec<_>, _>>().map_err(err)?;
            let mut recipient = None;
            for owner in owners {
                let bytes = sha256::Hash::hash(format!("INSECURE SHARED MOCK:{owner}").as_bytes()).to_byte_array();
                let key = SecretKey::from_slice(&bytes).map_err(err)?;
                if key.public_key(&Secp256k1::new()) == payee {
                    let preimage = Self::quote_preimage(&key, invoice.payment_secret());
                    if sha256::Hash::hash(&preimage).to_string() != hash {
                        return Err(LightningError::PaymentNotDispatched("unknown mock invoice".into()));
                    }
                    stateless_preimage = Some(hex::encode(preimage));
                    recipient = Some(owner);
                    break;
                }
            }
            let recipient = recipient.ok_or_else(|| LightningError::PaymentNotDispatched("unknown mock payee".into()))?;
            let amount = invoice.amount_milli_satoshis()
                .filter(|amount| *amount > 0)
                .and_then(|amount| i64::try_from(amount).ok())
                .ok_or_else(|| LightningError::PaymentNotDispatched("invalid mock quote amount".into()))?;
            (recipient, None, bolt11.to_owned(), amount)
        };
        if stored != bolt11 || recipient == self.owner {
            return Err(LightningError::PaymentNotDispatched(
                "invoice does not name another shared mock recipient".into(),
            ));
        }
        if let Some(payer) = payer {
            if payer != self.owner {
                return Err(LightningError::PaymentNotDispatched(
                    "invoice already paid by another node".into(),
                ));
            }
        } else {
            if tx
                .execute(
                    "UPDATE accounts SET balance=balance-?1 WHERE owner=?2 AND balance>=?1",
                    params![amount, self.owner],
                )
                .map_err(err)?
                != 1
            {
                return Err(LightningError::PaymentNotDispatched(
                    "insufficient mock balance".into(),
                ));
            }
            tx.execute(
                "UPDATE accounts SET balance=balance+?1 WHERE owner=?2",
                params![amount, recipient],
            )
            .map_err(err)?;
            if let Some(preimage) = stateless_preimage {
                // Atomically materialize the receipt with settlement, never a
                // pending record. Failed payments roll the entire transaction back.
                tx.execute("INSERT INTO invoices VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![hash, recipient, self.owner, preimage, bolt11, amount,
                        invoice.duration_since_epoch().as_secs(), invoice.description().to_string()]).map_err(err)?;
            } else {
                tx.execute(
                    "UPDATE invoices SET payer=?1 WHERE hash=?2",
                    params![self.owner, hash],
                ).map_err(err)?;
            }
        }
        let details = Self::details(&tx, &self.owner, &hash)?;
        tx.commit().map_err(err)?;
        Ok(details)
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        Self::details(&*self.db.lock().map_err(err)?, &self.owner, hash)
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.db
            .lock()
            .map_err(err)?
            .query_row(
                "SELECT balance FROM accounts WHERE owner=?1",
                [&self.owner],
                |r| r.get(0),
            )
            .map_err(err)
    }
    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        let db = self.db.lock().map_err(err)?;
        let mut stmt=db.prepare("SELECT hash FROM invoices WHERE recipient=?1 OR payer=?1 ORDER BY created DESC LIMIT ?2").map_err(err)?;
        let hashes = stmt
            .query_map(params![self.owner, limit], |r| r.get::<_, String>(0))
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        hashes
            .iter()
            .map(|h| Self::details(&db, &self.owner, h))
            .collect()
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn keysend(
        &self,
        _dest: &str,
        _amount: u64,
        _memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentNotDispatched(
            "shared mock uses recipient invoices".into(),
        ))
    }
    async fn get_node_pubkey(&self) -> Option<String> {
        Some(self.signing_key.public_key(&Secp256k1::new()).to_string())
    }
}
