use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    hashes::Hash,
    opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV},
    script::Builder,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    Network, ScriptBuf, WPubkeyHash,
};
use zeroize::{Zeroize, Zeroizing};

use crate::RecoveryError;

/// LDK 0.2.2's v2 static payment key space: `m/8'/0'` through `m/8'/999'`.
pub const STATIC_KEY_COUNT: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputKind {
    StaticRemoteKey,
    /// The `to_remote` output of an anchor channel, **not** its 330-sat anchor.
    AnchorToRemote,
}

/// Public scan metadata. The sweep signer matches the actual prevout script,
/// never an externally supplied key index or output kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryScript {
    pub key_index: u32,
    pub kind: OutputKind,
    pub script_pubkey: ScriptBuf,
}

/// In-memory signing material. Intentionally no Debug, Clone, serialization,
/// or secret accessor. Retained scalar bytes zeroize on drop (including unwind).
/// rust-bitcoin/secp256k1 use Copy secrets internally: temporary/compiler copies
/// cannot be guaranteed erased. We erase owned extended/scalar keys best-effort.
/// The caller remains responsible for erasing its original seed buffer.
pub struct RecoveryKeys {
    pub(crate) secrets: Vec<Zeroizing<[u8; 32]>>,
    scripts: Vec<RecoveryScript>,
}

// RAII protects success, error, and unwind paths. Never derive Debug here.
struct ErasingXpriv(Xpriv);
impl Drop for ErasingXpriv {
    fn drop(&mut self) {
        self.0.private_key.non_secure_erase();
        let chain_code: &mut [u8] = self.0.chain_code.as_mut();
        chain_code.zeroize();
    }
}

pub(crate) struct ErasingSecret(pub(crate) SecretKey);
impl Drop for ErasingSecret {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

pub(crate) fn anchor_script(public: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_slice(public.serialize())
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_int(1)
        .push_opcode(OP_CSV)
        .into_script()
}

impl RecoveryKeys {
    pub fn from_ldk_seed(seed: &[u8; 32]) -> Result<Self, RecoveryError> {
        let secp = Secp256k1::new();
        // Matches KeysManager::new; network changes only serialization prefixes.
        let master = ErasingXpriv(
            Xpriv::new_master(Network::Testnet, seed).map_err(|_| RecoveryError::Derivation)?,
        );
        let parent = ErasingXpriv(
            master
                .0
                .derive_priv(&secp, &[ChildNumber::Hardened { index: 8 }])
                .map_err(|_| RecoveryError::Derivation)?,
        );
        let mut secrets = Vec::with_capacity(STATIC_KEY_COUNT as usize);
        let mut scripts = Vec::with_capacity(STATIC_KEY_COUNT as usize * 2);
        for index in 0..STATIC_KEY_COUNT {
            let child = ErasingXpriv(
                parent
                    .0
                    .derive_priv(&secp, &[ChildNumber::Hardened { index }])
                    .map_err(|_| RecoveryError::Derivation)?,
            );
            let public = PublicKey::from_secret_key(&secp, &child.0.private_key);
            secrets.push(Zeroizing::new(child.0.private_key.secret_bytes()));
            scripts.push(RecoveryScript {
                key_index: index,
                kind: OutputKind::StaticRemoteKey,
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&public.serialize())),
            });
            scripts.push(RecoveryScript {
                key_index: index,
                kind: OutputKind::AnchorToRemote,
                script_pubkey: anchor_script(&public).to_p2wsh(),
            });
        }
        Ok(Self { secrets, scripts })
    }

    /// All 2000 scripts, in LDK order: P2WPKH then anchor P2WSH for each index.
    pub fn scripts(&self) -> &[RecoveryScript] {
        &self.scripts
    }
}
