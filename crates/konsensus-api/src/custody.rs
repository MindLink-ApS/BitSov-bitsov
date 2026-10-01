//! Where the node's seed lives, as the owner's app labels it
//! (`docs/protocol/REMOTE-SIGNER.md` §2).

use serde::Serialize;

/// The node's custody mode, reported owner-only in `GET /api/v1/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyMode {
    /// A plaintext recovery phrase on the node's machine.
    LocalSeed,
    /// An encrypted recovery phrase with no plaintext copy beside it.
    EncryptedSeed,
    /// The node holds its seed on a machine operated for the owner (Cloud
    /// tier, or `[identity] hosted = true`): whoever runs it can spend.
    HostedCustody,
    /// Money and owner-approval keys are on the owner's signer; the identity
    /// root stays on the VM. Reserved until that slice exists. Must never be
    /// reported as [`Self::RemoteSigner`].
    MoneySigner,
    /// The node holds no seed and no owner key, including the identity root.
    /// Allowed only when `money_keys_off_vm && owner_approval_key_off_vm &&
    /// identity_root_off_vm` (REMOTE-SIGNER.md §2). Reserved until then.
    RemoteSigner,
}
