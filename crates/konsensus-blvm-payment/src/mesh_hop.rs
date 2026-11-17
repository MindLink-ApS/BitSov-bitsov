//! Mesh hop payment acquisition for blvm-mesh `payment_gated` relays.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use konsensus_core::traits::blvm_payment::BlvmPaymentError;
use konsensus_core::traits::lightning::{LightningError, LightningProvider};

use crate::mesh_route::MeshRoutePayment;
use crate::mesh_rpc::HttpBlvmMeshRpc;
use crate::rpc::RpcBlvmError;

/// Errors acquiring mesh hop payment proofs.
#[derive(Debug, thiserror::Error)]
pub enum MeshHopError {
    #[error("lightning: {0}")]
    Lightning(#[from] LightningError),
    #[error("mesh hop payment required but no acquirer configured")]
    AcquirerMissing,
    #[error("lightning payment missing preimage")]
    MissingPreimage,
    #[error("rpc: {0}")]
    Rpc(#[from] RpcBlvmError),
    #[error("gate proof mapping: {0}")]
    GateProof(#[from] BlvmPaymentError),
}

/// Acquires a per-hop mesh route payment proof (separate from UKM gate payment).
#[async_trait]
pub trait MeshHopPaymentAcquirer: Send + Sync {
    async fn acquire_hop_payment(
        &self,
        destination: [u8; 32],
        amount_msat: u64,
    ) -> Result<MeshRoutePayment, MeshHopError>;
}

/// Creates and pays a Lightning invoice locally for mesh hop settlement.
///
/// Development / co-located endpoints only. Production endpoints should use
/// [`RelayMeshHopAcquirer`] so the first-hop relay issues the invoice.
pub struct LightningMeshHopAcquirer {
    lightning: Arc<dyn LightningProvider>,
    invoice_expiry_secs: u32,
}

impl LightningMeshHopAcquirer {
    pub fn new(lightning: Arc<dyn LightningProvider>) -> Self {
        Self {
            lightning,
            invoice_expiry_secs: 3600,
        }
    }

    pub fn with_invoice_expiry_secs(mut self, secs: u32) -> Self {
        self.invoice_expiry_secs = secs;
        self
    }
}

#[async_trait]
impl MeshHopPaymentAcquirer for LightningMeshHopAcquirer {
    async fn acquire_hop_payment(
        &self,
        _destination: [u8; 32],
        amount_msat: u64,
    ) -> Result<MeshRoutePayment, MeshHopError> {
        let invoice = self
            .lightning
            .create_invoice(amount_msat, "bitsov mesh hop", self.invoice_expiry_secs)
            .await?;
        let payment = self.lightning.pay_invoice(&invoice.bolt11).await?;
        build_lightning_hop_proof(
            invoice.bolt11,
            payment.preimage,
            amount_msat,
            self.invoice_expiry_secs,
        )
    }
}

/// Requests a hop invoice from the co-located blvm-node relay and pays it.
pub struct RelayMeshHopAcquirer {
    rpc: HttpBlvmMeshRpc,
    lightning: Arc<dyn LightningProvider>,
    invoice_expiry_secs: u32,
}

impl RelayMeshHopAcquirer {
    pub fn new(rpc: HttpBlvmMeshRpc, lightning: Arc<dyn LightningProvider>) -> Self {
        Self {
            rpc,
            lightning,
            invoice_expiry_secs: 3600,
        }
    }

    pub fn with_invoice_expiry_secs(mut self, secs: u32) -> Self {
        self.invoice_expiry_secs = secs;
        self
    }
}

#[async_trait]
impl MeshHopPaymentAcquirer for RelayMeshHopAcquirer {
    async fn acquire_hop_payment(
        &self,
        destination: [u8; 32],
        amount_msat: u64,
    ) -> Result<MeshRoutePayment, MeshHopError> {
        let hop = self
            .rpc
            .request_hop_invoice(destination, amount_msat, self.invoice_expiry_secs)
            .await?;
        let payment = self.lightning.pay_invoice(&hop.invoice).await?;
        build_lightning_hop_proof(
            hop.invoice,
            payment.preimage,
            hop.amount_msats,
            self.invoice_expiry_secs,
        )
    }
}

fn build_lightning_hop_proof(
    invoice: String,
    preimage_hex: Option<String>,
    amount_msats: u64,
    invoice_expiry_secs: u32,
) -> Result<MeshRoutePayment, MeshHopError> {
    let preimage_hex = preimage_hex.ok_or(MeshHopError::MissingPreimage)?;
    let preimage_bytes = hex::decode(preimage_hex.trim())
        .map_err(|e| MeshHopError::Rpc(RpcBlvmError::CallFailed(format!("preimage hex: {e}"))))?;
    let preimage: [u8; 32] = preimage_bytes.try_into().map_err(|_| {
        MeshHopError::Rpc(RpcBlvmError::CallFailed("preimage must be 32 bytes".into()))
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(MeshRoutePayment::Lightning {
        invoice,
        preimage,
        amount_msats,
        timestamp: now,
        expires_at: now + u64::from(invoice_expiry_secs),
    })
}

/// Resolve mesh route payment from UKM gate proof and optional hop acquirer.
pub async fn resolve_mesh_route_payment(
    gate_payment: &konsensus_core::gate_payment::GatePaymentProof,
    destination: [u8; 32],
    hop_msat: u64,
    payment_required: bool,
    hop_policy: MeshHopPolicy,
    acquirer: Option<&dyn MeshHopPaymentAcquirer>,
) -> Result<Option<MeshRoutePayment>, MeshHopError> {
    use crate::mesh_proof::gate_proof_to_mesh_payment;

    let route = gate_proof_to_mesh_payment(gate_payment)?;
    if route.is_some() {
        return Ok(route);
    }

    if !payment_required && hop_policy == MeshHopPolicy::Disabled {
        return Ok(None);
    }

    match hop_policy {
        MeshHopPolicy::Disabled if payment_required => Err(MeshHopError::AcquirerMissing),
        MeshHopPolicy::Disabled => Ok(None),
        MeshHopPolicy::PerSend => {
            let Some(acquirer) = acquirer else {
                return Err(MeshHopError::AcquirerMissing);
            };
            acquirer
                .acquire_hop_payment(destination, hop_msat)
                .await
                .map(Some)
        }
    }
}

/// When to acquire separate mesh hop payment for Lightning-gated UKM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MeshHopPolicy {
    /// Do not acquire hop payment (open relays or BLVM gate paths 2–3 only).
    #[default]
    Disabled,
    /// Pay a hop invoice before each mesh send.
    PerSend,
}

impl MeshHopPolicy {
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s {
            "disabled" => Some(Self::Disabled),
            "per_send" => Some(Self::PerSend),
            _ => None,
        }
    }
}

/// Where hop Lightning invoices are issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MeshHopInvoiceSource {
    /// Endpoint creates and pays its own invoice (dev / co-located LN).
    #[default]
    SelfIssue,
    /// First-hop relay issues invoice via blvm-node RPC.
    Relay,
}

impl MeshHopInvoiceSource {
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s {
            "self" => Some(Self::SelfIssue),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}
