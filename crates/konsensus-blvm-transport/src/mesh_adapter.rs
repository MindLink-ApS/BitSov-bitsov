//! Mesh fallback via `MeshPacketSender` (wired to `MeshClient` at node bootstrap).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use konsensus_blvm_payment::MeshRoutePayment;
use konsensus_core::traits::transport::TransportError;
use konsensus_core::types::NodeId;
use tracing::debug;

use crate::address_book::MeshAddressBook;
use crate::hybrid::MeshFallback;
use crate::mesh_sender::MeshPacketSender;

/// UKM mesh fallback using a node-provided `MeshPacketSender`.
pub struct MeshSenderFallback {
    sender: Arc<dyn MeshPacketSender>,
    address_book: Option<Arc<dyn MeshAddressBook>>,
    route_payment: Mutex<Option<MeshRoutePayment>>,
}

impl MeshSenderFallback {
    pub fn new(sender: Arc<dyn MeshPacketSender>) -> Self {
        Self {
            sender,
            address_book: None,
            route_payment: Mutex::new(None),
        }
    }

    pub fn with_address_book(
        sender: Arc<dyn MeshPacketSender>,
        address_book: Arc<dyn MeshAddressBook>,
    ) -> Self {
        Self {
            sender,
            address_book: Some(address_book),
            route_payment: Mutex::new(None),
        }
    }

    pub fn with_route_payment(
        sender: Arc<dyn MeshPacketSender>,
        payment: MeshRoutePayment,
    ) -> Self {
        Self {
            sender,
            address_book: None,
            route_payment: Mutex::new(Some(payment)),
        }
    }

    pub fn set_route_payment(&self, payment: Option<MeshRoutePayment>) {
        *self.route_payment.lock().unwrap() = payment;
    }
}

#[async_trait]
impl MeshFallback for MeshSenderFallback {
    async fn send_via_mesh(
        &self,
        destination: &NodeId,
        payload: &[u8],
        protocol_id: &str,
        route_payment: Option<MeshRoutePayment>,
    ) -> Result<(), TransportError> {
        let payment = route_payment.or_else(|| self.route_payment.lock().unwrap().clone());
        let mesh_dest = if let Some(book) = &self.address_book {
            book.resolve_mesh_destination(destination).await?
        } else {
            *destination.as_bytes()
        };
        debug!(
            dest = %destination.to_hex(),
            mesh_dest = %hex::encode(mesh_dest),
            protocol_id,
            has_route_payment = payment.is_some(),
            payload_len = payload.len(),
            "mesh sender fallback"
        );
        self.sender
            .send_mesh_packet(
                mesh_dest,
                payload.to_vec(),
                protocol_id.to_string(),
                payment,
            )
            .await
    }
}
