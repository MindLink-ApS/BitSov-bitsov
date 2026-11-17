//! HTTP JSON-RPC bridge for blvm-mesh `send_packet` (avoids direct blvm-mesh dependency).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};

use crate::mesh_route::MeshRoutePayment;
use crate::rpc::RpcBlvmError;

/// Bincode-compatible with blvm-mesh `SendPacketRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Field order matches blvm-mesh `SendPacketRequest` at `070645f`:
/// destination, payload, payment_proof, protocol_id, ttl.
/// Sequence is assigned inside blvm-mesh when the source is this node and the
/// sequence is 0. This request does not set it. `send_packet` does not wait
/// on a signed hello; discovery does.
pub struct MeshSendPacketRequest {
    pub destination: [u8; 32],
    pub payload: Vec<u8>,
    pub payment_proof: Option<MeshRoutePayment>,
    pub protocol_id: Option<String>,
    pub ttl: Option<u64>,
}

/// Response from blvm-node `meshsendpacket` RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshSendPacketResponse {
    pub success: bool,
    pub packet_id: [u8; 32],
    pub route_length: usize,
    pub estimated_cost_sats: u64,
    pub error: Option<String>,
}

impl<'de> Deserialize<'de> for MeshSendPacketResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            success: bool,
            packet_id: String,
            route_length: usize,
            estimated_cost_sats: u64,
            error: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let packet_id_bytes =
            hex::decode(raw.packet_id.trim()).map_err(serde::de::Error::custom)?;
        let packet_id: [u8; 32] = packet_id_bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("packet_id must be 32 bytes"))?;
        Ok(Self {
            success: raw.success,
            packet_id,
            route_length: raw.route_length,
            estimated_cost_sats: raw.estimated_cost_sats,
            error: raw.error,
        })
    }
}

impl Serialize for MeshSendPacketResponse {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Raw<'a> {
            success: bool,
            packet_id: String,
            route_length: usize,
            estimated_cost_sats: u64,
            error: &'a Option<String>,
        }
        Raw {
            success: self.success,
            packet_id: hex::encode(self.packet_id),
            route_length: self.route_length,
            estimated_cost_sats: self.estimated_cost_sats,
            error: &self.error,
        }
        .serialize(serializer)
    }
}

/// blvm-node `meshsendpacket` JSON-RPC client.
pub struct HttpBlvmMeshRpc {
    client: reqwest::Client,
    url: String,
    mesh_module_id: String,
    rpc_token: Option<String>,
}

impl HttpBlvmMeshRpc {
    pub fn new(
        rpc_url: impl Into<String>,
        mesh_module_id: impl Into<String>,
        rpc_token: Option<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: rpc_url.into(),
            mesh_module_id: mesh_module_id.into(),
            rpc_token,
        }
    }

    fn authorized_post(&self, url: &str) -> reqwest::RequestBuilder {
        let req = self.client.post(url);
        match &self.rpc_token {
            Some(token) if !token.is_empty() => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            _ => req,
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcBlvmError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u32,
            "method": method,
            "params": params,
        });

        let response = self
            .authorized_post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RpcBlvmError::CallFailed(e.to_string()))?;

        let status = response.status();
        let payload: Value = response
            .json()
            .await
            .map_err(|e| RpcBlvmError::CallFailed(e.to_string()))?;

        if let Some(err) = payload.get("error") {
            return Err(RpcBlvmError::CallFailed(err.to_string()));
        }

        if !status.is_success() {
            return Err(RpcBlvmError::CallFailed(format!("HTTP {status}")));
        }

        payload
            .get("result")
            .cloned()
            .ok_or_else(|| RpcBlvmError::CallFailed("missing result field".into()))
    }

    /// Send opaque payload via blvm-mesh through blvm-node RPC.
    pub async fn send_packet(
        &self,
        destination: [u8; 32],
        payload: Vec<u8>,
        protocol_id: Option<String>,
        route_payment: Option<MeshRoutePayment>,
    ) -> Result<MeshSendPacketResponse, RpcBlvmError> {
        let request = MeshSendPacketRequest {
            destination,
            payload: payload.clone(),
            payment_proof: route_payment,
            protocol_id: protocol_id.clone(),
            ttl: Some(3600),
        };
        let request_hex = hex::encode(
            bincode::serialize(&request).map_err(|e| RpcBlvmError::CallFailed(e.to_string()))?,
        );

        let result = self
            .call(
                "meshsendpacket",
                json!({
                    "request_hex": request_hex,
                    "mesh_module_id": self.mesh_module_id,
                }),
            )
            .await?;

        serde_json::from_value(result).map_err(|e| RpcBlvmError::CallFailed(e.to_string()))
    }

    /// Poll locally delivered mesh packets from blvm-node.
    pub async fn poll_received(
        &self,
        protocol_id: Option<&str>,
        max_packets: usize,
    ) -> Result<Vec<MeshPolledPacket>, RpcBlvmError> {
        let result = self
            .call(
                "meshpollreceived",
                json!({
                    "protocol_id": protocol_id,
                    "max_packets": max_packets.clamp(1, 64),
                    "mesh_module_id": self.mesh_module_id,
                }),
            )
            .await?;

        let packets = result
            .get("packets")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcBlvmError::CallFailed("missing packets array".into()))?;

        packets
            .iter()
            .map(|p| {
                let protocol_id = p
                    .get("protocol_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RpcBlvmError::CallFailed("packet missing protocol_id".into()))?
                    .to_string();
                let payload_hex = p
                    .get("payload_hex")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RpcBlvmError::CallFailed("packet missing payload_hex".into()))?;
                let payload = hex::decode(payload_hex.trim())
                    .map_err(|e| RpcBlvmError::CallFailed(format!("payload_hex: {e}")))?;
                let source_hex = p
                    .get("source_hex")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RpcBlvmError::CallFailed("packet missing source_hex".into()))?;
                let source_bytes = hex::decode(source_hex.trim())
                    .map_err(|e| RpcBlvmError::CallFailed(format!("source_hex: {e}")))?;
                let source: [u8; 32] = source_bytes
                    .try_into()
                    .map_err(|_| RpcBlvmError::CallFailed("source must be 32 bytes".into()))?;
                Ok(MeshPolledPacket {
                    protocol_id,
                    payload,
                    source,
                })
            })
            .collect()
    }

    /// Quote mesh routing fee in satoshis for a destination.
    pub async fn quote_route_fee(
        &self,
        destination: [u8; 32],
        base_fee_sats: u64,
    ) -> Result<u64, RpcBlvmError> {
        let result = self
            .call(
                "meshquoteroute",
                json!({
                    "destination_hex": hex::encode(destination),
                    "base_fee_sats": base_fee_sats,
                    "mesh_module_id": self.mesh_module_id,
                }),
            )
            .await?;

        result
            .get("fee_sats")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| RpcBlvmError::CallFailed("missing fee_sats".into()))
    }

    /// Request a relay-issued hop invoice from blvm-mesh via blvm-node RPC.
    pub async fn request_hop_invoice(
        &self,
        destination: [u8; 32],
        amount_msats: u64,
        expiry_seconds: u32,
    ) -> Result<MeshHopInvoiceResponse, RpcBlvmError> {
        let result = self
            .call(
                "meshrequesthopinvoice",
                json!({
                    "destination_hex": hex::encode(destination),
                    "amount_msats": amount_msats,
                    "expiry_seconds": expiry_seconds,
                    "mesh_module_id": self.mesh_module_id,
                }),
            )
            .await?;

        serde_json::from_value(result).map_err(|e| RpcBlvmError::CallFailed(e.to_string()))
    }
}

/// Relay-issued hop invoice from `meshrequesthopinvoice`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshHopInvoiceResponse {
    pub invoice: String,
    pub amount_msats: u64,
    pub expires_at: u64,
}

/// One locally delivered mesh packet from `meshpollreceived`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPolledPacket {
    pub protocol_id: String,
    pub payload: Vec<u8>,
    pub source: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_packet_request_bincode_roundtrip() {
        let req = MeshSendPacketRequest {
            destination: [0xAB; 32],
            payload: b"ukm".to_vec(),
            payment_proof: Some(MeshRoutePayment::OnChainSettlement {
                payment_request_id: "req-1".into(),
                tx_hash: [0x11; 32],
                amount_sats: 1000,
                timestamp: 42,
            }),
            protocol_id: Some("bitsov-ukm-v1".into()),
            ttl: Some(3600),
        };
        let bytes = bincode::serialize(&req).unwrap();
        let decoded: MeshSendPacketRequest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.destination, req.destination);
        assert_eq!(decoded.payload, req.payload);
    }

    #[test]
    fn response_deserializes_hex_packet_id() {
        let json = json!({
            "success": true,
            "packet_id": hex::encode([0xCD; 32]),
            "route_length": 2,
            "estimated_cost_sats": 100,
            "error": null
        });
        let resp: MeshSendPacketResponse = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.packet_id, [0xCD; 32]);
    }

    #[test]
    fn poll_parses_packets_array() {
        let json = json!({
            "packets": [{
                "protocol_id": "bitsov-ukm-v1",
                "payload_hex": hex::encode(b"ukm"),
                "source_hex": hex::encode([0xAB; 32]),
            }]
        });
        let packets = json["packets"].as_array().unwrap();
        assert_eq!(packets.len(), 1);
    }
}
