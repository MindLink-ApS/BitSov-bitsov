//! HTTP JSON-RPC client for blvm-node payment methods.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::rpc::{
    BlvmNodeRpc, CreatedPaymentRequest, OnChainVerification, PaymentRequestOutput,
    PaymentStateSnapshot, RpcBlvmError,
};

fn covenant_proof_bytes_from_json(value: &Value) -> Result<Vec<u8>, RpcBlvmError> {
    serde_json::to_vec(value)
        .map_err(|e| RpcBlvmError::CallFailed(format!("covenant proof encode: {e}")))
}

/// blvm-node JSON-RPC over HTTP (e.g. `http://127.0.0.1:8332/`).
pub struct HttpBlvmNodeRpc {
    client: reqwest::Client,
    url: String,
    rpc_token: Option<String>,
}

impl HttpBlvmNodeRpc {
    pub fn new(rpc_url: impl Into<String>, rpc_token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: rpc_url.into(),
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
}

#[async_trait]
impl BlvmNodeRpc for HttpBlvmNodeRpc {
    async fn verify_on_chain_payment(
        &self,
        payment_request_id: &str,
        tx_hash_hex: &str,
    ) -> Result<OnChainVerification, RpcBlvmError> {
        let result = self
            .call(
                "verifyonchainpayment",
                json!([payment_request_id, tx_hash_hex]),
            )
            .await?;

        Ok(OnChainVerification {
            verified: result
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            state: result
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            amount_sats: result.get("amount_sats").and_then(|v| v.as_u64()),
            tx_hash: result
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .map(String::from),
            reason: result
                .get("reason")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }

    async fn verify_on_chain_payment_by_tx(
        &self,
        payment_request_id: &str,
        tx_hash_hex: &str,
        min_amount_sats: u64,
    ) -> Result<OnChainVerification, RpcBlvmError> {
        let result = self
            .call(
                "verifyonchainpaymentbytx",
                json!([payment_request_id, tx_hash_hex, min_amount_sats]),
            )
            .await?;

        Ok(OnChainVerification {
            verified: result
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            state: result
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            amount_sats: result.get("amount_sats").and_then(|v| v.as_u64()),
            tx_hash: result
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .map(String::from),
            reason: result
                .get("reason")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }

    async fn verify_covenant_proof(
        &self,
        covenant_proof: &[u8],
        output_index: u32,
        amount_sats: u64,
    ) -> Result<bool, RpcBlvmError> {
        let result = self
            .call(
                "verifycovenantproof",
                json!([hex::encode(covenant_proof), output_index, amount_sats,]),
            )
            .await?;

        Ok(result
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    async fn create_payment_request(
        &self,
        outputs: &[PaymentRequestOutput],
        merchant_data: Option<&[u8]>,
        create_covenant: bool,
    ) -> Result<CreatedPaymentRequest, RpcBlvmError> {
        let outputs_json: Vec<Value> = outputs
            .iter()
            .map(|o| {
                json!({
                    "amount": o.amount_sats,
                    "script_pubkey": o.script_pubkey_hex,
                })
            })
            .collect();

        let merchant = merchant_data.map(hex::encode);
        let params = match merchant {
            Some(m) => json!([outputs_json, m, create_covenant]),
            None => json!([outputs_json, null, create_covenant]),
        };

        let result = self.call("createpaymentrequest", params).await?;
        let payment_id = result
            .get("payment_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcBlvmError::CallFailed("missing payment_id".into()))?
            .to_string();

        let covenant_proof = result
            .get("covenant_proof")
            .map(covenant_proof_bytes_from_json)
            .transpose()?;

        Ok(CreatedPaymentRequest {
            payment_id,
            covenant_proof,
        })
    }

    async fn create_covenant_proof(
        &self,
        payment_request_id: &str,
    ) -> Result<Vec<u8>, RpcBlvmError> {
        let result = self
            .call("createcovenantproof", json!([payment_request_id]))
            .await?;
        covenant_proof_bytes_from_json(&result)
    }

    async fn get_payment_state(
        &self,
        payment_request_id: &str,
    ) -> Result<PaymentStateSnapshot, RpcBlvmError> {
        let result = self
            .call("getpaymentstate", json!([payment_request_id]))
            .await?;

        Ok(PaymentStateSnapshot {
            state: result
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            tx_hash: result
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verify_on_chain_result() {
        let result = json!({
            "verified": true,
            "state": "in_mempool",
            "amount_sats": 150000,
            "tx_hash": "aa",
            "reason": null
        });
        let v = OnChainVerification {
            verified: result["verified"].as_bool().unwrap(),
            state: result["state"].as_str().unwrap().into(),
            amount_sats: result["amount_sats"].as_u64(),
            tx_hash: result["tx_hash"].as_str().map(String::from),
            reason: None,
        };
        assert!(v.verified);
        assert_eq!(v.amount_sats, Some(150_000));
    }

    #[test]
    fn parses_verify_covenant_result() {
        let result = json!({ "verified": true, "reason": null });
        assert!(result["verified"].as_bool().unwrap());
    }
}
