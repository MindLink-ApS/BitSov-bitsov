// Semgrep-only fixture: intentionally unsafe examples, never compiled.
fn tls(client: Client) {
    // ruleid: bitsov-cln-insecure-tls
    client.danger_accept_invalid_certs(true);
    // ruleid: bitsov-cln-insecure-tls
    client.tls_built_in_root_certs(true);
    // ruleid: bitsov-cln-insecure-tls
    client.danger_accept_invalid_hostnames(true);
    // ruleid: bitsov-cln-insecure-tls
    client.https_only(false);
    // ok: bitsov-cln-insecure-tls
    client.tls_built_in_root_certs(false);
}
// ruleid: bitsov-cln-rune-debug
#[derive(Debug)]
struct Leaks { rune: String }
// ok: bitsov-cln-rune-debug
#[derive(Clone)]
struct Secret { rune: String }
fn leaks(rune: String, cmd: Command, request: Request) {
    // ruleid: bitsov-cln-rune-exposure
    info!(rune = %rune, "leak");
    // ruleid: bitsov-cln-rune-exposure
    format!("https://localhost/?rune={rune}");
    // ruleid: bitsov-cln-rune-exposure
    cmd.arg(rune);
    // ruleid: bitsov-cln-rune-exposure
    request.json(&rune);
    // ok: bitsov-cln-rune-exposure
    request.header("Rune", self.rune.clone());
    // ok: bitsov-cln-rune-exposure
    f.debug_struct("ClnProvider").field("rune", &"<redacted>");
}
fn money(provider: Provider) {
    // ruleid: bitsov-cln-uncapped-payment
    json!({"invstring": invoice, "retry_for": 60});
    // ruleid: bitsov-cln-uncapped-payment
    json!({"destination": dest, "amount_msat": 1000});
    // ok: bitsov-cln-uncapped-payment
    json!({"invstring": invoice, "maxfee": 0, "retry_for": 60});
    // ok: bitsov-cln-uncapped-payment
    json!({"destination": dest, "amount_msat": 1000, "maxfee": ceiling});
    // ruleid: bitsov-cln-legacy-pay
    provider.rpc("pay", params);
    // ok: bitsov-cln-legacy-pay
    provider.rpc("xpay", params);
    // ruleid: bitsov-cln-clear-payment-guard
    self.payment_capable.store(true, Ordering::Relaxed);
    // ruleid: bitsov-cln-clear-payment-guard
    attempts.remove(&hash);
    // ok: bitsov-cln-clear-payment-guard
    self.payment_capable.store(false, Ordering::Relaxed);
    // ok: bitsov-cln-clear-payment-guard
    attempts.insert(hash);
}
impl UnsafeTransport {
    // ruleid: bitsov-cln-post-not-dispatched
    async fn rpc(&self, method: &str, params: Value) -> Result<Value, LightningError> {
        self.client.post(endpoint).send().await
            .map_err(|_| LightningError::PaymentNotDispatched("timeout".into()))?;
        Ok(json!({}))
    }
}
impl SafeTransport {
    // ok: bitsov-cln-post-not-dispatched
    async fn rpc(&self, method: &str, params: Value) -> Result<Value, LightningError> {
        self.client.post(endpoint).send().await
            .map_err(|_| LightningError::Backend("ambiguous".into()))?;
        Ok(json!({}))
    }
}
