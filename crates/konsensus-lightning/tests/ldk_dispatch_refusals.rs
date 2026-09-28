use std::sync::Arc;
use konsensus_core::traits::lightning::{LightningError, LightningProvider};
use konsensus_lightning::LdkProvider;

#[tokio::test(flavor = "multi_thread")]
async fn real_ldk_route_refusals_are_not_dispatched_and_preserve_capability() {
    let mut server = mockito::Server::new_async().await;
    let fees = server.mock("GET", "/fee-estimates").with_status(200).with_body("{}").create_async().await;
    let dir = tempfile::tempdir().unwrap();
    let mut builder = ldk_node::Builder::new();
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
    builder.set_entropy_seed_bytes([42; 64]);
    builder.set_listening_addresses(vec![]).unwrap();
    builder.set_gossip_source_p2p();
    builder.set_chain_source_esplora(server.url(), Some(ldk_node::config::EsploraSyncConfig {
        background_sync_config: None, ..Default::default()
    }));
    let node = Arc::new(builder.build().unwrap());
    node.start().unwrap();
    let provider = LdkProvider::from_node(node.clone());
    let invoice = provider.create_stateless_invoice(1000, "no channels", 3600).await.unwrap();
    for result in [
        provider.pay_invoice_with_fee_limit(&invoice.bolt11, 0).await,
        provider.keysend_with_fee_limit(&node.node_id().to_string(), 1000, None, 0).await,
        provider.keysend_with_binding(&node.node_id().to_string(), 1000, b"binding").await,
    ] {
        assert!(matches!(result, Err(LightningError::PaymentNotDispatched(_))), "{result:?}");
        assert!(provider.is_payment_capable().await);
    }
    assert!(node.list_payments().iter().all(|p| p.status == ldk_node::payment::PaymentStatus::Failed));
    // Existing failed hash is still single-use. Callers request a fresh invoice.
    assert!(matches!(provider.pay_invoice_with_fee_limit(&invoice.bolt11, 5000).await,
        Err(LightningError::PaymentNotDispatched(reason)) if reason.contains("fresh invoice hash")));
    node.stop().unwrap();
    fees.assert_async().await;
}
