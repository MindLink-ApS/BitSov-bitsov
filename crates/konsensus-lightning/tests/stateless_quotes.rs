use konsensus_core::traits::lightning::LightningProvider;
use konsensus_lightning::ldk::LdkProvider;
use std::{collections::BTreeMap, path::Path, sync::Arc};

fn disk_snapshot(root: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, files);
            } else {
                files.insert(path.strip_prefix(root).unwrap().into(), std::fs::read(path).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[test]
fn ldk_quote_does_not_write_payment_or_disk_state() {
    // Unstarted regtest object, fixed disposable seed, no network or funds.
    let dir = tempfile::tempdir().unwrap();
    let mut builder = ldk_node::Builder::new();
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_entropy_seed_bytes([42; 64]);
    builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
    let node = Arc::new(builder.build().unwrap());
    let provider = LdkProvider::from_node(node.clone());
    let before = disk_snapshot(dir.path());
    assert!(node.list_payments().is_empty());
    let invoice = futures::executor::block_on(provider.create_stateless_invoice(2000, "bound quote", 55)).unwrap();
    assert!(node.list_payments().is_empty(), "quote created a pending payment");
    assert_eq!(before, disk_snapshot(dir.path()), "quote changed durable storage");
    let signed: lightning_invoice::Bolt11Invoice = invoice.bolt11.parse().unwrap();
    assert_eq!(signed.recover_payee_pub_key(), node.node_id());
    assert_eq!(signed.amount_milli_satoshis(), Some(2000));
    assert_eq!(signed.description().to_string(), "bound quote");
    assert_eq!(signed.expiry_time().as_secs(), 55);
}

#[tokio::test]
async fn lnd_and_lnbits_fail_closed_without_invoice_rpc() {
    use konsensus_lightning::{lnd::{LndConfig, LndProvider}, lnbits::{LnbitsConfig, LnbitsProvider}};
    use konsensus_core::traits::lightning::LightningError;
    let lnd = LndProvider::new(LndConfig {
        api_url: "http://127.0.0.1:1".into(), macaroon_hex: "00".into(), tls_cert_path: None,
    }).unwrap();
    let lnbits = LnbitsProvider::new(LnbitsConfig {
        api_url: "http://127.0.0.1:1".into(), admin_key: "disposable".into(),
    }).unwrap();
    for backend in [&lnd as &dyn LightningProvider, &lnbits as &dyn LightningProvider] {
        let error = backend.create_stateless_invoice(2000, "quote", 55).await.unwrap_err();
        assert!(matches!(error, LightningError::StatelessQuoteUnsupported));
        assert_eq!(error.to_string(), "stateless_quote_unsupported");
    }
}
