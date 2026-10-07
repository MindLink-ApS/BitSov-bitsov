//! Configured hub-only channel opens at the owner HTTP boundary, in-process:
//! no sockets and no money. The backend records every open that reaches it.
use super::test_common as common;
use super::*;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_lightning::RecoveringLightning;
use std::sync::Mutex;
use tower::ServiceExt;

const HUB: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const STRANGER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

#[derive(Default)]
struct OpenRecorder {
    opened: Mutex<Vec<String>>,
}
impl OpenRecorder {
    fn opened(&self) -> Vec<String> {
        self.opened.lock().unwrap().clone()
    }
    fn record(&self, peer: &str) -> ChannelOpenResult {
        self.opened.lock().unwrap().push(peer.to_string());
        ChannelOpenResult {
            channel_id: "channel".into(),
            funding_txid: None,
            status: ChannelOpenStatus::Opening,
            funding_fee: None,
        }
    }
}
#[async_trait]
impl LightningProvider for OpenRecorder {
    async fn create_invoice(&self, a: u64, d: &str, e: u32) -> Result<Invoice, LightningError> {
        StubLightning.create_invoice(a, d, e).await
    }
    async fn pay_invoice(&self, i: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.pay_invoice(i).await
    }
    async fn get_payment_status(&self, h: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.get_payment_status(h).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn open_channel(
        &self,
        peer: &str,
        _addr: &str,
        _amount: u64,
        _announce: bool,
        _rate: Option<f32>,
    ) -> Result<String, LightningError> {
        Ok(self.record(peer).channel_id)
    }
    async fn open_channel_with_status(
        &self,
        peer: &str,
        _addr: &str,
        _amount: u64,
        _announce: bool,
        _rate: Option<f32>,
    ) -> Result<ChannelOpenResult, LightningError> {
        Ok(self.record(peer))
    }
    async fn open_channel_with_funding(
        &self,
        peer: &str,
        _addr: &str,
        _amount: u64,
        _announce: bool,
        _options: FundingOptions,
    ) -> Result<ChannelOpenResult, LightningError> {
        Ok(self.record(peer))
    }
}

fn hub_only() -> ChannelPeers {
    ChannelPeers::HubOnly(Arc::from([HUB.to_string()]))
}

async fn guarded(
    backend: Arc<OpenRecorder>,
    channel_peers: ChannelPeers,
) -> (tempfile::TempDir, Arc<RecoveringLightning>, Arc<GuardedLightning>) {
    let dir = tempfile::tempdir().unwrap();
    let recovering = Arc::new(
        RecoveringLightning::new(
            move || {
                let backend = backend.clone();
                async move { Ok(backend as Arc<dyn LightningProvider>) }
            },
            Default::default(),
        )
        .await
        .unwrap(),
    );
    tokio::task::yield_now().await;
    assert!(recovering.money_ready().await);
    let provider = Arc::new(GuardedLightning {
        inner: recovering.clone(),
        disk: Arc::new(DiskGuard::new(dir.path().into(), 0)),
        channel_peers,
        _state_guard: Arc::new(
            crate::safety::ensure_generation(dir.path(), crate::safety::STATE_GENERATION).unwrap(),
        ),
    });
    (dir, recovering, provider)
}

async fn open_over_api(channel_peers: ChannelPeers, peer: &str) -> (StatusCode, serde_json::Value, Vec<String>) {
    let backend = Arc::new(OpenRecorder::default());
    let (_dir, recovering, provider) = guarded(backend.clone(), channel_peers).await;
    let state = test_state_with_lightning(provider);
    let body = serde_json::json!({"peer_pubkey": peer, "peer_addr": "127.0.0.1:9735", "amount_sats": 50000});
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/payments/open-channel")
                .header("authorization", auth_header(&state))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    recovering.shutdown().await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap(), backend.opened())
}

#[tokio::test]
async fn hub_only_api_open_to_the_hub_reaches_the_backend() {
    for peer in [HUB.to_string(), HUB.to_ascii_uppercase()] {
        let (status, body, opened) = open_over_api(hub_only(), &peer).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["channel_id"], "channel");
        assert_eq!(opened, vec![peer]);
    }
}

#[tokio::test]
async fn hub_only_api_open_to_another_peer_is_refused_before_the_backend() {
    let (status, body, opened) = open_over_api(hub_only(), STRANGER).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], HUB_ONLY_WHILE_LOCKABLE);
    assert_eq!(body["retry_allowed"], false);
    assert!(opened.is_empty(), "refused open reached the backend: {opened:?}");
}

#[tokio::test]
async fn hub_only_refuses_every_open_entry_point_including_auto_channel() {
    let backend = Arc::new(OpenRecorder::default());
    let (_dir, recovering, provider) = guarded(backend.clone(), hub_only()).await;
    // `open_channel` is the auto-channel worker's path; the other two serve the API.
    let refused = [
        provider.open_channel(STRANGER, "127.0.0.1:9735", 50000, false, None).await.map(|_| ()),
        provider.open_channel_with_status(STRANGER, "127.0.0.1:9735", 50000, false, None).await.map(|_| ()),
        provider
            .open_channel_with_funding(STRANGER, "127.0.0.1:9735", 50000, false, Default::default())
            .await
            .map(|_| ()),
    ];
    for result in refused {
        assert!(
            matches!(result, Err(LightningError::PaymentNotDispatched(ref r)) if r == HUB_ONLY_WHILE_LOCKABLE),
            "{result:?}"
        );
    }
    assert!(backend.opened().is_empty());
    provider.open_channel(HUB, "127.0.0.1:9735", 50000, false, None).await.unwrap();
    provider.open_channel_with_status(HUB, "127.0.0.1:9735", 50000, false, None).await.unwrap();
    provider
        .open_channel_with_funding(HUB, "127.0.0.1:9735", 50000, false, Default::default())
        .await
        .unwrap();
    recovering.shutdown().await.unwrap();
    assert_eq!(backend.opened(), vec![HUB.to_string(); 3]);
}

#[tokio::test]
async fn explicit_opt_out_allows_any_peer() {
    for peer in [HUB, STRANGER] {
        let (status, body, opened) = open_over_api(
            ChannelPeers::from_config(
                &toml::from_str("backend = 'ldk'\nhub_only_channels = false").unwrap(),
            )
            .unwrap(),
            peer,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(opened, vec![peer.to_string()]);
    }
}

#[test]
fn hub_only_policy_is_the_configured_liquidity_providers() {
    let ldk = |extra: &str| -> crate::config::LightningConfig {
        toml::from_str(&format!(
            "backend = 'ldk'\n[liquidity]\n[[liquidity.providers]]\nnode_id = '{HUB}'\naddress = '127.0.0.1:9735'\n{extra}"
        ))
        .unwrap()
    };
    assert_eq!(ChannelPeers::hub_only(&ldk("")).unwrap().allowlist(), Some(vec![HUB.to_string()]));
    assert_eq!(ChannelPeers::Any.allowlist(), None);
    let error = ChannelPeers::hub_only(&ldk("[lsps2_service]\nenabled = true\nrequire_token = 't'"))
        .unwrap_err();
    assert!(error.to_string().starts_with(HUB_ONLY_WHILE_LOCKABLE), "{error}");
    // Backends without a configured hub refuse every peer.
    let mock: crate::config::LightningConfig = toml::from_str("backend = 'mock'").unwrap();
    assert_eq!(ChannelPeers::hub_only(&mock).unwrap().allowlist(), Some(vec![]));
}

#[test]
fn home_config_enforces_hubs_without_a_startup_flag_and_allows_explicit_opt_out() {
    let config = |extra: &str| -> crate::config::LightningConfig {
        toml::from_str(&format!("backend = 'ldk'\n{extra}")).unwrap()
    };
    assert_eq!(
        ChannelPeers::from_config(&config("")).unwrap().allowlist(),
        Some(vec![])
    );
    assert_eq!(
        ChannelPeers::from_config(&config("hub_only_channels = false"))
            .unwrap()
            .allowlist(),
        None
    );
    let legacy = config(&format!(
        "lsp_node_id = '{HUB}'\nlsp_address = '127.0.0.1:9735'"
    ));
    assert_eq!(
        ChannelPeers::from_config(&legacy).unwrap().allowlist(),
        Some(vec![HUB.into()])
    );
    let service = config("[lsps2_service]\nenabled = true\nrequire_token = 't'");
    assert_eq!(
        ChannelPeers::from_config(&service).unwrap().allowlist(),
        None
    );
    assert!(ChannelPeers::from_config(&config(
        "hub_only_channels = true\n[lsps2_service]\nenabled = true\nrequire_token = 't'"
    ))
    .is_err());
}

#[tokio::test]
async fn default_home_config_refuses_non_hub_over_owner_api() {
    let config = toml::from_str(&format!(
        "backend = 'ldk'\n[[liquidity.providers]]\nnode_id = '{HUB}'\naddress = '127.0.0.1:9735'"
    ))
    .unwrap();
    let (status, body, opened) =
        open_over_api(ChannelPeers::from_config(&config).unwrap(), STRANGER).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], HUB_ONLY_WHILE_LOCKABLE);
    assert!(opened.is_empty());
}

#[tokio::test]
async fn owner_status_reports_real_backend_policy_through_wrappers_but_public_health_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let mut builder = ldk_node::Builder::from_config(ldk_node::config::Config {
        channel_limits: Some(ldk_node::channel_limits::ChannelLimits::new(50_000, 80_000)),
        channel_peer_allowlist: Some(vec![HUB.parse().unwrap()]),
        ..Default::default()
    });
    builder.set_network(ldk_node::bitcoin::Network::Regtest);
    builder.set_storage_dir_path(dir.path().join("ldk").to_str().unwrap().into());
    builder.set_entropy_seed_bytes([93; 64]);
    let node = Arc::new(builder.build().unwrap());
    let backend = Arc::new(konsensus_lightning::LdkProvider::from_node(node));
    let recovering = Arc::new(
        RecoveringLightning::new(
            move || {
                let backend = backend.clone();
                async move { Ok(backend as Arc<dyn LightningProvider>) }
            },
            Default::default(),
        )
        .await
        .unwrap(),
    );
    let provider = Arc::new(GuardedLightning {
        inner: recovering.clone(),
        disk: Arc::new(DiskGuard::new(dir.path().into(), 0)),
        channel_peers: hub_only(),
        _state_guard: Arc::new(
            crate::safety::ensure_generation(dir.path(), crate::safety::STATE_GENERATION).unwrap(),
        ),
    });
    let state = test_state_with_lightning(provider);
    for (path, authorized) in [
        ("/api/v1/status", false),
        ("/api/v1/status", true),
        ("/api/v1/health", false),
    ] {
        let mut request = Request::builder().uri(path);
        if authorized {
            request = request.header("authorization", auth_header(&state));
        }
        let response = test_router(state.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        if path == "/api/v1/status" && !authorized {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            continue;
        }
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 100_000)
                .await
                .unwrap(),
        )
        .unwrap();
        if authorized {
            assert_eq!(
                body["channel_safety"],
                serde_json::json!({
                    "max_channel_capacity_sats": 50_000,
                    "max_total_channel_capacity_sats": 80_000,
                    "hub_only": true,
                })
            );
        } else {
            assert!(body.get("channel_safety").is_none());
        }
    }
    // The real test backend was deliberately never started; stop reports NotRunning.
    let error = recovering.shutdown().await.unwrap_err();
    assert!(error.to_string().contains("not running"), "{error}");
}
