use axum::{routing::post, Json, Router};
use konsensus_chain::{BitcoindConfig, BitcoindProvider};
use konsensus_core::traits::chain::{ChainProvider, TrustLevel};
use serde_json::{json, Value};

#[test]
fn file_auth_validation_and_redaction() {
    for auth in [
        json!({"cookie_file":"/tmp/core.cookie"}),
        json!({"rpc_user":"bitsov","rpc_password_file":"/tmp/core.pass"}),
    ] {
        let mut config = auth;
        config["rpc_host"] = json!("localhost");
        config["rpc_port"] = json!(18443);
        assert!(serde_json::from_value::<BitcoindConfig>(config).is_ok());
    }
    for extra in [
        json!({"rpc_password":"SECRET"}),
        json!({"rpc_host":"user:SECRET@localhost"}),
        json!({"rpc_host":"http://localhost"}),
        json!({"rpc_user":"bitsov"}),
        json!({"rpc_password_file":"/tmp/pass"}),
    ] {
        let mut config =
            json!({"rpc_host":"localhost","rpc_port":18443,"cookie_file":"/tmp/core.cookie"});
        config
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(serde_json::from_value::<BitcoindConfig>(config).is_err());
    }
}

#[tokio::test]
async fn rpc_data_pruned_confirmation_and_cookie_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let cookie = dir.path().join(".cookie");
    std::fs::write(&cookie, "user:secret\n").unwrap();
    let app = Router::new().route("/", post(|headers: axum::http::HeaderMap, Json(request): Json<Value>| async move {
        // A rotated cookie must be loaded for the next RPC request.
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert_eq!(auth, if request["method"] == "getblockcount" {
            "Basic dXNlcjpzZWNyZXQ="
        } else { "Basic dXNlcjpuZXc=" });
        let result = match request["method"].as_str().unwrap() {
            "getblockcount" => json!(101),
            "getblockchaininfo" => json!({"blocks":101,"headers":101,"initialblockdownload":false,"pruned":true,"pruneheight":100}),
            "getblockhash" => json!("ab".repeat(32)),
            "getblockheader" => json!({"height":101,"hash":"ab".repeat(32),"time":1700000000,"bits":"207fffff"}),
            "estimatesmartfee" => json!({"feerate":0.00002,"blocks":6}),
            "getrawtransaction" => return Json(json!({"result":null,"error":{"code":-5,"message":"SECRET must not escape"},"id":1})),
            "getblock" => json!({"confirmations":2,"tx":["cd".repeat(32)]}),
            _ => panic!("unexpected RPC"),
        };
        Json(json!({"result":result,"error":null,"id":1}))
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config: BitcoindConfig = serde_json::from_value(
        json!({"rpc_host":"127.0.0.1","rpc_port":port,"cookie_file":cookie}),
    )
    .unwrap();
    let provider = BitcoindProvider::new(config).unwrap();
    assert_eq!(provider.trust_level(), TrustLevel::FullValidation);
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    std::fs::write(&cookie, "user:new\n").unwrap();
    assert!(provider.is_synced().await);
    let header = provider.get_block_header(101).await.unwrap();
    assert_eq!(header.bits, 0x207fffff);
    assert_eq!(header.timestamp, 1700000000);
    assert_eq!(provider.estimate_fee(6).await.unwrap().sat_per_vbyte, 2.0);
    assert!(provider.is_tx_confirmed(&"cd".repeat(32), 2).await.unwrap());
    assert!(!provider.is_tx_confirmed(&"cd".repeat(32), 3).await.unwrap());
    assert!(provider.is_tx_confirmed(&"CD".repeat(32), 2).await.unwrap());
    let error = provider
        .is_tx_confirmed(&"ef".repeat(32), 1)
        .await
        .unwrap_err()
        .to_string();
    assert!(!error.contains("SECRET"));
    server.abort();
}

#[test]
fn password_file_contents_are_read_without_trimming_password_spaces() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rpc.pass");
    std::fs::write(&path, " SECRET with spaces \n").unwrap();
    let config: BitcoindConfig = serde_json::from_value(json!({
        "rpc_host":"::1", "rpc_port":18443, "rpc_user":"bitsov", "rpc_password_file":path
    }))
    .unwrap();
    let (user, password) = config.credentials().unwrap();
    assert_eq!(user.as_str(), "bitsov");
    assert_eq!(password.as_str(), " SECRET with spaces ");
    assert!(!format!("{config:?}").contains("SECRET"));
    assert!(!serde_json::to_string(&config).unwrap().contains("SECRET"));
    std::fs::write(&path, "SECRET\nbad").unwrap();
    assert!(!config
        .credentials()
        .unwrap_err()
        .to_string()
        .contains("SECRET"));
}
