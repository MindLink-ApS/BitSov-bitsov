use super::*;
use konsensus_core::kind::*;

fn engine() -> StaticPricingEngine {
    StaticPricingEngine::new(StaticPricingConfig::default())
}

#[tokio::test]
async fn chat_price() {
    let e = engine();
    assert_eq!(e.get_price_msat(KIND_CHAT).await.unwrap(), 10);
    assert_eq!(e.get_price_msat(KIND_REPLY).await.unwrap(), 10);
    assert_eq!(e.get_price_msat(KIND_REACTION).await.unwrap(), 10);
}

#[tokio::test]
async fn longform_price_uses_longform_msat() {
    let e = engine();
    // KIND_LONGFORM (1) is Communication but uses longform_msat (50), not chat_msat (10)
    assert_eq!(e.get_price_msat(KIND_LONGFORM).await.unwrap(), 50);
}

#[tokio::test]
async fn structured_data_price() {
    let e = engine();
    assert_eq!(e.get_price_msat(KIND_CALENDAR_EVENT).await.unwrap(), 25);
    assert_eq!(e.get_price_msat(KIND_RSVP).await.unwrap(), 25);
    assert_eq!(e.get_price_msat(KIND_CONTACT).await.unwrap(), 25);
    assert_eq!(e.get_price_msat(KIND_PROFILE).await.unwrap(), 25);
    assert_eq!(e.get_price_msat(KIND_CALENDAR_UPDATE).await.unwrap(), 25);
}

#[tokio::test]
async fn file_price() {
    let e = engine();
    assert_eq!(e.get_price_msat(KIND_FILE_REF).await.unwrap(), 100);
    assert_eq!(e.get_price_msat(KIND_INLINE_IMAGE).await.unwrap(), 100);
    assert_eq!(e.get_price_msat(KIND_VOICE_MEMO).await.unwrap(), 100);
}

#[tokio::test]
async fn collaboration_price() {
    let e = engine();
    assert_eq!(e.get_price_msat(KIND_CRDT_OP).await.unwrap(), 25);
    assert_eq!(e.get_price_msat(KIND_DOC_SNAPSHOT).await.unwrap(), 25);
}

#[tokio::test]
async fn control_price() {
    let e = engine();
    assert_eq!(e.get_price_msat(KIND_TYPING).await.unwrap(), 1);
    assert_eq!(e.get_price_msat(KIND_READ_RECEIPT).await.unwrap(), 1);
    assert_eq!(e.get_price_msat(KIND_MLS_WELCOME).await.unwrap(), 1);
    assert_eq!(e.get_price_msat(KIND_KEY_EXCHANGE).await.unwrap(), 1);
}

#[tokio::test]
async fn app_extension_price() {
    let e = engine();
    assert_eq!(e.get_price_msat(1000).await.unwrap(), 10);
    assert_eq!(e.get_price_msat(1500).await.unwrap(), 10);
}

#[tokio::test]
async fn realtime_signaling_price() {
    let e = engine();
    assert_eq!(e.get_price_msat(KIND_CALL_INVITE).await.unwrap(), 50);
    assert_eq!(e.get_price_msat(KIND_CALL_ANSWER).await.unwrap(), 50);
    assert_eq!(e.get_price_msat(KIND_ICE_CANDIDATE).await.unwrap(), 50);
}

#[tokio::test]
async fn web_content_price() {
    let e = engine();
    assert_eq!(e.get_price_msat(KIND_PAGE_REQUEST).await.unwrap(), 50);
    assert_eq!(e.get_price_msat(KIND_PAGE_RESPONSE).await.unwrap(), 50);
    assert_eq!(e.get_price_msat(KIND_WEB_MANIFEST).await.unwrap(), 50);
}

#[tokio::test]
async fn relay_storage_category_price() {
    let e = engine();
    assert_eq!(
        e.get_category_price_msat(KindCategory::Storage)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn unknown_kind_not_priceable() {
    let e = engine();
    assert!(e.get_price_msat(600).await.is_err());
    assert!(e.get_price_msat(800).await.is_err());
}

#[tokio::test]
async fn category_pricing() {
    let e = engine();
    assert_eq!(
        e.get_category_price_msat(KindCategory::Communication)
            .await
            .unwrap(),
        10
    );
    assert_eq!(
        e.get_category_price_msat(KindCategory::StructuredData)
            .await
            .unwrap(),
        25
    );
    assert_eq!(
        e.get_category_price_msat(KindCategory::FilesMedia)
            .await
            .unwrap(),
        100
    );
    assert_eq!(
        e.get_category_price_msat(KindCategory::RealTimeSignaling)
            .await
            .unwrap(),
        50
    );
    assert_eq!(
        e.get_category_price_msat(KindCategory::Storage)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn custom_config() {
    let config = StaticPricingConfig {
        chat_msat: 50,
        longform_msat: 200,
        calendar_msat: 100,
        file_ref_msat: 500,
        control_msat: 5,
        collaboration_msat: 75,
        realtime_signal_msat: 90,
        app_ext_msat: 25,
        web_content_msat: 100,
        relay_storage_msat_per_byte_day: 3,
    };
    let e = StaticPricingEngine::new(config);

    assert_eq!(e.get_price_msat(KIND_CHAT).await.unwrap(), 50);
    assert_eq!(e.get_price_msat(KIND_LONGFORM).await.unwrap(), 200);
    assert_eq!(e.get_price_msat(KIND_FILE_REF).await.unwrap(), 500);
    assert_eq!(e.get_price_msat(KIND_TYPING).await.unwrap(), 5);
    assert_eq!(e.get_price_msat(KIND_CALL_INVITE).await.unwrap(), 90);
    assert_eq!(
        e.get_category_price_msat(KindCategory::Storage)
            .await
            .unwrap(),
        3
    );
}

#[test]
fn default_config_matches_toml_example() {
    let config = StaticPricingConfig::default();
    assert_eq!(config.chat_msat, 10);
    assert_eq!(config.longform_msat, 50);
    assert_eq!(config.calendar_msat, 25);
    assert_eq!(config.file_ref_msat, 100);
    assert_eq!(config.control_msat, 1);
    assert_eq!(config.realtime_signal_msat, 50);
    assert_eq!(config.relay_storage_msat_per_byte_day, 1);
}

#[test]
fn deny_unknown_fields_rejects_typos() {
    let json = r#"{"chat_msat":10,"longform_msat":50,"calendar_msat":25,"file_ref_msat":100,"control_msat":1,"collaboration_msat":25,"app_ext_msat":10,"web_content_msat":50,"typo_field":999}"#;
    let result: Result<StaticPricingConfig, _> = serde_json::from_str(json);
    assert!(result.is_err(), "unknown fields should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field"),
        "error should mention unknown field: {err}"
    );
}
