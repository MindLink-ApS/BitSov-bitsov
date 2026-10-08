use konsensus_chain::EsploraConfig;

#[test]
fn endpoint_debug_redacts_url_credentials() {
    for url in [
        "https://alice:private-url-password@localhost:8080",
        "https://localhost:8080?api_key=private-url-password",
        "https://localhost:8080#private-url-password",
    ] {
        let mut config = EsploraConfig::mempool_space();
        config.api_url = url.into();
        for output in [format!("{config:?}"), format!("{config:#?}")] {
            assert!(!output.contains("private-url-password"));
            assert!(output.contains("<redacted>"));
            assert!(output.contains("trust_level"));
            assert!(output.contains("timeout_secs"));
        }
    }
    let config = EsploraConfig::mempool_space();
    assert!(format!("{config:?}").contains(&config.api_url));
}
