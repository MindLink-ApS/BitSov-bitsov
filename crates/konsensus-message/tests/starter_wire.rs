use konsensus_message::wire::{
    decode_frame, encode_frame, Frame, MAX_LN_ADDR_BYTES, MAX_LN_PUBKEY_BYTES,
    MAX_STARTER_CHANNEL_ID_BYTES, MAX_STARTER_LN_PUBKEY_BYTES, MAX_STARTER_LN_SIG_BYTES,
    MAX_STARTER_NETWORK_BYTES, MAX_STARTER_REASON_BYTES, MAX_STARTER_STATE_BYTES,
    MAX_STARTER_TXID_BYTES,
};
#[test]
fn starter_control_frames_round_trip_without_amounts_in_request() {
    let request = Frame::StarterRequest {
        v: 1,
        request_id: uuid::Uuid::new_v4(),
        network: "regtest".into(),
        ln_pubkey: "02".repeat(33),
        ln_sig: "signature".into(),
    };
    let encoded = encode_frame(&request).unwrap();
    assert!(matches!(
        decode_frame(&encoded).unwrap().unwrap().0,
        Frame::StarterRequest { v: 1, .. }
    ));
}

#[test]
fn starter_status_preserves_refusal_and_original_identity() {
    let original = uuid::Uuid::new_v4();
    let frame = Frame::StarterStatus {
        request_id: uuid::Uuid::new_v4(),
        state: "refused".into(),
        reason: Some("already_served".into()),
        retry_after_unix: Some(1234),
        original_request_id: Some(original),
        capacity_sats: None,
        push_sats: None,
        channel_id: None,
        funding_txid: None,
    };
    let bytes = encode_frame(&frame).unwrap();
    assert!(
        matches!(decode_frame(&bytes).unwrap().unwrap().0,Frame::StarterStatus{original_request_id:Some(id),retry_after_unix:Some(1234),..} if id==original)
    );
}

fn starter_request(network: &str, ln_pubkey: &str, ln_sig: &str) -> Frame {
    Frame::StarterRequest {
        v: 1,
        request_id: uuid::Uuid::nil(),
        network: network.into(),
        ln_pubkey: ln_pubkey.into(),
        ln_sig: ln_sig.into(),
    }
}

fn starter_status(
    state: &str,
    reason: Option<&str>,
    channel_id: Option<&str>,
    funding_txid: Option<&str>,
) -> Frame {
    Frame::StarterStatus {
        request_id: uuid::Uuid::nil(),
        state: state.into(),
        reason: reason.map(str::to_owned),
        retry_after_unix: None,
        original_request_id: None,
        capacity_sats: None,
        push_sats: None,
        channel_id: channel_id.map(str::to_owned),
        funding_txid: funding_txid.map(str::to_owned),
    }
}

fn decodes(frame: &Frame) -> bool {
    Frame::from_bytes(&frame.to_bytes().unwrap()).is_ok()
}

#[test]
fn starter_and_lightning_info_strings_reject_one_byte_past_the_cap() {
    let pubkey = "02".repeat(33);
    assert!(decodes(&starter_request(
        &"n".repeat(MAX_STARTER_NETWORK_BYTES),
        &pubkey,
        "sig"
    )));
    assert!(!decodes(&starter_request(
        &"n".repeat(MAX_STARTER_NETWORK_BYTES + 1),
        &pubkey,
        "sig"
    )));
    assert!(decodes(&starter_request(
        "regtest",
        &"k".repeat(MAX_STARTER_LN_PUBKEY_BYTES),
        "sig"
    )));
    assert!(!decodes(&starter_request(
        "regtest",
        &"k".repeat(MAX_STARTER_LN_PUBKEY_BYTES + 1),
        "sig"
    )));
    assert!(decodes(&starter_request(
        "regtest",
        &pubkey,
        &"s".repeat(MAX_STARTER_LN_SIG_BYTES)
    )));
    assert!(!decodes(&starter_request(
        "regtest",
        &pubkey,
        &"s".repeat(MAX_STARTER_LN_SIG_BYTES + 1)
    )));

    assert!(decodes(&starter_status(
        &"t".repeat(MAX_STARTER_STATE_BYTES),
        None,
        None,
        None
    )));
    assert!(!decodes(&starter_status(
        &"t".repeat(MAX_STARTER_STATE_BYTES + 1),
        None,
        None,
        None
    )));
    assert!(decodes(&starter_status(
        "refused",
        Some(&"r".repeat(MAX_STARTER_REASON_BYTES)),
        Some(&"c".repeat(MAX_STARTER_CHANNEL_ID_BYTES)),
        Some(&"f".repeat(MAX_STARTER_TXID_BYTES)),
    )));
    assert!(!decodes(&starter_status(
        "refused",
        Some(&"r".repeat(MAX_STARTER_REASON_BYTES + 1)),
        None,
        None,
    )));
    assert!(!decodes(&starter_status(
        "refused",
        None,
        Some(&"c".repeat(MAX_STARTER_CHANNEL_ID_BYTES + 1)),
        None,
    )));
    assert!(!decodes(&starter_status(
        "refused",
        None,
        None,
        Some(&"f".repeat(MAX_STARTER_TXID_BYTES + 1)),
    )));

    let info = Frame::LightningInfo {
        ln_pubkey: "k".repeat(MAX_LN_PUBKEY_BYTES),
        ln_addr: Some("a".repeat(MAX_LN_ADDR_BYTES - ":9735".len()) + ":9735"),
    };
    assert!(decodes(&info));
    let over_key = Frame::LightningInfo {
        ln_pubkey: "k".repeat(MAX_LN_PUBKEY_BYTES + 1),
        ln_addr: None,
    };
    assert!(!decodes(&over_key));
    let over_addr = Frame::LightningInfo {
        ln_pubkey: pubkey,
        ln_addr: Some("a".repeat(MAX_LN_ADDR_BYTES + 1)),
    };
    assert!(!decodes(&over_addr));
}

#[test]
fn starter_status_null_strings_and_lightning_info_without_addr_still_decode() {
    let status = starter_status("refused", None, None, None);
    let decoded = Frame::from_bytes(&status.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        decoded,
        Frame::StarterStatus {
            reason: None,
            channel_id: None,
            funding_txid: None,
            ..
        }
    ));
    let info = Frame::LightningInfo {
        ln_pubkey: "02".repeat(33),
        ln_addr: None,
    };
    let decoded = Frame::from_bytes(&info.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        decoded,
        Frame::LightningInfo { ln_addr: None, .. }
    ));
}
