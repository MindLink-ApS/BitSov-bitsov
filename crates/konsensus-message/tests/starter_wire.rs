use konsensus_message::wire::{decode_frame, encode_frame, Frame};
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
