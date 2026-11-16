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
        identity_sig: vec![],
    };
    assert!(decodes(&info));
    let over_key = Frame::LightningInfo {
        ln_pubkey: "k".repeat(MAX_LN_PUBKEY_BYTES + 1),
        ln_addr: None,
        identity_sig: vec![],
    };
    assert!(!decodes(&over_key));
    let over_addr = Frame::LightningInfo {
        ln_pubkey: pubkey,
        ln_addr: Some("a".repeat(MAX_LN_ADDR_BYTES + 1)),
        identity_sig: vec![],
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
        identity_sig: vec![],
    };
    let decoded = Frame::from_bytes(&info.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        decoded,
        Frame::LightningInfo { ln_addr: None, .. }
    ));
}

#[test]
fn starter_status_omitted_optional_strings_decode_as_none() {
    for omitted in [
        vec!["reason"],
        vec!["channel_id"],
        vec!["funding_txid"],
        vec!["reason", "channel_id", "funding_txid"],
    ] {
        let mut value = serde_json::to_value(starter_status("received", None, None, None)).unwrap();
        for field in omitted {
            value["StarterStatus"]
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
        let decoded = Frame::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            decoded,
            Frame::StarterStatus {
                reason: None,
                channel_id: None,
                funding_txid: None,
                ..
            }
        ));
    }
}

#[test]
fn lightning_address_accepts_maximum_dns_hostname_and_five_digit_port() {
    let host = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(host.len(), 253);
    let addr = format!("{host}:65535");
    assert_eq!(addr.len(), 259);
    assert!(decodes(&Frame::LightningInfo {
        ln_pubkey: "02".repeat(33),
        ln_addr: Some(addr),
        identity_sig: vec![],
    }));
}

#[test]
fn bounded_strings_count_decoded_utf8_bytes_and_preserve_escapes() {
    for (encoded, decoded) in [
        (r"\u0061".repeat(32), "a".repeat(32)),
        (r"\u00e9".repeat(16), "é".repeat(16)),
        (r"\u20ac".repeat(10) + "ab", "€".repeat(10) + "ab"),
        (r"\ud83d\ude00".repeat(8), "😀".repeat(8)),
        (r#"\"\\\/\b\f\n\r\t"#.into(), "\"\\/\u{8}\u{c}\n\r\t".into()),
        ("é".repeat(16), "é".repeat(16)),
    ] {
        let json = format!(
            r#"{{"StarterRequest":{{"v":1,"request_id":"00000000-0000-0000-0000-000000000000","network":"{encoded}","ln_pubkey":"02","ln_sig":"sig"}}}}"#
        );
        let frame = Frame::from_bytes(json.as_bytes()).unwrap();
        assert!(matches!(frame, Frame::StarterRequest { network, .. } if network == decoded));
        if decoded.len() == 32 {
            assert!(Frame::from_bytes(
                json.replace(&format!("\"{encoded}\""), &format!("\"{encoded}x\""))
                    .as_bytes()
            )
            .is_err());
        }
    }
    for malformed in [r"\ud800", r"\udc00", r"\ud800\u0061", r"\uZZZZ", r"\x"] {
        let json = format!(r#"{{"LightningInfo":{{"ln_pubkey":"{malformed}"}}}}"#);
        assert!(Frame::from_bytes(json.as_bytes()).is_err());
    }
}

proptest::proptest! {
    #[test]
    fn bounded_string_unicode_encodings_match_decoded_byte_limit(
        chars in proptest::collection::vec(proptest::char::any(), 0..40)
    ) {
        let value: String = chars.into_iter().collect();
        let escaped: String = value.encode_utf16().map(|unit| format!(r"\u{unit:04x}")).collect();
        for token in [serde_json::to_string(&value).unwrap(), format!("\"{escaped}\"")] {
            let json = format!(r#"{{"StarterRequest":{{"v":1,"request_id":"00000000-0000-0000-0000-000000000000","network":{token},"ln_pubkey":"02","ln_sig":"sig"}}}}"#);
            let result = Frame::from_bytes(json.as_bytes());
            if value.len() <= MAX_STARTER_NETWORK_BYTES {
                let Frame::StarterRequest { network, .. } = result.unwrap() else { unreachable!() };
                proptest::prop_assert_eq!(network, value.as_str());
            } else {
                proptest::prop_assert!(result.is_err());
            }
        }
    }
}

#[test]
fn frame_depth_guard_counts_containers_but_not_escaped_string_contents() {
    // Two outer objects plus 126 arrays reaches the frame depth cap.
    for (arrays, accepted) in [(126, true), (127, false)] {
        let nested = format!("{}0{}", "[".repeat(arrays), "]".repeat(arrays));
        let json = format!(r#"{{"LightningInfo":{{"ln_pubkey":"02","ignored":{nested}}}}}"#);
        assert_eq!(Frame::from_bytes(json.as_bytes()).is_ok(), accepted);
    }
    let value = "\"\\[{]}".repeat(256);
    let json = serde_json::json!({"LightningInfo": {"ln_pubkey": "02", "ignored": value}});
    assert!(Frame::from_bytes(&serde_json::to_vec(&json).unwrap()).is_ok());
}
