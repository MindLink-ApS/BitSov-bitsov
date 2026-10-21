//! Parsers must return an error for malformed input. They must not panic.

use proptest::prelude::*;

proptest! {
    #[test]
    fn introduction_and_invite_parse_do_not_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..600)
    ) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = konsensus_core::introduction::Introduction::parse(&text);
        let _ = konsensus_core::InviteToken::parse(&text);
        let _ = konsensus_core::InviteToken::parse_uri(&text);
    }

    #[test]
    fn introduction_oversize_is_rejected(
        extra in proptest::collection::vec(any::<u8>(), 0..32)
    ) {
        let mut text = "a".repeat(konsensus_core::introduction::MAX_ENCODED_LEN + 1);
        text.push_str(&String::from_utf8_lossy(&extra));
        let err = konsensus_core::introduction::Introduction::parse(&text).unwrap_err();
        assert!(matches!(
            err,
            konsensus_core::introduction::IntroductionError::TooLarge(_)
        ));
    }
}
