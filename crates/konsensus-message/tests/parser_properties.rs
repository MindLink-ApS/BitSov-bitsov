//! Length-prefixed frames must reject or defer malformed input without panicking
//! or allocating a body for a prefix that already exceeds the cap.

use proptest::prelude::*;

proptest! {
    #[test]
    fn decode_frame_arbitrary_bytes_do_not_panic(
        buf in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let _ = konsensus_message::wire::decode_frame(&buf);
    }

    #[test]
    fn oversized_prefix_is_rejected_before_a_body_is_required(
        len in (konsensus_message::wire::MAX_FRAME_SIZE as u32 + 1)..=u32::MAX,
        tail in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut buf = len.to_be_bytes().to_vec();
        buf.extend_from_slice(&tail);
        let err = konsensus_message::wire::decode_frame(&buf).unwrap_err();
        assert!(matches!(
            err,
            konsensus_message::wire::WireError::FrameTooLarge { .. }
        ));
    }
}
