//! BSX parsing is size-capped and must not panic on hostile documents.

use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_bsx_arbitrary_bytes_do_not_panic(
        buf in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let _ = konsensus_bsx::parse_bsx(&buf);
    }

    #[test]
    fn oversize_document_is_rejected_before_json(
        extra in 1usize..64
    ) {
        let buf = vec![b'{'; konsensus_bsx::MAX_DOCUMENT_SIZE + extra];
        let err = konsensus_bsx::parse_bsx(&buf).unwrap_err();
        assert!(matches!(err, konsensus_bsx::ParseError::TooLarge { .. }));
    }
}
