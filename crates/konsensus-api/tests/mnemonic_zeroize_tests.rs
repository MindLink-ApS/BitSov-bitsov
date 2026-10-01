//! Type-level regression checks for deserialized recovery material.

use konsensus_api::bootstrap::FirstRunRestoreBody;
use konsensus_api::handlers::identity::VerifyMnemonicRequest;
use konsensus_api::handlers::pairing_routes::ReplacementRequestBody;
use zeroize::{ZeroizeOnDrop, Zeroizing};

fn assert_zeroizing(value: &Zeroizing<String>) {
    fn assert_drop<T: ZeroizeOnDrop>(_: &T) {}
    assert_drop(value);
    assert_eq!(value.as_str(), "abandon abandon about");
}

#[test]
fn mnemonic_request_fields_are_zeroizing() {
    let json = r#"{"mnemonic":"abandon abandon about"}"#;
    let verify: VerifyMnemonicRequest = serde_json::from_str(json).unwrap();
    let restore: FirstRunRestoreBody = serde_json::from_str(json).unwrap();
    let replacement: ReplacementRequestBody = serde_json::from_str(json).unwrap();
    assert_zeroizing(&verify.mnemonic);
    assert_zeroizing(&restore.mnemonic);
    assert_zeroizing(&replacement.mnemonic);
}

#[test]
fn owner_socket_mnemonic_is_zeroizing() {
    let request: konsensus_api::control::ControlRequest = serde_json::from_str(
        r#"{"op":"approve-replacement","op_id":"test","confirmation":"test","mnemonic":"abandon abandon about"}"#,
    ).unwrap();
    let konsensus_api::control::ControlRequest::ApproveReplacement { mnemonic, .. } = request
    else {
        panic!("expected replacement");
    };
    assert_zeroizing(&mnemonic);
}

// Ambiguous inference makes this fail to compile if a sensitive request gains
// any of these traits, including through a future derive.
macro_rules! assert_not_impl {
    ($request:ty, $bound:path) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            struct Implemented;
            impl<T: ?Sized + $bound> AmbiguousIfImpl<Implemented> for T {}
            let _ = <$request as AmbiguousIfImpl<_>>::check;
        };
    };
}

macro_rules! assert_secret_request {
    ($request:ty) => {
        assert_not_impl!($request, std::fmt::Debug);
        assert_not_impl!($request, Clone);
        assert_not_impl!($request, serde::Serialize);
    };
}

assert_secret_request!(VerifyMnemonicRequest);
assert_secret_request!(FirstRunRestoreBody);
assert_secret_request!(ReplacementRequestBody);
assert_secret_request!(konsensus_api::control::ControlRequest);
