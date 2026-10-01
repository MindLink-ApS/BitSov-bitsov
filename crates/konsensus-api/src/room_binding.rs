//! Rooms MVP on this node: the optional room binding on chat
//! ([`konsensus_core::payloads::room`]). Checked on compose, before any quote
//! or payment, and on receive, after the payment gate and decryption: every
//! incoming chat is held (invisible to history, plaintext, resync and
//! duplicate ACKs) from before its paid acceptance until this check passes,
//! and a refused one is withdrawn like a refused call signal. The node keeps
//! no room state.

use konsensus_core::kind::KIND_CHAT;
use konsensus_core::payloads::room::{RoomBinding, RoomChat, RoomRefusal, ROOM_BINDING_CAPABILITY};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::NodeId;

use crate::error::ApiError;
use crate::state::AppState;

/// A member's node does not list the capability; nothing was paid.
pub const UNSUPPORTED: &str = "room_binding_unsupported";
/// A member without an E2EE session was skipped; nothing was paid.
pub const NO_SESSION: &str = "room_member_no_session";

/// Whether an incoming message of `kind` may carry a binding, so it is held
/// (invisible) from its paid acceptance until [`admit_incoming`] passes.
pub fn is_candidate(kind: u16) -> bool {
    kind == KIND_CHAT
}

/// The binding a chat carries, if any. Other kinds never carry one.
pub fn binding(kind: u16, plaintext: &str) -> Result<Option<RoomBinding>, RoomRefusal> {
    if kind != KIND_CHAT {
        return Ok(None);
    }
    Ok(RoomChat::parse(plaintext)?.map(|chat| chat.room))
}

/// Admit a chat this node (`own`) received from `sender` (after the gate). A
/// refusal must not reach the app. Undecryptable chat carries no binding we
/// can see and is admitted as before.
pub fn admit_incoming(own: &NodeId, sender: &NodeId, kind: u16, plaintext: Option<&str>) -> Result<Option<RoomBinding>, RoomRefusal> {
    let Some(text) = plaintext else { return Ok(None) };
    let Some(room) = binding(kind, text)? else { return Ok(None) };
    room.check(sender, own)?;
    Ok(Some(room))
}

/// A compose-side refusal, always before any quote or payment: `not_dispatched`
/// (#115) lets a client release its reservation, `reason` names the rule.
pub(crate) fn refused(e: RoomRefusal) -> ApiError {
    ApiError::NotDispatched(e.to_string()).with_reason(e.code())
}

/// The binding of a chat we (`own`) compose, which must list us.
pub(crate) fn outgoing(own: &NodeId, kind: u16, plaintext: &str) -> Result<Option<RoomBinding>, ApiError> {
    let Some(room) = binding(kind, plaintext).map_err(refused)? else { return Ok(None) };
    if !room.contains(own) {
        return Err(refused(RoomRefusal::SenderNotMember));
    }
    Ok(Some(room))
}

/// Whether `peer`'s live connection advertised [`ROOM_BINDING_CAPABILITY`].
pub async fn advertises(transport: &dyn MessageTransport, peer: &NodeId) -> bool {
    let want = format!("Custom({ROOM_BINDING_CAPABILITY:?})");
    transport.peer_info(peer).await.is_some_and(|info| info.capabilities.contains(&want))
}

/// A room-bound chat to one member (not a fan-out): both ends in the roster,
/// the member's node lists the capability, and we have an E2EE session (a
/// room never pays a first contact). Refused before any payment.
pub(crate) async fn check_one(state: &AppState, own: &NodeId, peer: &NodeId, room: &RoomBinding) -> Result<(), ApiError> {
    room.check(own, peer).map_err(refused)?;
    if !advertises(state.transport.as_ref(), peer).await {
        return Err(ApiError::NotDispatched(format!(
            "their node does not advertise {ROOM_BINDING_CAPABILITY} (not connected, or an older node); nothing was paid"
        ))
        .with_reason(UNSUPPORTED));
    }
    if !state.session_manager.has_session(peer).await {
        return Err(no_session());
    }
    Ok(())
}

/// No E2EE session with the member: a room never pays a first contact.
pub(crate) fn no_session() -> ApiError {
    ApiError::NotDispatched("no E2EE session with this member; nothing was paid".into()).with_reason(NO_SESSION)
}
