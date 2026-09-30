//! Rooms MVP on this node: the optional room binding on chat
//! ([`konsensus_core::payloads::room`]). Checked on compose, before any quote
//! or payment, and on receive, after the payment gate (a refused chat is
//! withdrawn like a refused call signal). The node keeps no room state.

use konsensus_core::kind::KIND_CHAT;
use konsensus_core::payloads::room::{RoomBinding, RoomChat, RoomRefusal, ROOM_BINDING_CAPABILITY};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::NodeId;

use crate::error::ApiError;

/// A member's node does not list the capability; nothing was paid.
pub const UNSUPPORTED: &str = "room_binding_unsupported";
/// A member without an E2EE session was skipped; nothing was paid.
pub const NO_SESSION: &str = "room_member_no_session";

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

pub(crate) fn refused(e: RoomRefusal) -> ApiError {
    ApiError::BadRequest(e.to_string()).with_reason(e.code())
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
/// and the member's node lists the capability. Refused before any payment.
pub(crate) async fn check_one(transport: &dyn MessageTransport, own: &NodeId, peer: &NodeId, room: &RoomBinding) -> Result<(), ApiError> {
    room.check(own, peer).map_err(refused)?;
    if !advertises(transport, peer).await {
        return Err(ApiError::BadRequest(format!(
            "their node does not advertise {ROOM_BINDING_CAPABILITY} (not connected, or an older node); nothing was paid"
        ))
        .with_reason(UNSUPPORTED));
    }
    Ok(())
}
