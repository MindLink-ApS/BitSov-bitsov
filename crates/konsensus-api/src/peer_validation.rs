//! Input rules shared by owner-console and HTTP peer writers.

use crate::error::ApiError;
use konsensus_core::types::NodeId;

const MAX_PEER_LABEL_LEN: usize = 256;

pub(crate) fn validate_peer_id(node_id: &NodeId, local_id: &NodeId) -> Result<(), ApiError> {
    if node_id == local_id {
        return Err(ApiError::BadRequest(
            "cannot add this node as its own peer".into(),
        ));
    }
    Ok(())
}

/// Reject labels that can inject terminal controls or hide/reorder visible text.
/// Ordinary Unicode text is accepted; the limit is measured in UTF-8 bytes.
pub fn validate_peer_label(label: Option<&str>) -> Result<(), ApiError> {
    let Some(label) = label else {
        return Ok(());
    };
    if label.len() > MAX_PEER_LABEL_LEN {
        return Err(ApiError::BadRequest(format!(
            "peer label exceeds {MAX_PEER_LABEL_LEN} bytes"
        )));
    }
    if label.chars().any(|c| {
        c.is_control()
            || matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
        | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
    }) {
        return Err(ApiError::BadRequest(
            "peer label must not contain control or invisible formatting characters".into(),
        ));
    }
    Ok(())
}

/// A dial target must identify a unicast host and a nonzero service port.
/// Loopback, private and link-local hosts remain valid owner-supplied targets.
pub fn validate_peer_addr(addr: &std::net::SocketAddr) -> Result<(), ApiError> {
    // IPv4-mapped IPv6 must obey the same rules as native IPv4.
    let ip = addr.ip().to_canonical();
    if addr.port() == 0 || ip.is_unspecified() || ip.is_multicast() {
        return Err(ApiError::BadRequest(
            "peer address must be a unicast IP address with a nonzero port".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_limit_counts_utf8_bytes_and_allows_clearing() {
        assert!(validate_peer_label(Some(&"ø".repeat(128))).is_ok());
        assert!(validate_peer_label(Some(&format!("{}a", "ø".repeat(128)))).is_err());
        assert!(validate_peer_label(Some("")).is_ok());
        assert!(validate_peer_label(None).is_ok());
    }
}
