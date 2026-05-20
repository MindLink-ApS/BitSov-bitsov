//! BSX document parser.
//!
//! Parses a raw JSON byte slice or string into a validated [`BsxPage`].
//! Enforces size limits and structural constraints at parse time.

use crate::model::{BsxPage, MAX_DOCUMENT_SIZE};

/// Errors that can occur during BSX document parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Document exceeds the maximum allowed size.
    #[error("document too large: {size} bytes exceeds {max} byte limit")]
    TooLarge {
        /// Actual document size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// JSON deserialization failed.
    #[error("invalid BSX JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// Document is empty.
    #[error("empty document")]
    Empty,
}

/// Parse a BSX document from a JSON byte slice.
///
/// Enforces [`MAX_DOCUMENT_SIZE`] before attempting deserialization.
///
/// # Errors
///
/// Returns [`ParseError`] if the input is too large, empty, or not valid BSX JSON.
pub fn parse_bsx(input: &[u8]) -> Result<BsxPage, ParseError> {
    if input.is_empty() {
        return Err(ParseError::Empty);
    }
    if input.len() > MAX_DOCUMENT_SIZE {
        return Err(ParseError::TooLarge {
            size: input.len(),
            max: MAX_DOCUMENT_SIZE,
        });
    }
    let doc: BsxPage = serde_json::from_slice(input)?;
    Ok(doc)
}

/// Parse a BSX document from a JSON string.
///
/// Convenience wrapper around [`parse_bsx`].
///
/// # Errors
///
/// Returns [`ParseError`] if the input is too large, empty, or not valid BSX JSON.
pub fn parse_bsx_str(input: &str) -> Result<BsxPage, ParseError> {
    parse_bsx(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_document() {
        let json = r#"{
            "meta": { "title": "Hello" },
            "blocks": [{ "type": "text", "content": "World" }]
        }"#;
        let doc = parse_bsx_str(json).unwrap();
        assert_eq!(doc.meta.title, "Hello");
        assert_eq!(doc.blocks.len(), 1);
    }

    #[test]
    fn parse_empty_input() {
        let err = parse_bsx(b"").unwrap_err();
        assert!(matches!(err, ParseError::Empty));
    }

    #[test]
    fn parse_too_large() {
        let huge = vec![b' '; MAX_DOCUMENT_SIZE + 1];
        let err = parse_bsx(&huge).unwrap_err();
        match err {
            ParseError::TooLarge { size, max } => {
                assert_eq!(size, MAX_DOCUMENT_SIZE + 1);
                assert_eq!(max, MAX_DOCUMENT_SIZE);
            }
            _ => panic!("expected TooLarge, got {err:?}"),
        }
    }

    #[test]
    fn parse_invalid_json() {
        let err = parse_bsx(b"not json").unwrap_err();
        assert!(matches!(err, ParseError::InvalidJson(_)));
    }

    #[test]
    fn parse_unknown_field_rejected() {
        let json = r#"{
            "meta": { "title": "Test", "unknown_field": true },
            "blocks": []
        }"#;
        let err = parse_bsx_str(json).unwrap_err();
        assert!(matches!(err, ParseError::InvalidJson(_)));
    }

    #[test]
    fn parse_all_block_types() {
        let json = r##"{
            "meta": { "title": "All Blocks" },
            "resources": [
                { "hash": "blake3:abc123", "mime_type": "image/webp", "size_bytes": 1000 }
            ],
            "style_hints": { "accent_color": "#336699", "font_preference": "sans-serif" },
            "blocks": [
                { "type": "text", "content": "Hello **world**" },
                { "type": "heading", "level": 1, "text": "Title" },
                { "type": "image", "resource_hash": "blake3:abc123", "caption": "Photo" },
                { "type": "code", "content": "fn main() {}", "language": "rust" },
                { "type": "table", "headers": ["A", "B"], "rows": [["1", "2"]] },
                { "type": "divider" },
                { "type": "quote", "content": "Be sovereign", "attribution": "Satoshi" },
                { "type": "list", "ordered": true, "items": ["one", "two"] },
                { "type": "card", "title": "Info", "content": "Card body" },
                { "type": "form", "fields": [{"name": "email", "label": "Email", "field_type": "email"}], "submit_label": "Send" },
                { "type": "embed", "source_pubkey": "deadbeef", "path": "/about" },
                { "type": "audio", "resource_hash": "blake3:abc123" },
                { "type": "video", "resource_hash": "blake3:abc123" },
                { "type": "grid", "columns": 2, "items": [{"type": "text", "content": "col1"}, {"type": "text", "content": "col2"}] },
                { "type": "callout", "variant": "warning", "content": "Careful!" },
                { "type": "feed", "entries": [{"title": "Post 1", "path": "/blog/1"}] }
            ]
        }"##;
        let doc = parse_bsx_str(json).unwrap();
        assert_eq!(doc.blocks.len(), 16);
        assert_eq!(doc.resources.len(), 1);
        assert!(doc.style_hints.is_some());
    }

    #[test]
    fn parse_document_with_payment_meta() {
        let json = r#"{
            "meta": {
                "title": "Paid Content",
                "payment": { "amount_sats": 25 },
                "author_pubkey": "abc123"
            },
            "blocks": [{ "type": "text", "content": "Premium content" }]
        }"#;
        let doc = parse_bsx_str(json).unwrap();
        assert_eq!(doc.meta.payment.unwrap().amount_sats, 25);
    }
}
