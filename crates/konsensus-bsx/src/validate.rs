//! BSX document validation.
//!
//! Validates a parsed [`BsxPage`] against structural constraints:
//! block counts, resource limits, text lengths, heading levels, table
//! dimensions, etc. Returns hard errors and soft warnings separately.

use crate::model::{
    BsxBlock, BsxPage, MAX_BLOCKS, MAX_FORM_FIELDS, MAX_GRID_COLS, MAX_LIST_ITEMS,
    MAX_RESOURCES, MAX_TABLE_COLS, MAX_TABLE_ROWS, MAX_TEXT_LENGTH,
};
use crate::sanitize::{extract_markdown_links, is_allowed_link};

/// A hard validation error — the document cannot be rendered.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    /// Too many blocks.
    #[error("too many blocks: {count} exceeds limit of {max}")]
    TooManyBsxBlocks {
        /// Actual block count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many resources.
    #[error("too many resources: {count} exceeds limit of {max}")]
    TooManyResources {
        /// Actual resource count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Text content exceeds the maximum length.
    #[error("block {index}: text too long ({length} bytes, max {max})")]
    TextTooLong {
        /// BsxBlock index.
        index: usize,
        /// Actual text length.
        length: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid heading level (must be 1-6).
    #[error("block {index}: invalid heading level {level} (must be 1-6)")]
    InvalidHeadingLevel {
        /// BsxBlock index.
        index: usize,
        /// The invalid level.
        level: u8,
    },

    /// Table has too many rows.
    #[error("block {index}: table has {count} rows (max {max})")]
    TooManyTableRows {
        /// BsxBlock index.
        index: usize,
        /// Actual row count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Table has too many columns.
    #[error("block {index}: table has {count} columns (max {max})")]
    TooManyTableCols {
        /// BsxBlock index.
        index: usize,
        /// Actual column count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// List has too many items.
    #[error("block {index}: list has {count} items (max {max})")]
    TooManyListItems {
        /// BsxBlock index.
        index: usize,
        /// Actual item count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Form has too many fields.
    #[error("block {index}: form has {count} fields (max {max})")]
    TooManyFormFields {
        /// BsxBlock index.
        index: usize,
        /// Actual field count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Grid has too many columns.
    #[error("block {index}: grid has {columns} columns (max {max})")]
    TooManyGridCols {
        /// BsxBlock index.
        index: usize,
        /// Actual column count.
        columns: u8,
        /// Maximum allowed.
        max: usize,
    },

    /// Grid column count is zero.
    #[error("block {index}: grid has 0 columns")]
    ZeroGridCols {
        /// BsxBlock index.
        index: usize,
    },

    /// Resource hash does not use the required blake3: prefix.
    #[error("resource {index}: hash must start with 'blake3:' (got '{hash}')")]
    InvalidResourceHash {
        /// Resource index.
        index: usize,
        /// The invalid hash string.
        hash: String,
    },

    /// Image/audio/video references a resource hash not declared in resources.
    #[error("block {index}: references undeclared resource hash '{hash}'")]
    UndeclaredResource {
        /// BsxBlock index.
        index: usize,
        /// The missing hash.
        hash: String,
    },

    /// Empty title in metadata.
    #[error("document title is empty")]
    EmptyTitle,

    /// Link uses a forbidden scheme (only `bitsov://` and relative paths allowed).
    #[error("block {index}: link uses forbidden scheme '{url}' (only bitsov:// allowed)")]
    ForbiddenLinkScheme {
        /// BsxBlock index.
        index: usize,
        /// The offending URL.
        url: String,
    },
}

/// A soft validation warning — the document can still be rendered but
/// something looks suspicious.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationWarning {
    /// No blocks in the document.
    EmptyDocument,
    /// Style hint has an invalid accent color.
    InvalidAccentColor(String),
    /// Table row has fewer cells than headers.
    InconsistentTableRow {
        /// BsxBlock index.
        block_index: usize,
        /// Row index.
        row_index: usize,
        /// Expected column count.
        expected: usize,
        /// Actual cell count.
        actual: usize,
    },
}

/// Validation result containing errors and warnings.
#[derive(Debug)]
pub struct ValidationResult {
    /// Hard errors that prevent rendering.
    pub errors: Vec<ValidationError>,
    /// Soft warnings.
    pub warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    /// Returns true if there are no hard errors.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate a parsed BSX document.
///
/// Returns a [`ValidationResult`] containing all errors and warnings found.
/// The caller decides whether to reject or render based on the result.
pub fn validate_document(doc: &BsxPage) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Title
    if doc.meta.title.trim().is_empty() {
        errors.push(ValidationError::EmptyTitle);
    }

    // BsxBlock count
    let block_count = count_blocks_recursive(&doc.blocks);
    if block_count > MAX_BLOCKS {
        errors.push(ValidationError::TooManyBsxBlocks {
            count: block_count,
            max: MAX_BLOCKS,
        });
    }

    // Resource count
    if doc.resources.len() > MAX_RESOURCES {
        errors.push(ValidationError::TooManyResources {
            count: doc.resources.len(),
            max: MAX_RESOURCES,
        });
    }

    // Resource hash format
    for (i, res) in doc.resources.iter().enumerate() {
        if !res.hash.starts_with("blake3:") {
            errors.push(ValidationError::InvalidResourceHash {
                index: i,
                hash: res.hash.clone(),
            });
        }
    }

    // Style hints
    if let Some(ref hints) = doc.style_hints {
        if let Some(ref color) = hints.accent_color {
            if !is_valid_hex_color(color) {
                warnings.push(ValidationWarning::InvalidAccentColor(color.clone()));
            }
        }
    }

    // Empty document
    if doc.blocks.is_empty() {
        warnings.push(ValidationWarning::EmptyDocument);
    }

    // Collect declared resource hashes for reference checking.
    let declared_hashes: std::collections::HashSet<&str> =
        doc.resources.iter().map(|r| r.hash.as_str()).collect();

    // BsxBlock-level validation
    validate_blocks(&doc.blocks, &declared_hashes, &mut errors, &mut warnings);

    ValidationResult { errors, warnings }
}

fn validate_blocks(
    blocks: &[BsxBlock],
    declared_hashes: &std::collections::HashSet<&str>,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    for (i, block) in blocks.iter().enumerate() {
        validate_block(i, block, declared_hashes, errors, warnings);
    }
}

fn validate_block(
    index: usize,
    block: &BsxBlock,
    declared_hashes: &std::collections::HashSet<&str>,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    match block {
        BsxBlock::Text { content } => {
            check_text_length(index, content, errors);
            check_link_schemes(index, content, errors);
        }
        BsxBlock::Heading { level, text } => {
            if *level == 0 || *level > 6 {
                errors.push(ValidationError::InvalidHeadingLevel {
                    index,
                    level: *level,
                });
            }
            check_text_length(index, text, errors);
            check_link_schemes(index, text, errors);
        }
        BsxBlock::Image { resource_hash, .. } => {
            check_resource_ref(index, resource_hash, declared_hashes, errors);
        }
        BsxBlock::Code { content, .. } => {
            check_text_length(index, content, errors);
        }
        BsxBlock::Table {
            headers, rows, ..
        } => {
            if headers.len() > MAX_TABLE_COLS {
                errors.push(ValidationError::TooManyTableCols {
                    index,
                    count: headers.len(),
                    max: MAX_TABLE_COLS,
                });
            }
            if rows.len() > MAX_TABLE_ROWS {
                errors.push(ValidationError::TooManyTableRows {
                    index,
                    count: rows.len(),
                    max: MAX_TABLE_ROWS,
                });
            }
            for (ri, row) in rows.iter().enumerate() {
                if row.len() != headers.len() {
                    warnings.push(ValidationWarning::InconsistentTableRow {
                        block_index: index,
                        row_index: ri,
                        expected: headers.len(),
                        actual: row.len(),
                    });
                }
            }
        }
        BsxBlock::Quote { content, .. } => {
            check_text_length(index, content, errors);
            check_link_schemes(index, content, errors);
        }
        BsxBlock::List { items, .. } => {
            if items.len() > MAX_LIST_ITEMS {
                errors.push(ValidationError::TooManyListItems {
                    index,
                    count: items.len(),
                    max: MAX_LIST_ITEMS,
                });
            }
            for item in items {
                check_link_schemes(index, item, errors);
            }
        }
        BsxBlock::Card { content, .. } => {
            check_text_length(index, content, errors);
            check_link_schemes(index, content, errors);
        }
        BsxBlock::Form { fields, .. } => {
            if fields.len() > MAX_FORM_FIELDS {
                errors.push(ValidationError::TooManyFormFields {
                    index,
                    count: fields.len(),
                    max: MAX_FORM_FIELDS,
                });
            }
        }
        BsxBlock::Audio { resource_hash, .. } => {
            check_resource_ref(index, resource_hash, declared_hashes, errors);
        }
        BsxBlock::Video { resource_hash, .. } => {
            check_resource_ref(index, resource_hash, declared_hashes, errors);
        }
        BsxBlock::Grid { columns, items } => {
            if *columns == 0 {
                errors.push(ValidationError::ZeroGridCols { index });
            } else if *columns as usize > MAX_GRID_COLS {
                errors.push(ValidationError::TooManyGridCols {
                    index,
                    columns: *columns,
                    max: MAX_GRID_COLS,
                });
            }
            // Recursively validate grid children.
            validate_blocks(items, declared_hashes, errors, warnings);
        }
        BsxBlock::Callout { content, .. } => {
            check_text_length(index, content, errors);
            check_link_schemes(index, content, errors);
        }
        BsxBlock::Feed { entries } => {
            for entry in entries {
                if entry.title.len() > MAX_TEXT_LENGTH {
                    errors.push(ValidationError::TextTooLong {
                        index,
                        length: entry.title.len(),
                        max: MAX_TEXT_LENGTH,
                    });
                }
            }
        }
        BsxBlock::Divider {} | BsxBlock::Embed { .. } => {}
    }
}

fn check_link_schemes(index: usize, text: &str, errors: &mut Vec<ValidationError>) {
    for url in extract_markdown_links(text) {
        if !is_allowed_link(url) {
            errors.push(ValidationError::ForbiddenLinkScheme {
                index,
                url: url.to_string(),
            });
        }
    }
}

fn check_text_length(index: usize, text: &str, errors: &mut Vec<ValidationError>) {
    if text.len() > MAX_TEXT_LENGTH {
        errors.push(ValidationError::TextTooLong {
            index,
            length: text.len(),
            max: MAX_TEXT_LENGTH,
        });
    }
}

fn check_resource_ref(
    index: usize,
    hash: &str,
    declared: &std::collections::HashSet<&str>,
    errors: &mut Vec<ValidationError>,
) {
    if !declared.contains(hash) {
        errors.push(ValidationError::UndeclaredResource {
            index,
            hash: hash.to_string(),
        });
    }
}

fn count_blocks_recursive(blocks: &[BsxBlock]) -> usize {
    let mut count = blocks.len();
    for block in blocks {
        if let BsxBlock::Grid { items, .. } = block {
            count += count_blocks_recursive(items);
        }
    }
    count
}

fn is_valid_hex_color(s: &str) -> bool {
    if !s.starts_with('#') {
        return false;
    }
    let hex = &s[1..];
    matches!(hex.len(), 3 | 6) && hex.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn minimal_doc() -> BsxPage {
        BsxPage {
            meta: BsxMeta {
                title: "Test".into(),
                author_pubkey: None,
                payment: None,
                description: None,
                created_at: None,
                updated_at: None,
            },
            style_hints: None,
            resources: vec![],
            blocks: vec![BsxBlock::Text {
                content: "Hello".into(),
            }],
        }
    }

    #[test]
    fn valid_minimal_document() {
        let result = validate_document(&minimal_doc());
        assert!(result.is_valid());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn empty_title_is_error() {
        let mut doc = minimal_doc();
        doc.meta.title = "".into();
        let result = validate_document(&doc);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::EmptyTitle)));
    }

    #[test]
    fn too_many_blocks() {
        let mut doc = minimal_doc();
        doc.blocks = (0..MAX_BLOCKS + 1)
            .map(|_| BsxBlock::Divider {})
            .collect();
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::TooManyBsxBlocks { .. })));
    }

    #[test]
    fn too_many_resources() {
        let mut doc = minimal_doc();
        doc.resources = (0..MAX_RESOURCES + 1)
            .map(|i| BsxResource {
                hash: format!("blake3:hash{i}"),
                mime_type: "image/webp".into(),
                size_bytes: 100,
                alt: None,
            })
            .collect();
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::TooManyResources { .. })));
    }

    #[test]
    fn invalid_resource_hash() {
        let mut doc = minimal_doc();
        doc.resources = vec![BsxResource {
            hash: "sha256:nope".into(),
            mime_type: "image/webp".into(),
            size_bytes: 100,
            alt: None,
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::InvalidResourceHash { .. })));
    }

    #[test]
    fn undeclared_resource_reference() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Image {
            resource_hash: "blake3:missing".into(),
            caption: None,
            alt: None,
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::UndeclaredResource { .. })));
    }

    #[test]
    fn valid_resource_reference() {
        let mut doc = minimal_doc();
        doc.resources = vec![BsxResource {
            hash: "blake3:abc123".into(),
            mime_type: "image/webp".into(),
            size_bytes: 1000,
            alt: None,
        }];
        doc.blocks = vec![BsxBlock::Image {
            resource_hash: "blake3:abc123".into(),
            caption: None,
            alt: None,
        }];
        let result = validate_document(&doc);
        assert!(result.is_valid());
    }

    #[test]
    fn invalid_heading_level_zero() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Heading { level: 0, text: "Bad".into() }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::InvalidHeadingLevel { level: 0, .. })));
    }

    #[test]
    fn invalid_heading_level_seven() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Heading { level: 7, text: "Bad".into() }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::InvalidHeadingLevel { level: 7, .. })));
    }

    #[test]
    fn text_too_long() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Text {
            content: "x".repeat(MAX_TEXT_LENGTH + 1),
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::TextTooLong { .. })));
    }

    #[test]
    fn too_many_table_rows() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Table {
            caption: None,
            headers: vec!["A".into()],
            rows: (0..MAX_TABLE_ROWS + 1).map(|_| vec!["x".into()]).collect(),
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::TooManyTableRows { .. })));
    }

    #[test]
    fn too_many_list_items() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::List {
            ordered: false,
            items: (0..MAX_LIST_ITEMS + 1).map(|i| format!("item {i}")).collect(),
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::TooManyListItems { .. })));
    }

    #[test]
    fn zero_grid_cols() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Grid { columns: 0, items: vec![] }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::ZeroGridCols { .. })));
    }

    #[test]
    fn too_many_grid_cols() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Grid { columns: 13, items: vec![] }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::TooManyGridCols { .. })));
    }

    #[test]
    fn grid_children_validated_recursively() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Grid {
            columns: 2,
            items: vec![BsxBlock::Heading { level: 0, text: "Bad".into() }],
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::InvalidHeadingLevel { .. })));
    }

    #[test]
    fn empty_document_warning() {
        let mut doc = minimal_doc();
        doc.blocks = vec![];
        let result = validate_document(&doc);
        assert!(result.is_valid()); // warnings are not errors
        assert!(result.warnings.iter().any(|w| matches!(w, ValidationWarning::EmptyDocument)));
    }

    #[test]
    fn inconsistent_table_row_warning() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Table {
            caption: None,
            headers: vec!["A".into(), "B".into()],
            rows: vec![vec!["only_one".into()]],
        }];
        let result = validate_document(&doc);
        assert!(result.is_valid()); // warnings, not errors
        assert!(result.warnings.iter().any(|w| matches!(w, ValidationWarning::InconsistentTableRow { .. })));
    }

    #[test]
    fn invalid_accent_color_warning() {
        let mut doc = minimal_doc();
        doc.style_hints = Some(StyleHints {
            accent_color: Some("not-a-color".into()),
            font_preference: None,
            theme: None,
        });
        let result = validate_document(&doc);
        assert!(result.is_valid());
        assert!(result.warnings.iter().any(|w| matches!(w, ValidationWarning::InvalidAccentColor(_))));
    }

    #[test]
    fn forbidden_http_link_in_text() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Text {
            content: "click [here](https://evil.com) now".into(),
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::ForbiddenLinkScheme { .. })));
    }

    #[test]
    fn bitsov_link_allowed() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Text {
            content: "see [page](bitsov://abc123/docs)".into(),
        }];
        let result = validate_document(&doc);
        assert!(result.is_valid());
    }

    #[test]
    fn relative_link_allowed() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Text {
            content: "see [about](/about)".into(),
        }];
        let result = validate_document(&doc);
        assert!(result.is_valid());
    }

    #[test]
    fn javascript_link_rejected() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Text {
            content: "click [me](javascript:alert(1))".into(),
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::ForbiddenLinkScheme { .. })));
    }

    #[test]
    fn forbidden_link_in_list_items() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::List {
            ordered: false,
            items: vec!["safe".into(), "bad [link](http://evil.com)".into()],
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::ForbiddenLinkScheme { .. })));
    }

    #[test]
    fn forbidden_link_in_callout() {
        let mut doc = minimal_doc();
        doc.blocks = vec![BsxBlock::Callout {
            variant: CalloutVariant::Warning,
            content: "see [docs](https://external.com)".into(),
        }];
        let result = validate_document(&doc);
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::ForbiddenLinkScheme { .. })));
    }

    #[test]
    fn valid_accent_colors() {
        assert!(is_valid_hex_color("#abc"));
        assert!(is_valid_hex_color("#336699"));
        assert!(!is_valid_hex_color("336699"));
        assert!(!is_valid_hex_color("#gg"));
        assert!(!is_valid_hex_color("#12345"));
    }
}
