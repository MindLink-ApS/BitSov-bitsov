//! BSX document data model.
//!
//! A BSX document consists of metadata, optional style hints, resource
//! declarations, and an ordered list of content blocks.

use serde::{Deserialize, Serialize};

/// Maximum document size in bytes (1 MiB).
pub const MAX_DOCUMENT_SIZE: usize = 1_048_576;

/// Maximum number of blocks per document.
pub const MAX_BLOCKS: usize = 1000;

/// Maximum number of resources per document.
pub const MAX_RESOURCES: usize = 100;

/// Maximum text length for a single block's text content (64 KiB).
pub const MAX_TEXT_LENGTH: usize = 65_536;

/// Maximum number of form fields per form block.
pub const MAX_FORM_FIELDS: usize = 50;

/// Maximum number of table rows.
pub const MAX_TABLE_ROWS: usize = 500;

/// Maximum number of table columns.
pub const MAX_TABLE_COLS: usize = 20;

/// Maximum number of list items.
pub const MAX_LIST_ITEMS: usize = 200;

/// Maximum grid columns.
pub const MAX_GRID_COLS: usize = 12;

/// A complete BSX page — the top-level document structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BsxPage {
    /// Page metadata (title, author, payment).
    pub meta: BsxMeta,

    /// Optional style hints the author provides. The renderer is free to
    /// ignore these — they are suggestions, not mandates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub style_hints: Option<StyleHints>,

    /// Resources referenced by content blocks (images, audio, video).
    /// Each resource is identified by its BLAKE3 content hash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<BsxResource>,

    /// Ordered list of content blocks.
    pub blocks: Vec<BsxBlock>,
}

/// Page metadata — title, author identity, payment gate, and timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BsxMeta {
    /// Human-readable title.
    pub title: String,

    /// Author's public key (hex-encoded Ed25519).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_pubkey: Option<String>,

    /// Payment requirements for viewing this page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<PaymentMeta>,

    /// Optional description for search/preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// ISO 8601 creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,

    /// ISO 8601 last-modified timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Payment metadata for a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMeta {
    /// Cost in satoshis to view this page.
    pub amount_sats: u64,
}

/// Style hints — suggestions from the author, not mandates.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StyleHints {
    /// Suggested accent color (CSS hex, e.g. "#336699").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,

    /// Font preference: "sans-serif", "serif", "monospace".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_preference: Option<FontPreference>,

    /// Suggested theme: "dark", "light", "auto".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<ThemePreference>,
}

/// Font preference hint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FontPreference {
    /// Sans-serif (default body font).
    SansSerif,
    /// Serif font.
    Serif,
    /// Monospace font.
    Monospace,
}

/// Theme preference hint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThemePreference {
    /// Dark theme.
    Dark,
    /// Light theme.
    Light,
    /// Follow system preference.
    Auto,
}

/// A resource referenced by content blocks (images, audio, video).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BsxResource {
    /// BLAKE3 content hash, prefixed with "blake3:".
    pub hash: String,

    /// MIME type (e.g. "image/webp", "audio/opus").
    pub mime_type: String,

    /// Size in bytes (for budgeting before download).
    pub size_bytes: u64,

    /// Optional alt text for accessibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt: Option<String>,
}

/// A content block — the building blocks of a BSX page.
///
/// 16 variants covering all content types: text, heading, image, code,
/// table, divider, quote, list, card, form, embed, audio, video, grid,
/// callout, feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BsxBlock {
    /// Rich text paragraph (supports limited markdown: bold, italic, links, code).
    Text {
        /// Text content with limited inline formatting.
        content: String,
    },

    /// Section heading (levels 1-6).
    Heading {
        /// Heading level (1-6).
        level: u8,
        /// Heading text.
        text: String,
    },

    /// Image block, referencing a resource by BLAKE3 hash.
    Image {
        /// BLAKE3 hash of the image resource.
        resource_hash: String,
        /// Optional caption.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
        /// Optional alt text (overrides resource alt).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alt: Option<String>,
    },

    /// Code block with syntax highlighting hint.
    Code {
        /// Source code content.
        content: String,
        /// Language hint for syntax highlighting (e.g. "rust", "python").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        language: Option<String>,
    },

    /// Data table.
    Table {
        /// Optional table caption.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
        /// Column headers.
        headers: Vec<String>,
        /// Table rows (each row is a Vec of cell strings).
        rows: Vec<Vec<String>>,
    },

    /// Horizontal divider.
    Divider {},

    /// Block quote.
    Quote {
        /// Quoted text.
        content: String,
        /// Optional attribution.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attribution: Option<String>,
    },

    /// Ordered or unordered list.
    List {
        /// true = ordered (numbered), false = unordered (bullets).
        #[serde(default)]
        ordered: bool,
        /// List items (plain text or limited markdown).
        items: Vec<String>,
    },

    /// A card — a visually distinct container with optional title.
    Card {
        /// Optional card title.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        /// Card body content.
        content: String,
    },

    /// Interactive form (submissions are UKM messages back to the author).
    Form {
        /// Form fields.
        fields: Vec<FormField>,
        /// Submit button label.
        submit_label: String,
        /// Payment required for form submission (in sats).
        #[serde(default)]
        payment_amount: u64,
    },

    /// Embedded content from another node (resolved by your node, not arbitrary URLs).
    Embed {
        /// Node pubkey of the embedded content source.
        source_pubkey: String,
        /// Path on the source node.
        path: String,
    },

    /// Audio block.
    Audio {
        /// BLAKE3 hash of the audio resource.
        resource_hash: String,
        /// Optional title/label.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },

    /// Video block.
    Video {
        /// BLAKE3 hash of the video resource.
        resource_hash: String,
        /// Optional caption.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
    },

    /// Grid layout — arranges child blocks in columns.
    Grid {
        /// Number of columns (1-12).
        columns: u8,
        /// Child blocks arranged in the grid.
        items: Vec<BsxBlock>,
    },

    /// Callout — highlighted information box.
    Callout {
        /// Callout variant: "info", "warning", "error", "success".
        variant: CalloutVariant,
        /// Callout body text.
        content: String,
    },

    /// Feed — a list of linked content entries (like a blog index).
    Feed {
        /// Feed entries.
        entries: Vec<FeedEntry>,
    },
}

/// Form field definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormField {
    /// Field name (used as the key in submission).
    pub name: String,
    /// Display label.
    pub label: String,
    /// Field type.
    pub field_type: FormFieldType,
    /// Whether this field is required.
    #[serde(default)]
    pub required: bool,
    /// Placeholder text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

/// Form field types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FormFieldType {
    /// Single-line text input.
    Text,
    /// Multi-line text area.
    Textarea,
    /// Numeric input.
    Number,
    /// Email input.
    Email,
    /// Selection from options.
    Select {
        /// Available options.
        options: Vec<String>,
    },
    /// Boolean checkbox.
    Checkbox,
}

/// Callout variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CalloutVariant {
    /// Informational callout.
    Info,
    /// Warning callout.
    Warning,
    /// Error callout.
    Error,
    /// Success callout.
    Success,
}

/// A feed entry (link to another page).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEntry {
    /// Entry title.
    pub title: String,
    /// Path to the full content.
    pub path: String,
    /// Optional summary/excerpt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Optional ISO 8601 date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}
