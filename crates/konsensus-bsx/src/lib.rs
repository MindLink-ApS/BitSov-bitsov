//! # konsensus-bsx — BitSov eXpression Document Format
//!
//! BSX is a constrained JSON document format for sovereign content rendering.
//! Peers serve structured JSON documents (BSX format) that the local node
//! validates and renders using local components.
//!
//! **Security by construction:** The peer provides structure and content.
//! Your node provides rendering and style. No CSS, no JavaScript, no external
//! URLs, no absolute positioning, no animations, no iframes. Resources are
//! referenced by BLAKE3 content hash only.
//!
//! ## 16 Block Types
//!
//! text, heading, image, code, table, divider, quote, list, card, form,
//! embed, audio, video, grid, callout, feed.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod parse;
mod render;
/// Content sanitization — HTML stripping and link scheme validation.
pub mod sanitize;
mod validate;

pub use model::*;
pub use parse::{parse_bsx, parse_bsx_str, ParseError};
pub use render::render_to_html;
pub use sanitize::sanitize_document;
pub use validate::{validate_document, ValidationError, ValidationWarning};
