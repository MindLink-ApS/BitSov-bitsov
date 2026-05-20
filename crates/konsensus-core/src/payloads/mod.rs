//! Typed payload schemas for specific UKM kinds.
//!
//! Each payload module defines the serde-compatible structures that go inside
//! the `ciphertext` field of a UKM envelope for its corresponding kind range.

pub mod calendar;
pub mod content;
pub mod discovery;
