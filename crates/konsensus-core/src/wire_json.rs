//! Peer JSON admission, shared by Frame and payload/envelope entry points.
//! Generic serde implementations intentionally remain usable with owner config,
//! readers and Values. Call these entry points at untrusted byte boundaries.

use serde::Deserialize;

pub mod strings;

/// Matches the transport's outer frame budget. Payload callers may cap earlier.
pub const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
/// Six raw bytes per byte of a maximum-size (64 KiB) BOLT11/SDP string.
pub const MAX_RAW_STRING_TOKEN_BYTES: usize = 6 * 64 * 1024;

/// No underlying serde diagnostic is retained: even type errors can echo input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid wire JSON")]
pub struct DecodeError;

/// Decode peer JSON after an allocation-free lexical admission scan. Narrower
/// field/collection visitors on T still apply. This caps individual string
/// scratch/error allocations; it is not a total allocation budget for T.
pub fn from_slice<'de, T: Deserialize<'de>>(data: &'de [u8]) -> Result<T, DecodeError> {
    from_slice_with_large_strings(data, &[])
}

pub fn from_str<'de, T: Deserialize<'de>>(data: &'de str) -> Result<T, DecodeError> {
    from_slice(data.as_bytes())
}

/// Explicit schema exceptions for large *top-level string* payload fields.
/// Callers must only name fields that T deserializes as String (never a number,
/// enum, or arbitrary Value). Each exception is checked for decoded UTF-8 size
/// before serde unescapes it. Keys, unknown fields, nested values and wrong-type
/// strings in all other positions retain the ordinary raw-token ceiling.
pub fn from_slice_with_large_strings<'de, T: Deserialize<'de>>(
    data: &'de [u8],
    fields: &[(&str, usize)],
) -> Result<T, DecodeError> {
    check_payload(data, fields).map_err(|_| DecodeError)?;
    serde_json::from_slice(data).map_err(|_| DecodeError)
}

/// Standalone payload admission, including its aggregate byte budget.
pub fn check_payload(data: &[u8], fields: &[(&str, usize)]) -> Result<(), &'static str> {
    if data.len() > MAX_JSON_BYTES {
        return Err("JSON exceeds wire byte cap");
    }
    check_tokens(data, fields)
}

/// Lexical guard only: serde remains responsible for JSON grammar validation.
/// Shared with Frame so the raw-token/depth rules cannot drift. Frame's total
/// byte budget stays at its transport entry, preserving field-only decoding.
pub fn check_tokens(data: &[u8], fields: &[(&str, usize)]) -> Result<(), &'static str> {
    let mut depth: usize = 0;
    let mut start = None;
    let mut escaped = false;
    let mut next_limit = None;
    let mut limit = None;
    for (i, &byte) in data.iter().enumerate() {
        if let Some(begin) = start {
            if !escaped && byte == b'"' {
                if let Some(max) = limit {
                    let raw = std::str::from_utf8(&data[begin..=i]).map_err(|_| "invalid UTF-8")?;
                    strings::check_string_bytes(raw, max)?;
                }
                if depth == 1
                    && data[i + 1..]
                        .iter()
                        .copied()
                        .find(|b| !b.is_ascii_whitespace())
                        == Some(b':')
                {
                    next_limit = fields.iter().find_map(|(name, max)| {
                        key_matches(&data[begin + 1..i], name).then_some(*max)
                    });
                }
                start = None;
                continue;
            }
            if i - begin > limit.map_or(MAX_RAW_STRING_TOKEN_BYTES, |n: usize| n.saturating_mul(6))
            {
                return Err("JSON string exceeds frame token cap");
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            }
        } else {
            match byte {
                b'"' => {
                    start = Some(i);
                    limit = next_limit.take();
                }
                b'[' | b'{' => {
                    next_limit = None;
                    depth += 1;
                    if depth > 128 {
                        return Err("JSON nesting exceeds frame depth cap");
                    }
                }
                b']' | b'}' => {
                    next_limit = None;
                    depth = depth.saturating_sub(1);
                }
                b':' | b' ' | b'\t' | b'\r' | b'\n' => {}
                _ => next_limit = None,
            }
        }
    }
    // Without a closing quote there is no decoded-size check above. In
    // particular, an escaped unfinished large payload must never reach serde's
    // scratch buffer under the more generous raw (6x decoded) budget.
    if start.is_some() {
        return Err("unterminated JSON string");
    }
    Ok(())
}

// Exception names are ASCII schema identifiers. Accept escaped spellings too,
// without allocating a String or unescaping an attacker-controlled key.
fn key_matches(mut raw: &[u8], name: &str) -> bool {
    for expected in name.bytes() {
        if raw.first() == Some(&expected) {
            raw = &raw[1..];
        } else if raw.starts_with(b"\\u") && raw.len() >= 6 {
            let mut value = 0u32;
            for digit in &raw[2..6] {
                let Some(n) = (*digit as char).to_digit(16) else {
                    return false;
                };
                value = value * 16 + n;
            }
            if value != u32::from(expected) {
                return false;
            }
            raw = &raw[6..];
        } else {
            return false;
        }
    }
    raw.is_empty()
}
