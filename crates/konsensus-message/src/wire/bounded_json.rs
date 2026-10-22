//! Pre-copy bounds for borrowing JSON wire decoders.
use serde::{de, Deserialize, Deserializer};

/// Borrow the raw token before serde_json can unescape it into scratch space.
/// This wire decoder requires a borrowing JSON source (`from_slice`/`from_str`),
/// as used by `Frame::from_bytes`; a reader or prebuilt Value cannot supply it.
/// RawValue scans the token without copying it. Count decoded UTF-8 bytes
/// without materialising them, then let serde_json decode only an admitted
/// string. CPU for the raw scan is still bounded by the outer frame limit.
pub fn limited_string<'de, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<String, D::Error> {
    string_with_limit(deserializer, MAX)
}

pub fn check_string_bytes(raw: &str, max: usize) -> Result<(), &'static str> {
    let contents = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or("expected a JSON string")?;
    let mut chars = contents.chars();
    let mut bytes = 0;
    while let Some(ch) = chars.next() {
        bytes += if ch != '\\' {
            ch.len_utf8()
        } else {
            match chars.next() {
                Some('u') => {
                    let first = hex_quad(&mut chars)?;
                    match first {
                        0xD800..=0xDBFF => {
                            if chars.next() != Some('\\') || chars.next() != Some('u') {
                                return Err("invalid Unicode surrogate pair");
                            }
                            if !(0xDC00..=0xDFFF).contains(&hex_quad(&mut chars)?) {
                                return Err("invalid Unicode surrogate pair");
                            }
                            4
                        }
                        0xDC00..=0xDFFF => return Err("unpaired Unicode surrogate"),
                        0..=0x7F => 1,
                        0x80..=0x7FF => 2,
                        _ => 3,
                    }
                }
                Some('"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') => 1,
                _ => return Err("invalid JSON string escape"),
            }
        };
        if bytes > max {
            return Err("string exceeds byte cap");
        }
    }
    Ok(())
}

fn hex_quad(chars: &mut std::str::Chars<'_>) -> Result<u32, &'static str> {
    let mut value = 0;
    for _ in 0..4 {
        let digit = chars
            .next()
            .and_then(|ch| ch.to_digit(16))
            .ok_or("invalid Unicode escape")?;
        value = value * 16 + digit;
    }
    Ok(value)
}

/// Runtime-size form for fixed-width identifiers.
pub fn string_with_limit<'de, D: Deserializer<'de>>(
    deserializer: D,
    max: usize,
) -> Result<String, D::Error> {
    let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
    check_string_bytes(raw.get(), max).map_err(de::Error::custom)?;
    serde_json::from_str(raw.get()).map_err(de::Error::custom)
}

/// Enum names are short protocol tokens, including externally tagged objects.
pub const MAX_ENUM_TAG_BYTES: usize = 128;

/// Check a borrowed enum tag before serde can unescape or echo an unknown name.
/// Full JSON syntax and the known variant set are still validated by serde.
pub fn check_enum_tag(raw: &str) -> Result<(), &'static str> {
    let raw = raw.trim_start();
    let tag = raw.strip_prefix('{').unwrap_or(raw).trim_start();
    if !tag.starts_with('"') {
        return Err("expected a JSON enum tag");
    }
    let mut escaped = false;
    for (i, byte) in tag.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return check_string_bytes(&tag[..=i], MAX_ENUM_TAG_BYTES);
        }
    }
    Err("unterminated JSON enum tag")
}

/// A borrowing JSON entry point for nested enums.
pub fn enum_value<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
    check_enum_tag(raw.get()).map_err(de::Error::custom)?;
    serde_json::from_str(raw.get()).map_err(de::Error::custom)
}

/// Parse fixed-width textual wire types (UUID / socket address) after bounding.
pub fn parsed_string<'de, D, T, const MAX: usize>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: std::str::FromStr,
{
    limited_string::<D, MAX>(deserializer)?
        .parse()
        .map_err(|_| de::Error::custom("invalid bounded string value"))
}

/// Decode a textual type only after the shared raw-token byte check. Kept at
/// wire fields so core identifiers still support TOML, Value and reader inputs.
pub fn string_value<'de, D, T, const MAX: usize>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
    check_string_bytes(raw.get(), MAX).map_err(de::Error::custom)?;
    serde_json::from_str(raw.get()).map_err(de::Error::custom)
}

/// Reject wrong-type strings before serde's sequence type error unescapes them.
pub fn sequence<'de, D, V>(deserializer: D, visitor: V) -> Result<V::Value, D::Error>
where
    D: Deserializer<'de>,
    V: de::Visitor<'de>,
{
    let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
    if !raw.get().starts_with('[') {
        return Err(de::Error::custom("expected a JSON array"));
    }
    (&mut serde_json::Deserializer::from_str(raw.get()))
        .deserialize_seq(visitor)
        .map_err(de::Error::custom)
}

/// Array elements need the same wrong-type guard as the array itself.
pub struct Byte(pub u8);
impl<'de> Deserialize<'de> for Byte {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <&serde_json::value::RawValue>::deserialize(deserializer)?;
        if !matches!(raw.get().as_bytes().first(), Some(b'0'..=b'9')) {
            return Err(de::Error::custom("expected a JSON byte"));
        }
        serde_json::from_str(raw.get())
            .map(Self)
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enum_tag_bound_counts_decoded_bytes() {
        for (token, accepted) in [
            ("a".repeat(128), true),
            ("a".repeat(129), false),
            (r"\u00e9".repeat(64), true),
            (r"\u00e9".repeat(65), false),
            (r"\ud83d\ude00".repeat(32), true),
            (r"\ud83d\ude00".repeat(33), false),
        ] {
            for raw in [format!("\"{token}\""), format!("{{\"{token}\":null}}")] {
                assert_eq!(check_enum_tag(&raw).is_ok(), accepted);
            }
        }
    }
}
