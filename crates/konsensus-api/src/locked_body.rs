//! Parse password-bearing JSON without serde_json's unwiped escape scratch.
use serde::Deserialize;
use zeroize::Zeroizing;

use super::UnlockError;

pub(super) struct UnlockBody {
    pub challenge: String,
    pub key_id: String,
    pub signature: String,
    pub password: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BorrowedBody<'a> {
    challenge: String,
    key_id: String,
    signature: String,
    #[serde(borrow)]
    password: &'a serde_json::value::RawValue,
}

pub(super) fn parse(raw: &[u8]) -> Result<UnlockBody, UnlockError> {
    // RawValue borrows the JSON spelling and skips, rather than decodes, escapes.
    let body: BorrowedBody<'_> = serde_json::from_slice(raw).map_err(|_| UnlockError::Failed)?;
    Ok(UnlockBody {
        challenge: body.challenge,
        key_id: body.key_id,
        signature: body.signature,
        password: decode_password(body.password.get())?,
    })
}

fn quad(chars: &mut std::str::Chars<'_>) -> Result<u32, UnlockError> {
    (0..4).try_fold(0, |n, _| {
        Ok(n * 16
            + chars
                .next()
                .and_then(|c| c.to_digit(16))
                .ok_or(UnlockError::Failed)?)
    })
}

fn decode_password(raw: &str) -> Result<Zeroizing<String>, UnlockError> {
    let inner = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(UnlockError::Failed)?;
    // Decoding can only shrink the spelling; no reallocations free old secrets.
    let mut password = Zeroizing::new(String::with_capacity(inner.len()));
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            if c == '"' || c < ' ' {
                return Err(UnlockError::Failed);
            }
            password.push(c);
            continue;
        }
        password.push(match chars.next().ok_or(UnlockError::Failed)? {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let mut scalar = quad(&mut chars)?;
                if (0xd800..=0xdbff).contains(&scalar) {
                    if chars.next() != Some('\\') || chars.next() != Some('u') {
                        return Err(UnlockError::Failed);
                    }
                    let low = quad(&mut chars)?;
                    if !(0xdc00..=0xdfff).contains(&low) {
                        return Err(UnlockError::Failed);
                    }
                    scalar = 0x10000 + ((scalar - 0xd800) << 10) + low - 0xdc00;
                }
                char::from_u32(scalar).ok_or(UnlockError::Failed)?
            }
            _ => return Err(UnlockError::Failed),
        });
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passwords_decode_directly_into_zeroizing_memory() {
        for (raw, expected) in [
            (r#""plain""#, "plain"),
            (
                r#""quote\" slash\/ backslash\\""#,
                "quote\" slash/ backslash\\",
            ),
            (r#""\b\f\n\r\t\u0000""#, "\u{8}\u{c}\n\r\t\0"),
            (r#""æ\u00e9\uD83D\uDD11""#, "æé🔑"),
            (r#""""#, ""),
        ] {
            assert_eq!(decode_password(raw).unwrap().as_str(), expected);
        }
        for raw in [
            r#""\uD800""#,
            r#""\uDC00""#,
            r#""\uD800\u0041""#,
            r#""\q""#,
            r#""\u00xz""#,
            "null",
            "123",
            "\"bad\n\"",
            "\"\\\"",
        ] {
            assert!(decode_password(raw).is_err());
        }
    }
    #[test]
    fn parser_borrows_password_and_rejects_duplicate_or_unknown_fields() {
        let body =
            parse(br#"{"challenge":"c","key_id":"k","signature":"s","password":"\uD83D\uDD11"}"#)
                .unwrap();
        assert_eq!(body.password.as_str(), "🔑");
        for raw in [
            br#"{"challenge":"c","key_id":"k","signature":"s","password":"a","password":"b"}"#
                .as_slice(),
            br#"{"challenge":"c","key_id":"k","signature":"s","password":"a","extra":1}"#,
        ] {
            assert!(parse(raw).is_err());
        }
    }
}
