//! A Rust library to interact with [RFC 8959](https://tools.ietf.org/html/rfc8959) secret-token URIs.
//!
//! See the RFC text for motivation and details.
use percent_encoding::{percent_decode, percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// The URI scheme used.
pub const SCHEME: &'static str = "secret-token";

/// The URI scheme with colon, for convenience.
pub const PREFIX: &'static str = "secret-token:";

// The list is shamelessly borrowed from
// https://github.com/Lexicality/secret-token/blob/d3cf01d7cc5b6c44d461e0ff71f7652b3edcb574/secret_token.py
const DISALLOWED_CHARACTERS: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b':')
    .remove(b'@');

/// Encodes the secret into the secret-token URI.
///
/// Non-ascii characters are UTF-8-encoded, disallowed characters then are percent-encoded,
/// finally the [PREFIX](const.PREFIX) is prependend.
pub fn encode(secret: &str) -> String {
    format!(
        "{}{}",
        PREFIX,
        percent_encode(secret.as_bytes(), DISALLOWED_CHARACTERS)
    )
}

/// Decodes the secret-token URI into a secret.
///
/// This function returns `None` when `uri`:
///
/// * Does not start with the [PREFIX](const.PREFIX)
/// * Has no token
/// * Has token that contains invalid percent-encoded UTF-8
pub fn decode(uri: impl AsRef<[u8]>) -> Option<String> {
    let uri = uri.as_ref();
    if !uri.starts_with(PREFIX.as_bytes()) {
        return None;
    }
    let uri = &uri[PREFIX.as_bytes().len()..];
    match uri {
        b"" => None,
        rest => match percent_decode(&rest).decode_utf8() {
            Ok(decoded) => Some(decoded.into_owned()),
            Err(_) => None,
        },
    }
}

/// Returns true if the URI is valid (this means it can be decoded), false otherwise.
pub fn is_valid(uri: impl AsRef<[u8]>) -> bool {
    decode(uri).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_pairs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("secret-token:s", "s"),
            ("secret-token:hello", "hello"),
            (
                "secret-token:E92FB7EB-D882-47A4-A265-A0B6135DC842%20foo",
                "E92FB7EB-D882-47A4-A265-A0B6135DC842 foo",
            ),
            ("secret-token:%C5%81%C3%B3d%C5%BA", "Łódź"),
        ]
    }

    fn invalid_uris() -> Vec<&'static str> {
        vec![
            "",
            "s",
            "hello",
            "Łódź",
            "%C5%81%C3%B3d%C5%BA",
            "secret-token",
            //"secret-token:",
            //"secret-token:secret-token:",
            //"secret-token:secret-token:hello",
            //"secret-token:secret-token:secret-token:secret-token:",
            //"secret-token:secret-token:secret-token:secret-token:hello",
            "SECRET-TOKEN:",
            "SECRET-TOKEN:hello",
            ":secret-token",
            ":secret-token:",
            ":secret-token:hello",
            "secret-token:%a1",
        ]
    }

    #[test]
    fn test_decode_and_is_valid_work_with_valid_uris() {
        for (input, output) in valid_pairs() {
            println!("Testing {}", input);
            assert_eq!(decode(input).unwrap(), output);
            assert!(is_valid(input));
            assert_eq!(decode(input.as_bytes()).unwrap(), output);
            assert!(is_valid(input.as_bytes()));
        }
    }

    #[test]
    fn test_decode_and_is_valid_with_invalid_uris() {
        for input in invalid_uris() {
            println!("Testing {}", input);
            assert!(decode(input).is_none());
            assert!(!is_valid(input));
            assert!(decode(input.as_bytes()).is_none());
            assert!(!is_valid(input.as_bytes()));
        }
    }

    #[test]
    fn test_encode() {
        for (input, output) in valid_pairs() {
            println!("Testing {}", input);
            assert_eq!(encode(output), input);
        }
    }
}
