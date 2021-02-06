//! A Rust library to interact with [RFC 8959](https://tools.ietf.org/html/rfc8959) secret-token URIs.
//!
//! See the RFC text for motivation and details.
#![feature(test)]
extern crate test;
#[macro_use]
extern crate lazy_static;
use percent_encoding::{percent_decode, percent_encode, AsciiSet, NON_ALPHANUMERIC};
use regex::bytes::Regex;

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
/// finally the [PREFIX](const.PREFIX) is prepended.
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
    lazy_static! {
        static ref ALLOWED_CHARACTERS_RE: Regex =
            Regex::new(r"^([a-zA-Z0-9._~!$&'()*+,;=:@-]|%[a-fA-F0-9]{2})*$").unwrap();
    }
    let uri = &uri[PREFIX.as_bytes().len()..];
    match uri {
        b"" => None,
        rest => match percent_decode(&rest).decode_utf8() {
            Ok(decoded) => {
                if ALLOWED_CHARACTERS_RE.is_match(rest) {
                    Some(decoded.into_owned())
                } else {
                    None
                }
            }
            Err(_) => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{black_box, Bencher};

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
    fn test_decode_works_with_valid_uris() {
        for (input, output) in valid_pairs() {
            println!("Testing {}", input);
            assert_eq!(decode(input).unwrap(), output);
            assert_eq!(decode(input.as_bytes()).unwrap(), output);
        }
    }

    #[test]
    fn test_decode_with_invalid_uris() {
        for input in invalid_uris() {
            println!("Testing {}", input);
            assert!(decode(input).is_none());
            assert!(decode(input.as_bytes()).is_none());
        }
    }

    #[test]
    fn test_encode() {
        for (input, output) in valid_pairs() {
            println!("Testing {}", input);
            assert_eq!(encode(output), input);
        }
    }

    #[test]
    fn test_characters_disallowed_in_encoding_are_also_rejected_when_decoding() {
        for i in 1u8..127u8 {
            let bytes = [i];
            let s = std::str::from_utf8(&bytes).unwrap();
            let encoded = encode(s);
            let decoded = decode(&format!("{}:{}", SCHEME, s));
            println!(
                "Character number {} ({:?}, decoded {:?})",
                i, encoded, decoded
            );
            if encoded.contains("%") {
                // Disallowed characters, got percent-encoded here so
                // it can't exist verbatim in the URIs.
                println!("Character number {} ({}, encoded {})", i, s, encoded);
                assert!(decoded.is_none());
            } else {
                assert_eq!(decoded.unwrap(), std::str::from_utf8(&bytes).unwrap());
            }
        }
    }

    #[bench]
    fn bench_decoding_invalid_uris(b: &mut Bencher) {
        let uris = invalid_uris();
        b.iter(|| {
            for uri in &uris {
                black_box(decode(&uri));
            }
        });
    }

    #[bench]
    fn bench_decoding_valid_uris(b: &mut Bencher) {
        let uris: Vec<&str> = valid_pairs().into_iter().map(|(uri, _)| uri).collect();
        b.iter(|| {
            for uri in &uris {
                black_box(decode(&uri));
            }
        });
    }

    #[bench]
    fn bench_encoding(b: &mut Bencher) {
        let tokens: Vec<&str> = valid_pairs().into_iter().map(|(_, token)| token).collect();
        b.iter(|| {
            for token in &tokens {
                black_box(encode(&token));
            }
        });
    }
}
