# sectok
[![crates.io](https://img.shields.io/crates/v/sectok)](https://crates.io/crates/sectok)
[![docs.rs](https://docs.rs/sectok/badge.svg)](https://docs.rs/sectok/)

A Rust library to interact with [RFC 8959](https://tools.ietf.org/html/rfc8959) secret-token URIs.
Inspired by [Lex Robinson's Python implementation](https://github.com/Lexicality/secret-token).

See the RFC text for motivation and details.

You can find the [library documentation on docs.rs](https://docs.rs/sectok/).

An example of decoding a URI:

```rust
use sectok;
use std::env;

fn main() {
    match env::var("API_KEY") {
        Ok(uri) => {
            println!("The URI: {}", uri);
            match sectok::decode(&uri) {
                Some(token) => println!("The decoded token: {}", token),
                None => println!("The URI is invalid, cannot decode the token"),
            }
        }
        Err(e) => {
            println!("Cannot read environment variable: {}", e);
        }
    }
}
```

```
% API_KEY=secret-token:hello%20world cargo run --quiet --example decode
The URI: secret-token:hello%20world
The decoded token: hello world
```
