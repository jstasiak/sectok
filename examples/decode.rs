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
