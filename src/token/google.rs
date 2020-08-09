use std::path::PathBuf;

use frank_jwt::{ValidationOptions, Algorithm, encode, decode, error::Error, validate_signature};
use serde_json::{Value as JsonValue};

pub struct Token {
    payload: Option<JsonValue>,
    token_string: Option<String>,
}

impl Token {
    const KEYPATH: &'static str = r"/home/simon/Development/rust/rust-firebase/src/token/jwtRS256.key";
    pub fn new(payload: Option<JsonValue>, token_string: Option<String>) -> Self {
    
        Self {
            payload: payload,
            token_string: token_string
        }
    }

    // Create RS256 token
    pub fn encode(&self) -> Result<String, Error> {
        let header = json!({});
        let path = PathBuf::from(Token::KEYPATH);

        match &self.payload {
            Some(payload) => encode(header, &path, &payload, Algorithm::RS256),
            None => Err(Error::JWTInvalid)
        }
    }

    pub fn decode(&self) -> Result<(JsonValue, JsonValue), Error> {
        let path = PathBuf::from(Token::KEYPATH);

        match &self.token_string {
            Some(ts) => decode(&ts, &path, Algorithm::RS256, &ValidationOptions::default()),
            None => Err(Error::SignatureInvalid)
        }
    }
}

    //Example usage :
    //    let payload = json!({
    //        "key1": "val1",
    //        "key2": "val2"
    //    });

    //    let res = GoogleToken::new(payload).encode();
