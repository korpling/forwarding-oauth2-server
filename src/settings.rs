use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};

use crate::errors::StartupError;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Logging {
    pub debug: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Bind {
    pub port: i16,
    pub host: String,
}

impl Default for Bind {
    fn default() -> Self {
        Bind {
            port: 8020,
            host: "localhost".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JWTVerification {
    HS256 { secret: String },
    RS256 { public_key: String },
}

impl JWTVerification {
    pub fn create_decoding_key(&self) -> Result<DecodingKey, StartupError> {
        let key = match &self {
            JWTVerification::HS256 { secret } => {
                jsonwebtoken::DecodingKey::from_secret(secret.as_bytes())
            }
            JWTVerification::RS256 { public_key } => {
                jsonwebtoken::DecodingKey::from_rsa_pem(public_key.as_bytes())?
            }
        };
        Ok(key)
    }

    pub fn as_algorithm(&self) -> jsonwebtoken::Algorithm {
        match &self {
            JWTVerification::HS256 { .. } => jsonwebtoken::Algorithm::HS256,
            JWTVerification::RS256 { .. } => jsonwebtoken::Algorithm::RS256,
        }
    }
}

impl Default for JWTVerification {
    fn default() -> Self {
        JWTVerification::HS256 {
            secret: "not-a-random-secret".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Auth {
    pub token_verification: JWTVerification,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Client {
    pub id: String,
    pub redirect_uri: String,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            id: "ANNIS".to_string(),
            redirect_uri: "http://localhost:5712".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Settings {
    pub auth: Auth,
    pub logging: Logging,
    pub bind: Bind,
    pub client: Client,
}
