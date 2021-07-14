use std::io::Write;
use std::ops::Deref;
use tempfile::NamedTempFile;

use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};

use crate::errors::{RuntimeError, StartupError};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Logging {
    pub debug: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum JWTVerification {
    HS256 { secret: String },
    RS256 { private_key: String },
}

impl JWTVerification {
    pub fn create_encoding_key(&self) -> Result<EncodingKey, RuntimeError> {
        let key = match &self {
            JWTVerification::HS256 { secret } => {
                jsonwebtoken::EncodingKey::from_secret(secret.as_bytes())
            }
            JWTVerification::RS256 { private_key, .. } => {
                jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes())?
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

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Auth {
    pub token_verification: JWTVerification,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Settings {
    pub auth: Auth,
    pub logging: Logging,
    pub bind: Bind,
    pub client: Client,
}

impl Settings {
    pub fn with_file<S: Deref<Target = str>>(config_file: S) -> Result<Self, StartupError> {
        let mut config = config::Config::default();

        // Write default settings to temporary file
        let mut default_file = NamedTempFile::new()?;
        write!(default_file, "{}", toml::to_string(&Settings::default())?)?;

        config.merge(config::File::new(
            &default_file.path().to_string_lossy(),
            config::FileFormat::Toml,
        ))?;

        let from_file = config::File::new(&config_file, config::FileFormat::Toml);
        config.merge(from_file)?;
        let result: Settings = config.try_into()?;
        Ok(result)
    }
}
