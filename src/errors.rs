use oxide_auth::primitives::scope::ParseScopeErr;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StartupError {
    #[error("Invalid client URL in configuration")]
    InvalidClientUrl(#[from] url::ParseError),
    #[error("Scope could not be parsed because of invalid chararcter '{0}'")]
    InvalidCharacterInScope(char),
    #[error("JSON Web Token Error")]
    JWT(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid configuration file")]
    Config(#[from] confy::ConfyError),
}

impl From<ParseScopeErr> for StartupError {
    fn from(e: ParseScopeErr) -> Self {
        match e {
            ParseScopeErr::InvalidCharacter(c) => StartupError::InvalidCharacterInScope(c),
        }
    }
}

impl StartupError {
    pub fn into_io(self) -> std::io::Error {
        match self {
            StartupError::InvalidClientUrl(_) => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, self)
            }
            StartupError::InvalidCharacterInScope(_) => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, self)
            }
            StartupError::JWT(_) => std::io::Error::new(std::io::ErrorKind::InvalidData, self),
            StartupError::Config(_) => std::io::Error::new(std::io::ErrorKind::InvalidData, self),
        }
    }
}
