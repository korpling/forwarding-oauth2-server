use oxide_auth::primitives::scope::ParseScopeErr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("Invalid client URL in configuration")]
    InvalidClientUrl(#[from] url::ParseError),
    #[error("Scope could not be parsed because of invalid chararcter '{0}'")]
    InvalidCharacterInScope(char),
}

impl From<ParseScopeErr> for StartupError {
    fn from(e: ParseScopeErr) -> Self {
        match e {
            ParseScopeErr::InvalidCharacter(c) => StartupError::InvalidCharacterInScope(c),
        }
    }
}
