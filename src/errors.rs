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
    Config(#[from] config::ConfigError),
    #[error("IO error")]
    IO(#[from] std::io::Error),
    #[error("TOML serialization error")]
    TOML(#[from] toml::ser::Error),
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
        std::io::Error::new(std::io::ErrorKind::InvalidData, self)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimeError {
    #[error("Could not parse template")]
    TemplateParsing(#[from] handlebars::RenderError),
    #[error("JSON Web Token Error")]
    JWT(#[from] jsonwebtoken::errors::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxide_auth::primitives::scope::Scope;

    #[test]
    fn test_invalid_scope_character() {
        let scope = "A\"BC".parse::<Scope>();

        assert!(scope.is_err());
        let err: StartupError = scope.unwrap_err().into();

        match err {
            StartupError::InvalidCharacterInScope(c) => assert_eq!('\"', c),
            _ => panic!("Wrong error type"),
        }
    }
}
