use oxide_auth::{
    endpoint::Issuer,
    primitives::{
        issuer::{RefreshedToken, TokenType::Bearer},
        prelude::IssuedToken,
    },
};

use serde::{Deserialize, Serialize};

use crate::settings::Settings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    /// Expiration date as unix timestamp in seconds since epoch and UTC
    pub exp: Option<i64>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
}

pub struct JWTIssuer {
    settings: Settings,
}

impl JWTIssuer {
    pub fn new(settings: Settings) -> JWTIssuer {
        JWTIssuer { settings }
    }
}

impl Issuer for JWTIssuer {
    fn issue(
        &mut self,
        grant: oxide_auth::primitives::grant::Grant,
    ) -> Result<oxide_auth::primitives::prelude::IssuedToken, ()> {
        let claims = Claims {
            sub: grant.owner_id.clone(),
            exp: Some(grant.until.timestamp()),
            groups: vec![],
            roles: vec![],
        };

        let key = self
            .settings
            .auth
            .token_verification
            .create_encoding_key()
            .map_err(|_| ())?;
        let header =
            jsonwebtoken::Header::new(self.settings.auth.token_verification.as_algorithm());
        let token_str = jsonwebtoken::encode(&header, &claims, &key).map_err(|_| ())?;

        // TODO: implement refresh tokens
        Ok(IssuedToken {
            token: token_str,
            refresh: None,
            until: grant.until,
            token_type: Bearer,
        })
    }

    fn refresh(
        &mut self,
        _refresh: &str,
        _grant: oxide_auth::primitives::grant::Grant,
    ) -> Result<oxide_auth::primitives::issuer::RefreshedToken, ()> {
        Err(())
    }

    fn recover_token<'a>(
        &'a self,
        _: &'a str,
    ) -> Result<Option<oxide_auth::primitives::grant::Grant>, ()> {
        Err(())
    }

    fn recover_refresh<'a>(
        &'a self,
        _: &'a str,
    ) -> Result<Option<oxide_auth::primitives::grant::Grant>, ()> {
        Err(())
    }
}
