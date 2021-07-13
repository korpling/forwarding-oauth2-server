use std::collections::HashMap;

use oxide_auth::{
    endpoint::Issuer,
    primitives::{
        grant::Grant,
        issuer::{RefreshedToken, TokenType::Bearer},
        prelude::{IssuedToken, RandomGenerator, TagGrant},
    },
};

use serde::{Deserialize, Serialize};

use crate::settings::Settings;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    /// Expiration date as unix timestamp in seconds since epoch and UTC
    pub exp: Option<i64>,
}

pub struct JWTIssuer {
    settings: Settings,
    access: HashMap<String, Grant>,
    refresh: HashMap<String, Grant>,
    refresh_token_generator: RandomGenerator,
}

impl JWTIssuer {
    pub fn new(settings: Settings) -> JWTIssuer {
        JWTIssuer {
            settings,
            access: HashMap::new(),
            refresh: HashMap::new(),
            refresh_token_generator: RandomGenerator::new(128),
        }
    }

    fn create_token<'a>(&self, claims: &Claims) -> Result<String, ()> {
        let key = self
            .settings
            .auth
            .token_verification
            .create_encoding_key()
            .map_err(|_| ())?;
        let header =
            jsonwebtoken::Header::new(self.settings.auth.token_verification.as_algorithm());
        let token_str = jsonwebtoken::encode(&header, &claims, &key).map_err(|_| ())?;
        Ok(token_str)
    }

    fn create_claims(&self, grant: &oxide_auth::primitives::grant::Grant) -> Claims {
        let claims = Claims {
            sub: grant.owner_id.clone(),
            exp: Some(grant.until.timestamp()),
        };
        claims
    }
}

impl Issuer for JWTIssuer {
    fn issue(
        &mut self,
        grant: oxide_auth::primitives::grant::Grant,
    ) -> Result<oxide_auth::primitives::prelude::IssuedToken, ()> {
        let claims = self.create_claims(&grant);
        let token = self.create_token(&claims)?;
        let refresh = self.refresh_token_generator.tag(0, &grant)?;

        self.access.insert(token.clone(), grant.clone());
        self.refresh.insert(refresh.clone(), grant.clone());

        Ok(IssuedToken {
            token,
            refresh: Some(refresh),
            until: grant.until,
            token_type: Bearer,
        })
    }

    fn refresh(
        &mut self,
        refresh: &str,
        grant: oxide_auth::primitives::grant::Grant,
    ) -> Result<oxide_auth::primitives::issuer::RefreshedToken, ()> {
        // Invalidate old refresh token
        self.refresh.remove(refresh);

        let claims = self.create_claims(&grant);
        let new_refresh = self.refresh_token_generator.tag(0, &grant)?;
        Ok(RefreshedToken {
            token: self.create_token(&claims)?,
            refresh: Some(new_refresh),
            until: grant.until,
            token_type: Bearer,
        })
    }

    fn recover_token<'a>(
        &'a self,
        token: &'a str,
    ) -> Result<Option<oxide_auth::primitives::grant::Grant>, ()> {
        Ok(self.access.get(token).map(|grant| grant.clone()))
    }

    fn recover_refresh<'a>(
        &'a self,
        token: &'a str,
    ) -> Result<Option<oxide_auth::primitives::grant::Grant>, ()> {
        Ok(self.refresh.get(token).map(|grant| grant.clone()))
    }
}
