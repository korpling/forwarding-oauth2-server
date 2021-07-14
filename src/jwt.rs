use std::collections::HashMap;

use log::error;
use oxide_auth::{
    endpoint::Issuer,
    primitives::{
        grant::Grant,
        issuer::{RefreshedToken, TokenType::Bearer},
        prelude::{IssuedToken, RandomGenerator, TagGrant},
    },
};

use serde::{Deserialize, Serialize};
use serde_json::Map;

use crate::{errors::RuntimeError, settings::Settings};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    /// Expiration date as unix timestamp in seconds since epoch and UTC
    pub exp: Option<i64>,
}

pub struct JWTIssuer {
    settings: Settings,
    refresh: HashMap<String, Grant>,
    refresh_token_generator: RandomGenerator,
}

impl JWTIssuer {
    pub fn new(settings: Settings) -> JWTIssuer {
        JWTIssuer {
            settings,
            refresh: HashMap::new(),
            refresh_token_generator: RandomGenerator::new(128),
        }
    }

    fn create_token(
        &self,
        grant: &oxide_auth::primitives::grant::Grant,
    ) -> Result<String, RuntimeError> {
        let sub = grant.owner_id.clone();
        let exp = grant.until.timestamp();

        // Parse template and apply substitutions
        let hb = handlebars::Handlebars::new();
        let default_template = include_str!("default-token-template.json");

        let mut variables: HashMap<String, String> = HashMap::new();
        variables.insert("sub".to_string(), sub);
        variables.insert("exp".to_string(), exp.to_string());
        // Add all public extensions as arguments
        for (k, v) in grant.extensions.public() {
            variables
                .entry(k.to_string())
                .or_insert(v.unwrap_or_default().to_string());
        }

        let unsigned_token_raw = hb.render_template(default_template, &variables)?;

        // Parse JSON so encoding it with serde later on will produce a correct value
        let unsigned_token: Map<String, serde_json::Value> =
            serde_json::from_str(&unsigned_token_raw)?;

        let key = self
            .settings
            .auth
            .token_verification
            .create_encoding_key()?;
        let header =
            jsonwebtoken::Header::new(self.settings.auth.token_verification.as_algorithm());
        let token_str = jsonwebtoken::encode(&header, &unsigned_token, &key)?;

        Ok(token_str)
    }
}

impl Issuer for JWTIssuer {
    fn issue(
        &mut self,
        grant: oxide_auth::primitives::grant::Grant,
    ) -> Result<oxide_auth::primitives::prelude::IssuedToken, ()> {
        let token = self
            .create_token(&grant)
            .map_err(|e| (error!("Could not issue token: {}", e)))?;
        let refresh = self.refresh_token_generator.tag(0, &grant)?;

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

        let token = self
            .create_token(&grant)
            .map_err(|e| (error!("Could not refresh token: {}", e)))?;
        let new_refresh = self.refresh_token_generator.tag(0, &grant)?;
        Ok(RefreshedToken {
            token: token,
            refresh: Some(new_refresh),
            until: grant.until,
            token_type: Bearer,
        })
    }

    fn recover_token<'a>(
        &'a self,
        _token: &'a str,
    ) -> Result<Option<oxide_auth::primitives::grant::Grant>, ()> {
        Err(())
    }

    fn recover_refresh<'a>(
        &'a self,
        token: &'a str,
    ) -> Result<Option<oxide_auth::primitives::grant::Grant>, ()> {
        Ok(self.refresh.get(token).map(|grant| grant.clone()))
    }
}
