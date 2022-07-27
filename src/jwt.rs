use std::{borrow::Cow, collections::HashMap};

use handlebars::JsonValue;
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
        let token_template: Cow<str> =
            if let Some(token_template_file) = &self.settings.mapping.token_template {
                std::fs::read_to_string(token_template_file)?.into()
            } else {
                include_str!("default-token-template.json").into()
            };

        let mut variables: HashMap<String, JsonValue> = HashMap::new();
        variables.insert("sub".to_string(), JsonValue::String(sub.clone()));
        variables.insert("exp".to_string(), JsonValue::String(exp.to_string()));
        // Get all roles and groups of this user from the configuration
        let user_settings = self
            .settings
            .mapping
            .users
            .iter()
            .filter(|u| u.id == sub)
            .next();
        if let Some(user_settings) = user_settings {
            variables.insert(
                "groups".to_string(),
                JsonValue::Array(user_settings.groups.iter().map(|v| JsonValue::String(v.to_string())).collect()),
            );
            variables.insert(
                "roles".to_string(),
                JsonValue::Array(user_settings.roles.iter().map(|v| JsonValue::String(v.to_string())).collect()),
            );
        }

        // Add all public extensions as arguments
        for (k, v) in grant.extensions.public() {
            variables
                .entry(k.to_string())
                .or_insert(JsonValue::String(v .unwrap_or_default().to_string()));
        }

        let unsigned_token_raw = hb.render_template(&token_template, &variables)?;
        
        // Parse JSON so encoding it with serde later on will produce a correct value
        let unsigned_token: Map<String, serde_json::Value> =
            serde_json::from_str(&unsigned_token_raw)?;

        let key = self
            .settings
            .client
            .token_verification
            .create_encoding_key()?;
        let header =
            jsonwebtoken::Header::new(self.settings.client.token_verification.as_algorithm());
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
