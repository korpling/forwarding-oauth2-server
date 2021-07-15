use std::collections::HashMap;

use actix_web::{web, HttpRequest};
use log::error;
use oxide_auth::{
    endpoint::{
        AccessTokenExtension, AccessTokenFlow, AuthorizationExtension, AuthorizationFlow,
        Extension, OwnerConsent, RefreshFlow, Solicitation,
    },
    frontends::simple::{endpoint::FnSolicitor, extensions::Extended},
    primitives::grant::{Extensions, Value},
};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, WebError};
use regex::Regex;

use crate::state::State;

struct HeaderExtension {
    headers: HashMap<String, String>,
}

impl Extension for HeaderExtension {
    fn access_token(&mut self) -> Option<&mut dyn AccessTokenExtension> {
        Some(self)
    }
}

impl AuthorizationExtension for HeaderExtension {
    fn extend(
        &mut self,
        _request: &dyn oxide_auth::code_grant::authorization::Request,
    ) -> std::result::Result<Extensions, ()> {
        let mut extensions = Extensions::new();
        for (n, v) in &self.headers {
            extensions.set_raw(n.to_string(), Value::Public(Some(v.to_string())));
        }
        Ok(extensions)
    }
}

impl AccessTokenExtension for HeaderExtension {
    fn extend(
        &mut self,
        _request: &dyn oxide_auth::code_grant::accesstoken::Request,
        _data: oxide_auth::primitives::grant::Extensions,
    ) -> std::result::Result<oxide_auth::primitives::grant::Extensions, ()> {
        let mut extensions = Extensions::new();
        for (n, v) in &self.headers {
            extensions.set_raw(n.to_string(), Value::Public(Some(v.to_string())));
        }
        Ok(extensions)
    }
}

pub async fn authorize(
    (auth_request, http_req, state): (OAuthRequest, HttpRequest, web::Data<State>),
) -> Result<OAuthResponse, WebError> {
    let remote_user_header = http_req.headers().get("X-Remote-User");
    let endpoint = state.endpoint().with_solicitor(FnSolicitor(
        move |_request: &mut OAuthRequest, _pre_grant: Solicitation| {
            if let Some(remote_user) = remote_user_header {
                if let Ok(remote_user) = remote_user.to_str() {
                    if !remote_user.is_empty() {
                        return OwnerConsent::Authorized(remote_user.to_string());
                    }
                }
            }
            OwnerConsent::Denied
        },
    ));

    AuthorizationFlow::prepare(endpoint)?
        .execute(auth_request)
        .map_err(WebError::from)
}

pub async fn token(
    (auth_request, http_req, state): (OAuthRequest, HttpRequest, web::Data<State>),
) -> Result<OAuthResponse, WebError> {
    let endpoint = state.endpoint();
    // Add all filtered headers to map
    // TODO: allow to configure the filter criterion
    let headers: HashMap<_, _> = if let Some(include_header) =
        &state.settings.mapping.include_header
    {
        let header_pattern = Regex::new(&include_header)
        .map_err(|e| {
            error!("Could not compile regular expression for \"mapping.include_headers\" parameter in configuration: {}", e); 
            WebError::InternalError(None)
        })?;
        http_req
            .headers()
            .iter()
            .filter(|(name, _)| header_pattern.is_match(name.as_str()))
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    } else {
        HashMap::new()
    };
    let extension = HeaderExtension { headers };

    let extended = Extended::extend_with(endpoint, extension);

    AccessTokenFlow::prepare(extended)?
        .execute(auth_request)
        .map_err(WebError::from)
}

pub async fn refresh(
    (auth_request, state): (OAuthRequest, web::Data<State>),
) -> Result<OAuthResponse, WebError> {
    let endpoint = state.endpoint();
    RefreshFlow::prepare(endpoint)?
        .execute(auth_request)
        .map_err(WebError::from)
}

#[cfg(test)]
mod tests;
