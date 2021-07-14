use std::collections::HashMap;

use actix_web::{web, HttpRequest};
use oxide_auth::{
    endpoint::{
        AccessTokenExtension, AccessTokenFlow, AuthorizationFlow, Extension,
        OwnerConsent, RefreshFlow, Solicitation,
    },
    frontends::simple::{endpoint::FnSolicitor, extensions::Extended},
    primitives::grant::{Extensions, Value},
};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, WebError};

use crate::state::State;

struct HeaderExtension {
    headers: HashMap<String, String>,
}

impl Extension for HeaderExtension {
    fn access_token(&mut self) -> Option<&mut dyn AccessTokenExtension> {
        Some(self)
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

    // Add all filtered headers to map
    // TODO: allow to configure the filter criterion
    let extension = HeaderExtension {
        headers: http_req
            .headers()
            .iter()
            .filter(|(name, _)| name.as_str().starts_with("X-"))
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect(),
    };

    let extended = Extended::extend_with(endpoint, extension);

    AuthorizationFlow::prepare(extended)?
        .execute(auth_request)
        .map_err(WebError::from)
}

pub async fn token(
    (auth_request, state): (OAuthRequest, web::Data<State>),
) -> Result<OAuthResponse, WebError> {
    let endpoint = state.endpoint();
    AccessTokenFlow::prepare(endpoint)?
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
