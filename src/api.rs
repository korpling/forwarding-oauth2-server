use std::collections::HashMap;

use actix_web::{web, HttpRequest};
use oxide_auth::{
    endpoint::{
        AccessTokenExtension, AccessTokenFlow, AuthorizationExtension, AuthorizationFlow,
        Extension, OwnerConsent, RefreshFlow, Solicitation,
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
    fn authorization(&mut self) -> Option<&mut dyn AuthorizationExtension> {
        Some(self)
    }
}

impl AuthorizationExtension for HeaderExtension {
    fn extend(
        &mut self,
        _request: &dyn oxide_auth::code_grant::authorization::Request,
    ) -> std::result::Result<Extensions, ()> {
        let mut extensions = Extensions::new();
        // Set all extensions by using the header values
        for (n, v) in &self.headers {
            extensions.set_raw(n.to_string(), Value::Public(Some(v.to_string())));
        }
        Ok(extensions)
    }
}

/// An AccessTokenExtension that just copies all extensions from the authorize request.
struct CopyExtension {
}

impl Extension for CopyExtension {
    fn access_token(&mut self) -> Option<&mut dyn AccessTokenExtension> {
        Some(self)
    }
}

impl AccessTokenExtension for CopyExtension {
    fn extend(
        &mut self,
        _request: &dyn oxide_auth::code_grant::accesstoken::Request,
        data: oxide_auth::primitives::grant::Extensions,
    ) -> std::result::Result<oxide_auth::primitives::grant::Extensions, ()> {
        Ok(data)
    }
}

pub async fn authorize(
    (auth_request, http_req, state): (OAuthRequest, HttpRequest, web::Data<State>),
) -> Result<OAuthResponse, WebError> {
    let headers = http_req.headers().clone();
    let settings = state.settings.clone();
    let endpoint = state.endpoint().with_solicitor(FnSolicitor(
        move |_request: &mut OAuthRequest, _pre_grant: Solicitation| match &settings
            .mapping
            .sub_header
        {
            Some(sub_header) => {
                if let Some(remote_user) = headers.get(sub_header) {
                    if let Ok(remote_user) = remote_user.to_str() {
                        if !remote_user.is_empty() {
                            return OwnerConsent::Authorized(remote_user.to_string());
                        }
                    }
                }
                OwnerConsent::Denied
            }
            None => OwnerConsent::Authorized(settings.mapping.default_sub.clone()),
        },
    ));
    // Add all configured headers to map
    let headers: HashMap<_, _> = state
        .settings
        .mapping
        .include_headers
        .iter()
        .filter_map(|name| {
            if let Some(value) = http_req.headers().get(name) {
                Some((
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                ))
            } else {
                None
            }
        })
        .collect();
    let extension = HeaderExtension { headers };
    let extended = Extended::extend_with(endpoint, extension);

    AuthorizationFlow::prepare(extended)?
        .execute(auth_request)
        .map_err(WebError::from)
}

pub async fn token(
    (auth_request, state): (OAuthRequest, web::Data<State>),
) -> Result<OAuthResponse, WebError> {
    let endpoint = state.endpoint();

    // Just copy the extensions from the authorize request in our token
    let extension = CopyExtension {};

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
