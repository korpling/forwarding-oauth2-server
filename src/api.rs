use actix_web::{web, HttpRequest};
use oxide_auth::{
    endpoint::{AccessTokenFlow, AuthorizationFlow, OwnerConsent, RefreshFlow, Solicitation},
    frontends::simple::endpoint::FnSolicitor,
};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, WebError};

use crate::state::State;

pub async fn authorize(
    (auth_request, http_req, state): (OAuthRequest, HttpRequest, web::Data<State>),
) -> Result<OAuthResponse, WebError> {
    let endpoint =
        state
            .endpoint()
            .with_solicitor(FnSolicitor(move |_: &mut _, _grant: Solicitation<'_>| {
                if let Some(remote_user) = http_req.headers().get("X-Remote-User") {
                    if let Ok(remote_user) = remote_user.to_str() {
                        if !remote_user.is_empty() {
                            return OwnerConsent::Authorized(remote_user.to_string());
                        }
                    }
                }
                OwnerConsent::Denied
            }));

    AuthorizationFlow::prepare(endpoint)?
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
