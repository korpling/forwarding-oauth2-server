use actix_web::{web, HttpResponse};
use oxide_auth::{
    endpoint::{AuthorizationFlow, OwnerConsent, Solicitation},
    frontends::simple::endpoint::FnSolicitor,
};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, WebError};

use crate::{errors::ServiceError, state::State};

pub async fn get_authorize(
    (req, state): (OAuthRequest, web::Data<State>),
) -> Result<OAuthResponse, WebError> {
    let endpoint =
        state
            .endpoint()
            .with_solicitor(FnSolicitor(move |_: &mut _, _grant: Solicitation<'_>| {
                OwnerConsent::Denied
            }));

    AuthorizationFlow::prepare(endpoint)?
        .execute(req)
        .map_err(WebError::from)
}

pub async fn post_authorize() -> Result<HttpResponse, ServiceError> {
    todo!()
}

pub async fn token() -> Result<HttpResponse, ServiceError> {
    todo!()
}

pub async fn refresh() -> Result<HttpResponse, ServiceError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn test_get_authorize() {
        let state = State::new().unwrap();
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/authorize", web::get().to(get_authorize)),
        )
        .await;

        let req = test::TestRequest::with_uri("/authorize?response_type=code&client_id=ANNIS&redirect_uri=http%3A%2F%2Flocalhost%3A5712&scope=default-scope&state=23235253").to_request();
        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 302);
        assert!(resp.headers().get("location").is_some());
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(
            location,
            "http://localhost:5712/?state=23235253&error=access_denied"
        );
    }
}
