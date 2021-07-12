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
                OwnerConsent::Authorized("tk".to_string())
//                OwnerConsent::Denied
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
mod tests {
    use std::collections::HashMap;

    use super::*;
    use actix_web::{
        dev::{Body, ResponseBody},
        test, web, App,
    };
    use url::Url;

    #[actix_rt::test]
    async fn test_retrieve_token() {
        let state = State::new().unwrap();
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/authorize", web::get().to(authorize))
                .route("/token", web::post().to(token)),
        )
        .await;

        let req = test::TestRequest::get().uri(
            "/authorize?response_type=code&client_id=ANNIS&redirect_uri=http%3A%2F%2Flocalhost%3A5712&scope=default-scope&state=23235253")
            .header("X-Remote-User", "testuser@example.com").to_request();
        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 302);
        assert!(resp.headers().get("location").is_some());
        let location = resp.headers().get("location").unwrap().to_str().unwrap();

        // Parse result and extract the code we need to get the actual token
        let location = Url::parse(location).unwrap();
        let params: HashMap<String, String> = location
            .query_pairs()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();

        let code = params.get("code").unwrap();

        // Use the code to request a token
        let req = test::TestRequest::post()
            .uri(&format!(
                "/token?grant_type=authorization_code&code={}",
                code
            ))
            .to_request();
        let mut resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 200);

        if let ResponseBody::Body(body) = resp.take_body() {
            match body {
                Body::Bytes(content) => {
                    // TODO: Decode the content and check its a valid JWT token
                    dbg!(content);
                }
                _ => panic!("Invalid response body content type"),
            }
        } else {
            panic!("Invalid response body type, should have been ResponseBody::Body")
        }
    }

    #[actix_rt::test]
    async fn test_invalid_token_code() {
        let state = State::new().unwrap();
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/token", web::post().to(token)),
        )
        .await;
        // Try a non-empty, but not known code value
        let req = test::TestRequest::post()
            .uri("/token?grant_type=authorization_code&code=invalid")
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), 400);

        // Also try not to give the parameter or an empty one
        let req = test::TestRequest::post()
            .uri("/token?grant_type=authorization_code")
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), 400);

        let req = test::TestRequest::post().uri("/token").to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), 400);

        let req = test::TestRequest::post()
            .uri("/token?grant_type=authorization_code&code=")
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_authorize_no_header() {
        let state = State::new().unwrap();
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/authorize", web::get().to(authorize)),
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
