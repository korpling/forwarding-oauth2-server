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
mod tests {
    use std::collections::HashMap;

    use super::*;
    use actix_web::{
        test::{self, read_body},
        web::{self, Buf},
        App,
    };
    use serde::{Deserialize, Serialize};
    use url::Url;

    #[derive(Serialize)]
    struct TokenParams {
        grant_type: String,
        code: String,
        client_id: String,
        redirect_uri: String,
    }

    #[derive(Serialize)]
    struct RefreshTokenParams {
        grant_type: String,
        refresh_token: String,
        client_id: String,
    }

    #[derive(Deserialize)]
    struct TokenResult {
        access_token: String,
        refresh_token: String,
        token_type: String,
        expires_in: i64,
        scope: String,
    }

    #[derive(Deserialize)]
    struct RefreshTokenResult {
        access_token: String,
        token_type: String,
        expires_in: i64,
        scope: String,
    }

    #[actix_rt::test]
    async fn test_retrieve_token() {
        let state = State::new().unwrap();
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/authorize", web::get().to(authorize))
                .route("/token", web::post().to(token))
                .route("/refresh", web::post().to(refresh)),

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
        let params = TokenParams {
            grant_type: "authorization_code".to_string(),
            code: code.to_string(),
            client_id: "ANNIS".to_string(),
            redirect_uri: "http://localhost:5712".to_string(),
        };
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(&params)
            .to_request();
        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 200);

        let body = read_body(resp).await;
        let response: TokenResult = serde_json::from_slice(body.bytes()).unwrap();

        assert_eq!(false, response.access_token.is_empty());
        assert_eq!(false, response.refresh_token.is_empty());
        assert_eq!("bearer", response.token_type);
        assert!(response.expires_in > 0);
        assert_eq!("default-scope", response.scope);

        // Refresh the token
        let params = RefreshTokenParams {
            grant_type: "refresh_token".to_string(),
            refresh_token: response.refresh_token.to_string(),
            client_id: "ANNIS".to_string(),
        };
        let req = test::TestRequest::post()
            .uri("/refresh")
            .set_form(&params)
            .to_request();
        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), 200);

        let body = read_body(resp).await;

        let response: RefreshTokenResult = serde_json::from_slice(body.bytes()).unwrap();
        assert_eq!(false, response.access_token.is_empty());
        assert_eq!("bearer", response.token_type);
        assert!(response.expires_in > 0);
        assert_eq!("default-scope", response.scope);
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
