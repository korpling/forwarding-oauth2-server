use crate::{init_app, settings::Settings};

use super::*;

use std::collections::HashMap;

use actix_web::{
    test::{self, read_body},
    web::{self, Buf},
    App,
};
use oxide_auth::code_grant::accesstoken::TokenResponse;
use serde::Serialize;
use url::Url;

#[derive(Serialize)]
struct TokenParams {
    grant_type: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    redirect_uri: String,
}

#[derive(Serialize)]
struct RefreshTokenParams {
    grant_type: String,
    refresh_token: String,
    client_id: String,
}

#[actix_rt::test]
async fn test_retrieve_token_with_header_sub() {
    let mut settings = Settings::default();
    settings.mapping.sub_header = Some("X-Remote-User".to_string());
    let state = init_app(&settings).unwrap();
    let mut app = test::init_service(
        App::new()
            .data(state)
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token))
            .route("/refresh", web::post().to(refresh)),
    )
    .await;

    let req = test::TestRequest::get().uri(
            "/authorize?response_type=code&client_id=default&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=default-scope")
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
        client_id: Some("default".to_string()),
        redirect_uri: "http://localhost:8080".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/token")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 200);

    let body = read_body(resp).await;
    let response: TokenResponse = serde_json::from_slice(body.bytes()).unwrap();

    assert!(response.access_token.is_some());
    assert!(response.refresh_token.is_some());
    assert_eq!(Some("bearer".to_string()), response.token_type);
    // TODO: when we use JWT token, the expiration must be in sync
    assert_eq!(true, response.expires_in.is_some());
    assert_eq!(Some("default-scope".to_string()), response.scope);

    // Try to refresh token with an invalid one
    let params = RefreshTokenParams {
        grant_type: "refresh_token".to_string(),
        refresh_token: "isnotarvalidfreshtoken".to_string(),
        client_id: "default".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/refresh")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 400);

    // Refresh the token with the actual token
    let params = RefreshTokenParams {
        grant_type: "refresh_token".to_string(),
        refresh_token: response.refresh_token.unwrap(),
        client_id: "default".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/refresh")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 200);

    let body = read_body(resp).await;

    let response: TokenResponse = serde_json::from_slice(body.bytes()).unwrap();

    assert!(response.access_token.is_some());
    assert!(response.refresh_token.is_some());
    assert_eq!(Some("bearer".to_string()), response.token_type);
    // TODO: when we use JWT token, the expiration must be in sync
    assert_eq!(true, response.expires_in.is_some());
    assert_eq!(Some("default-scope".to_string()), response.scope);
}

#[actix_rt::test]
async fn test_retrieve_token_without_header_sub() {
    let state = init_app(&Settings::default()).unwrap();
    let mut app = test::init_service(
        App::new()
            .data(state)
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token))
            .route("/refresh", web::post().to(refresh)),
    )
    .await;

    let req = test::TestRequest::get().uri(
            "/authorize?response_type=code&client_id=default&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=default-scope").to_request();
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
        client_id: Some("default".to_string()),
        redirect_uri: "http://localhost:8080".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/token")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 200);

    let body = read_body(resp).await;
    let response: TokenResponse = serde_json::from_slice(body.bytes()).unwrap();

    assert!(response.access_token.is_some());
    assert!(response.refresh_token.is_some());
    assert_eq!(Some("bearer".to_string()), response.token_type);
    // TODO: when we use JWT token, the expiration must be in sync
    assert_eq!(true, response.expires_in.is_some());
    assert_eq!(Some("default-scope".to_string()), response.scope);

    // Try to refresh token with an invalid one
    let params = RefreshTokenParams {
        grant_type: "refresh_token".to_string(),
        refresh_token: "isnotarvalidfreshtoken".to_string(),
        client_id: "default".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/refresh")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), 400);

    // Refresh the token with the actual token
    let params = RefreshTokenParams {
        grant_type: "refresh_token".to_string(),
        refresh_token: response.refresh_token.unwrap(),
        client_id: "default".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/refresh")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 200);

    let body = read_body(resp).await;

    let response: TokenResponse = serde_json::from_slice(body.bytes()).unwrap();

    assert!(response.access_token.is_some());
    assert!(response.refresh_token.is_some());
    assert_eq!(Some("bearer".to_string()), response.token_type);
    // TODO: when we use JWT token, the expiration must be in sync
    assert_eq!(true, response.expires_in.is_some());
    assert_eq!(Some("default-scope".to_string()), response.scope);
}

#[actix_rt::test]
async fn test_invalid_token_code() {
    let state = init_app(&Settings::default()).unwrap();

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
    let mut settings = Settings::default();
    settings.mapping.sub_header = Some("X-Remote-User".to_string());
    let state = init_app(&settings).unwrap();

    let mut app = test::init_service(
        App::new()
            .data(state)
            .route("/authorize", web::get().to(authorize)),
    )
    .await;

    let req = test::TestRequest::with_uri("/authorize?response_type=code&client_id=default&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=default-scope").to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 302);
    assert!(resp.headers().get("location").is_some());
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "http://localhost:8080/?error=access_denied");
}

#[actix_rt::test]
async fn test_check_confidential_client() {
    let mut settings = Settings::default();
    settings.client.secret = Some("abc".to_string());
    let state = init_app(&settings).unwrap();

    let mut app = test::init_service(
        App::new()
            .data(state)
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token))
    )
    .await;

    let req = test::TestRequest::get().uri(
            "/authorize?response_type=code&client_id=default&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=default-scope").to_request();
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
    let mut params = TokenParams {
        grant_type: "authorization_code".to_string(),
        code: code.to_string(),
        client_id: Some("default".to_string()),
        redirect_uri: "http://localhost:8080".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/token")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    // The client secret is missing and thus we should not get a token
    assert_eq!(resp.status(), 401);

    // Test again, but do neither provide a client id nor a secret
    params.client_id = None;
let req = test::TestRequest::post()
        .uri("/token")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 400);


    // Test with incorrect passphrase
    let req = test::TestRequest::post()
        .uri("/token")
        .header("Authorization", "Basic ZGVmYXVsdDpkZWYgLW4K")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 401);

    // Test again and provide the correct passphrase as HTTP Basic Auth header
    let req = test::TestRequest::post()
        .uri("/token")
        .header("Authorization", "Basic ZGVmYXVsdDphYmM=")
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 200);
}

