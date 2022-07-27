use crate::{
    init_app,
    jwt::Claims,
    settings::{Settings, User},
};

use super::*;

use std::collections::HashMap;

use actix_web::{
    test::{self, read_body},
    web::{self, Data},
    App,
};
use jsonwebtoken::{TokenData, Validation};
use oxide_auth::code_grant::accesstoken::TokenResponse;
use serde::{Deserialize, Serialize};
use std::io::Write;
use tempfile::NamedTempFile;
use time::{Duration, OffsetDateTime};
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
async fn test_full_flow() {
    let settings = Settings::default();
    let state = init_app(&settings).unwrap();
    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(state))
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token))
            .route("/refresh", web::post().to(refresh))
            .route("/userinfo", web::get().to(userinfo)),
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
    let response: TokenResponse = serde_json::from_slice(&body).unwrap();

    assert!(response.access_token.is_some());
    let access_token_string = response.access_token.unwrap();
    let decoding = settings
        .client
        .token_verification
        .create_decoding_key()
        .unwrap();
    let access_token: TokenData<Claims> =
        jsonwebtoken::decode(&access_token_string, &decoding, &Validation::default()).unwrap();
    assert_eq!(settings.mapping.default_sub, access_token.claims.sub);

    assert!(response.refresh_token.is_some());
    assert_eq!(Some("bearer".to_string()), response.token_type);
    // when we use JWT token, the expiration must be in sync
    assert_eq!(true, response.expires_in.is_some());
    let expires_response = response.expires_in.unwrap();
    assert!(expires_response > 0);
    let should_expire_in = OffsetDateTime::now_utc() + Duration::seconds(expires_response);
    let time_diff = access_token.claims.exp.unwrap() - should_expire_in.unix_timestamp();
    // Should be the same +/- 5 seconds
    assert!(time_diff.abs() < 5);

    assert_eq!(Some("default-scope".to_string()), response.scope);

    // Validate token using userinfo endpoint
    let req = test::TestRequest::get()
        .uri("/userinfo")
        .append_header(("Authorization", format!("Bearer {}", &access_token_string)))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert_eq!(200, resp.status());

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

    let response: TokenResponse = serde_json::from_slice(&body).unwrap();

    assert!(response.access_token.is_some());
    let access_token: TokenData<Claims> = jsonwebtoken::decode(
        &response.access_token.unwrap(),
        &decoding,
        &Validation::default(),
    )
    .unwrap();
    assert_eq!(settings.mapping.default_sub, access_token.claims.sub);

    assert!(response.refresh_token.is_some());
    assert_eq!(Some("bearer".to_string()), response.token_type);

    // when we use JWT token, the expiration must be in sync
    assert_eq!(true, response.expires_in.is_some());
    let expires_in = response.expires_in.unwrap();
    assert!(expires_in > 0);
    let expires_utc = OffsetDateTime::now_utc() + Duration::seconds(expires_in);
    let time_diff = access_token.claims.exp.unwrap() - expires_utc.unix_timestamp();
    // Should be the same +/- 5 seconds
    assert!(time_diff.abs() < 5);

    assert_eq!(Some("default-scope".to_string()), response.scope);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsWithHeader {
    sub: String,
    exp: i64,
    boilerplate: String,
    admin: String,
}

#[actix_rt::test]
async fn test_retrieve_token_with_headers() {
    let mut settings = Settings::default();
    settings.mapping.sub_header = Some("X-Remote-User".to_string());
    settings.mapping.include_headers = vec!["X-Boilerplate".to_owned(), "meta-admin".to_owned()];

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "{}", include_str!("template-with-header.json")).unwrap();

    settings.mapping.token_template = Some(file.path().to_string_lossy().to_string());
    let state = init_app(&settings).unwrap();
    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(state))
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token)),
    )
    .await;

    let req = test::TestRequest::get().uri(
            "/authorize?response_type=code&client_id=default&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=default-scope")
            .append_header(("X-Remote-User", "testuser@example.com"))
            .append_header(("X-Boilerplate", "something")).append_header(("meta-admin", "true")).to_request();
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
    let response: TokenResponse = serde_json::from_slice(&body).unwrap();

    assert!(response.access_token.is_some());

    let access_token = response.access_token.unwrap();
    let decoding = settings
        .client
        .token_verification
        .create_decoding_key()
        .unwrap();
    let access_token: TokenData<ClaimsWithHeader> =
        jsonwebtoken::decode(&access_token, &decoding, &Validation::default()).unwrap();
    assert_eq!("testuser@example.com", access_token.claims.sub);

    assert_eq!("something", access_token.claims.boilerplate);
    assert_eq!("true", access_token.claims.admin);

    assert!(response.refresh_token.is_some());
    assert_eq!(Some("bearer".to_string()), response.token_type);
    assert_eq!(true, response.expires_in.is_some());
    assert_eq!(Some("default-scope".to_string()), response.scope);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsWithGroups {
    sub: String,
    exp: i64,
    groups: Vec<String>,
    roles: Vec<String>,
}

#[actix_rt::test]
async fn test_retrieve_token_with_groups() {
    let mut settings = Settings::default();
    settings.mapping.sub_header = Some("X-Remote-User".to_string());

    let u = User {
        id: "testuser@example.com".to_string(),
        groups: vec![
            "public".to_string(),
            "academic".to_string(),
            "sensitive".to_string(),
        ],
        roles: vec!["administrator".to_string()],
    };
    settings.mapping.users.push(u);

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "{}", include_str!("template-with-groups.json")).unwrap();

    settings.mapping.token_template = Some(file.path().to_string_lossy().to_string());
    let state = init_app(&settings).unwrap();
    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(state))
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token)),
    )
    .await;

    let req = test::TestRequest::get().uri(
            "/authorize?response_type=code&client_id=default&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=default-scope")
            .append_header(("X-Remote-User", "testuser@example.com")).to_request();
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
    let response: TokenResponse = serde_json::from_slice(&body).unwrap();

    assert!(response.access_token.is_some());

    let access_token = response.access_token.unwrap();
    let decoding = settings
        .client
        .token_verification
        .create_decoding_key()
        .unwrap();
    let access_token: TokenData<ClaimsWithGroups> =
        jsonwebtoken::decode(&access_token, &decoding, &Validation::default()).unwrap();
    assert_eq!("testuser@example.com", access_token.claims.sub);

    assert_eq!(3, access_token.claims.groups.len());
    assert_eq!("public", access_token.claims.groups[0]);
    assert_eq!("academic", access_token.claims.groups[1]);
    assert_eq!("sensitive", access_token.claims.groups[2]);

    assert_eq!(1, access_token.claims.roles.len());
    assert_eq!("administrator", access_token.claims.roles[0]);

    // Repeat the token process with a non configured user
    let req = test::TestRequest::get().uri(
        "/authorize?response_type=code&client_id=default&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=default-scope")
        .append_header(("X-Remote-User", "someone")).to_request();
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
    let response: TokenResponse = serde_json::from_slice(&body).unwrap();

    assert!(response.access_token.is_some());

    let access_token = response.access_token.unwrap();
    let decoding = settings
        .client
        .token_verification
        .create_decoding_key()
        .unwrap();
    let access_token: TokenData<ClaimsWithGroups> =
        jsonwebtoken::decode(&access_token, &decoding, &Validation::default()).unwrap();
    assert_eq!("someone", access_token.claims.sub);
    assert_eq!(0, access_token.claims.groups.len());
    assert_eq!(0, access_token.claims.roles.len());
}

#[actix_rt::test]
async fn test_invalid_refresh() {
    let settings = Settings::default();
    let state = init_app(&settings).unwrap();
    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(state))
            .route("/refresh", web::post().to(refresh)),
    )
    .await;
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
}

#[actix_rt::test]
async fn test_invalid_token_code() {
    let state = init_app(&Settings::default()).unwrap();

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(state))
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
async fn test_invalid_userinfo() {
    let state = init_app(&Settings::default()).unwrap();

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(state))
            .route("/userinfo", web::get().to(userinfo)),
    )
    .await;

    // Test without header
    let req = test::TestRequest::get().uri("/userinfo").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert_eq!(401, resp.status());

    // Test with empty string
    let req = test::TestRequest::get()
        .uri("/userinfo")
        .append_header(("Authorization", "Bearer "))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert_eq!(403, resp.status());

    // Test with claims signed with an invalid secret
    let req = test::TestRequest::get()
        .uri("/userinfo")
        .append_header(("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MjcwNDI0NTcsImlhdCI6MTYyNzA0MDY1N30.4HWAx0mlPdqkvgpVVQ5i_3dHbownxyeywSjS7dBldjM"))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert_eq!(403, resp.status());
}

#[actix_rt::test]
async fn test_authorize_no_header() {
    let mut settings = Settings::default();
    settings.mapping.sub_header = Some("X-Remote-User".to_string());
    let state = init_app(&settings).unwrap();

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(state))
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
            .app_data(Data::new(state))
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token)),
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
        .append_header(("Authorization", "Basic ZGVmYXVsdDpkZWYgLW4K"))
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 401);

    // Test again and provide the correct passphrase as HTTP Basic Auth header
    let req = test::TestRequest::post()
        .uri("/token")
        .append_header(("Authorization", "Basic ZGVmYXVsdDphYmM="))
        .set_form(&params)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), 200);
}
