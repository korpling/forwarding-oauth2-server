use actix_web::HttpResponse;

use crate::errors::ServiceError;

pub async fn index() -> Result<HttpResponse, ServiceError> {
    Ok(HttpResponse::Ok()
        .content_type("text/plain")
        .body("Welcome"))
}

pub async fn get_authorize() -> Result<HttpResponse, ServiceError> {
    unimplemented!()
}

pub async fn post_authorize() -> Result<HttpResponse, ServiceError> {
    unimplemented!()
}

pub async fn token() -> Result<HttpResponse, ServiceError> {
    unimplemented!()
}

pub async fn refresh() -> Result<HttpResponse, ServiceError> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn test_index_get() {
        let mut app = test::init_service(App::new().route("/", web::get().to(index))).await;
        let req = test::TestRequest::with_header("content-type", "text/plain").to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success());
    }
}
