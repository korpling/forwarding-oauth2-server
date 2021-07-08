use actix_web::{HttpResponse, web};
use oxide_auth_actix::OAuthRequest;

use crate::{errors::ServiceError, state::State};

pub async fn get_authorize((req, state): (OAuthRequest, web::Data<State>)) -> Result<HttpResponse, ServiceError> {
    todo!()
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
        let mut app =
            test::init_service(App::new().route("/authorize", web::get().to(get_authorize))).await;

        let req = test::TestRequest::with_header("content-type", "text/plain").to_request();
        let resp = test::call_service(&mut app, req).await;

        assert!(resp.status().is_success());
        let body = resp.response().body();
        match body {
            actix_web::dev::ResponseBody::Body(_) => todo!(),
            actix_web::dev::ResponseBody::Other(_) => todo!(),
        }
    }
}
