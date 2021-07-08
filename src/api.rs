use actix_web::HttpResponse;

use crate::errors::ServiceError;

pub async fn index() -> Result<HttpResponse, ServiceError> {
    unimplemented!()
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