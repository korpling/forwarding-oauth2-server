mod api;
mod errors;

use actix_web::{
    middleware::{normalize::TrailingSlash, Logger, NormalizePath},
    web, App, HttpServer,
};
use log::{info, LevelFilter};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    info!("Starting up server");

    HttpServer::new(move || {
        App::new()
            .wrap(NormalizePath::new(TrailingSlash::Trim))
            .wrap(Logger::default())
            .service(
                web::resource("/authorize")
                    .route(web::get().to(api::get_authorize))
                    .route(web::post().to(api::post_authorize)),
            )
            .route("/token", web::post().to(api::token))
            .route("/refresh", web::post().to(api::refresh))
            .route("/", web::get().to(api::index))
    })
    .bind("localhost:8020")
    .expect("Failed to bind to socket")
    .run()
    .await
}
