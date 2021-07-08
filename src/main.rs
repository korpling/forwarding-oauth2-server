mod api;
pub mod errors;
mod state;

use actix_web::{
    middleware::{normalize::TrailingSlash, Logger, NormalizePath},
    web, App, HttpServer,
};
use log::{info, LevelFilter};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

use crate::state::State;

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e) )?;

    info!("Starting up server");
    let state =
        State::new().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let state = web::Data::new(state);

    HttpServer::new(move || {
        App::new()
            .data(state.clone())
            .wrap(NormalizePath::new(TrailingSlash::Trim))
            .wrap(Logger::default())
            .service(
                web::resource("/authorize")
                    .route(web::get().to(api::get_authorize))
                    .route(web::post().to(api::post_authorize)),
            )
            .route("/token", web::post().to(api::token))
            .route("/refresh", web::post().to(api::refresh))
    })
    .bind("localhost:8020")
    .expect("Failed to bind to socket")
    .run()
    .await
}
