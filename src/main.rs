mod api;
mod errors;
mod jwt;
mod settings;
mod state;

use actix_web::{
    middleware::{normalize::TrailingSlash, Logger, NormalizePath},
    web, App, HttpServer,
};
use clap::Arg;
use errors::StartupError;
use log::{info, warn, LevelFilter};
use simplelog::{ColorChoice, Config, SimpleLogger, TermLogger, TerminalMode};

use crate::{settings::Settings, state::State};

fn init_app() -> std::result::Result<(settings::Settings, State), StartupError> {
    // Parse CLI arguments
    let matches = clap::App::new("shibboleth-oauth2-forwarding")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("OAuth2 server for wrapping Shibboleth IdPs")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .help("Configuration file location")
                .takes_value(true),
        )
        .get_matches();

    // Load configuration file(s)
    let settings = if let Some(path) = matches.value_of_lossy("config") {
        confy::load_path(path.to_string())?
    } else {
        Settings::default()
    };

    let log_filter = if settings.logging.debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let mut log_config = simplelog::ConfigBuilder::new();
    if settings.logging.debug {
        warn!("Enabling request logging to console in debug mode");
    } else {
        log_config.add_filter_ignore_str("actix_web:");
    }

    let log_config = log_config.build();

    if let Err(e) = TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ) {
        println!("Error, can't initialize the terminal log output: {}.\nWill degrade to a more simple logger", e);
        if let Err(e_simple) = SimpleLogger::init(log_filter, log_config) {
            println!("Simple logging failed too: {}", e_simple);
        }
    }

    info!("Logging with level {}", log_filter);

    let state = State::new(&settings)?;

    Ok((settings, state))
}

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    let (settings, state) = init_app().map_err(StartupError::into_io)?;
    let state = web::Data::new(state);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(NormalizePath::new(TrailingSlash::Trim))
            .wrap(Logger::default())
            .service(
                web::resource("/authorize")
                    .route(web::get().to(api::authorize))
                    .route(web::post().to(api::authorize)),
            )
            .route("/token", web::post().to(api::token))
            .route("/refresh", web::post().to(api::refresh))
    })
    .bind(format!("{}:{}", settings.bind.host, settings.bind.port))
    .expect("Failed to bind to socket")
    .run()
    .await
}
