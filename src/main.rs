mod api;
mod errors;
mod jwt;
mod settings;
mod state;

use std::ffi::OsString;

use actix_web::{
    middleware::{Logger, NormalizePath, TrailingSlash},
    web, App, HttpServer,
};
use clap::{Arg, ArgSettings};
use errors::StartupError;
use log::{warn, LevelFilter};
use simplelog::{ColorChoice, Config, SimpleLogger, TermLogger, TerminalMode};

use crate::{settings::Settings, state::State};

fn init_app(settings: &Settings) -> std::result::Result<State, StartupError> {
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

    let state = State::new(&settings)?;
    Ok(state)
}

fn init_app_from_args<I, T>(
    args: I,
) -> std::result::Result<(settings::Settings, State), StartupError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // Parse CLI arguments
    let matches = clap::App::new("forwarding-oauth2-server")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("OAuth2 server for wrapping Shibboleth IdPs")
        .arg(
            Arg::with_name("config")
                .short('c')
                .long("config")
                .help("Configuration file location")
                .setting(ArgSettings::AllowInvalidUtf8)
                .takes_value(true),
        )
        .get_matches_from(args);

    // Load configuration file(s)
    let settings = if let Some(path) = matches.value_of_lossy("config") {
        Settings::with_file(path.to_string())?
    } else {
        Settings::default()
    };

    let state = init_app(&settings)?;

    Ok((settings, state))
}

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    let (settings, state) =
        init_app_from_args(std::env::args_os()).map_err(StartupError::into_io)?;

    let state = web::Data::new(state);

    let server = HttpServer::new(move || {
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
            .route("/userinfo", web::get().to(api::userinfo))
    })
    .bind(format!("{}:{}", settings.bind.host, settings.bind.port))
    .expect("Failed to bind to socket");

    server.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn partial_partial_config_file() -> Result<(), Box<dyn std::error::Error>> {
        let mut file = NamedTempFile::new()?;
        writeln!(
            file,
            r#"
    [client]
    doesnotexist = "something"
    id = "anotherid"
    "#
        )?;

        let test_args: Vec<OsString> =
            vec!["thisprogram".into(), "--config".into(), file.path().into()];
        let result = init_app_from_args(test_args);

        // The invalid field should be ignored, the client ID should be set
        assert!(result.is_ok());
        let (settings, _state) = result.unwrap();

        assert_eq!("anotherid", settings.client.id);
        Ok(())
    }
}
