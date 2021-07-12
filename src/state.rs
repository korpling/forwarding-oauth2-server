use std::sync::Mutex;

use crate::errors::StartupError;
use crate::jwt::JWTIssuer;
use crate::settings::Settings;
use oxide_auth::frontends::simple::endpoint::{Generic, Vacant};
use oxide_auth::primitives::prelude::*;

pub struct State {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<JWTIssuer>,
}

impl State {
    pub fn endpoint(&self) -> Generic<impl Registrar + '_, impl Authorizer + '_, impl Issuer + '_> {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            solicitor: Vacant,
            scopes: Vacant,
            response: Vacant,
        }
    }

    pub fn new(settings: &Settings) -> Result<Self, StartupError> {
        let registrar = vec![Client::public(
            &settings.client.id,
            settings.client.redirect_uri.parse::<url::Url>()?.into(),
            "default-scope".parse()?,
        )]
        .into_iter()
        .collect();
        let authorizer = AuthMap::new(RandomGenerator::new(16));
        let issuer = JWTIssuer::new(settings.clone());
        let state = State {
            registrar: Mutex::new(registrar),
            issuer: Mutex::new(issuer),
            authorizer: Mutex::new(authorizer),
        };
        Ok(state)
    }
}
