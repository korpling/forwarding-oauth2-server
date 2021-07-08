use oxide_auth::primitives::prelude::*;
use oxide_auth::{
    endpoint::Scope,
    frontends::simple::endpoint::{Generic, Vacant},
};
use oxide_auth_actix::OAuthResponse;

use crate::errors::StartupError;

pub struct State {
    endpoint: Generic<
        ClientMap,
        AuthMap<RandomGenerator>,
        TokenMap<RandomGenerator>,
        Vacant,
        Vec<Scope>,
        fn() -> OAuthResponse,
    >,
}

impl State {
    pub fn new() -> Result<Self, StartupError> {
        let state = State {
            endpoint: Generic {
                registrar: vec![Client::public(
                    "ANNIS",
                    "http://localhost:5712".parse::<url::Url>()?.into(),
                    "default-scope".parse()?,
                )]
                .into_iter()
                .collect(),
                authorizer: AuthMap::new(RandomGenerator::new(16)),
                issuer: TokenMap::new(RandomGenerator::new(16)),
                solicitor: Vacant,
                scopes: vec!["default-scope".parse()?],
                response: OAuthResponse::ok,
            },
        };
        Ok(state)
    }
}
