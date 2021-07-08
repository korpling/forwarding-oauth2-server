use actix::{Actor, Context, Handler};
use oxide_auth::endpoint::{Endpoint, OwnerConsent, OwnerSolicitor, Solicitation};
use oxide_auth::frontends::simple::endpoint::{ErrorInto, FnSolicitor};
use oxide_auth::primitives::prelude::*;
use oxide_auth::{
    endpoint::Scope,
    frontends::simple::endpoint::{Generic, Vacant},
};
use oxide_auth_actix::{OAuthMessage, OAuthOperation, OAuthRequest, OAuthResponse, WebError};

use crate::errors::StartupError;
use crate::Extras;

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

impl Actor for State {
    type Context = Context<Self>;
}

impl<Op> Handler<OAuthMessage<Op, Extras>> for State
where
    Op: OAuthOperation,
{
    type Result = Result<Op::Item, Op::Error>;

    fn handle(&mut self, msg: OAuthMessage<Op, Extras>, _: &mut Self::Context) -> Self::Result {
        let (op, _) = msg.into_inner();

        op.run(&mut self.endpoint)
    }
}
