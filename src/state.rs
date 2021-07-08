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

    pub fn with_solicitor<'a, S>(
        &'a mut self,
        solicitor: S,
    ) -> impl Endpoint<OAuthRequest, Error = WebError> + 'a
    where
        S: OwnerSolicitor<OAuthRequest> + 'static,
    {
        ErrorInto::new(Generic {
            authorizer: &mut self.endpoint.authorizer,
            registrar: &mut self.endpoint.registrar,
            issuer: &mut self.endpoint.issuer,
            solicitor,
            scopes: &mut self.endpoint.scopes,
            response: OAuthResponse::ok,
        })
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
        let (op, ex) = msg.into_inner();

        match ex {
            Extras::AuthGet => {
                let solicitor =
                    FnSolicitor(move |_: &mut OAuthRequest, pre_grant: Solicitation| {
                        // This will display a page to the user asking for his permission to proceed. The submitted form
                        // will then trigger the other authorization handler which actually completes the flow.
                        OwnerConsent::InProgress(
                            OAuthResponse::ok().content_type("text/html").unwrap().body(
                                &"TODO",
                            ),
                        )
                    });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::AuthPost(query_string) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: Solicitation| {
                    if query_string.contains("allow") {
                        OwnerConsent::Authorized("dummy user".to_owned())
                    } else {
                        OwnerConsent::Denied
                    }
                });

                op.run(self.with_solicitor(solicitor))
            }
            _ => op.run(&mut self.endpoint),
        }
    }
}
