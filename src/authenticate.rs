use actix_web::HttpMessage;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    future::{ready, Ready},
    rc::Rc,
};

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use futures_util::future::LocalBoxFuture;

use crate::{
    environment::JWT_SECRET,
    errors::{Error, Result},
    utilities::get_time_millis,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserJwt {
    pub(crate) id: String,
    pub(crate) issued_at: u128,
    pub(crate) expires_at: u128,
}

#[derive(Clone, Debug)]
pub struct Authenticate {
    pub jwt: String,
    pub jwt_content: UserJwt,
}

pub struct JwtAuthentication;
impl<S, B> Transform<S, ServiceRequest> for JwtAuthentication
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = JwtMiddleware<S>;
    type Future = Ready<std::result::Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtMiddleware {
            service: service.into(),
        }))
    }
}

pub struct JwtMiddleware<S> {
    service: Rc<S>,
}

pub async fn validate_token(jwt: &String) -> Result<Authenticate> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::new();
    validation.validate_exp = false;
    let token_data = decode::<UserJwt>(
        jwt,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &validation,
    )?;

    let millis = get_time_millis();
    if millis > token_data.claims.expires_at {
        return Err(Error::InvalidToken);
    }
    let collection = crate::database::session::get_collection();
    let query = collection
        .find_one(doc! {
            "token": jwt
        })
        .await?;
    if query.is_some() {
        return Ok(Authenticate {
            jwt: jwt.to_string(),
            jwt_content: token_data.claims,
        });
    }
    Err(Error::InvalidToken)
}

pub async fn get_token(req: &ServiceRequest) -> Result<Authenticate> {
    let authorization = req
        .headers()
        .get("Authorization")
        .ok_or(Error::MissingToken)?;
    let jwt = &authorization.to_str().map_err(|_| Error::InvalidToken)?[7..];
    validate_token(&jwt.to_string()).await
}

impl<S, B> Service<ServiceRequest> for JwtMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, std::result::Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    fn call(self: &JwtMiddleware<S>, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        Box::pin(async move {
            let token = get_token(&req).await;
            req.extensions_mut().insert(token);
            svc.call(req).await
        })
    }
}
