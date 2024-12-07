use actix_web::{web, Responder};
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::{self, doc, Binary};
use opaque_ke::{RegistrationRequest, RegistrationUpload};
use serde::{Deserialize, Serialize};

use crate::{
    authenticate::Authenticate,
    errors::{Error, Result},
    opaque::{begin_registration, finish_registration},
    utilities::{generate_continue_token_long, get_time_secs, validate_escalation},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "stage")]
#[repr(i8)]
pub enum UpdatePassword {
    BeginUpdate {
        escalation_token: String,
        message: Vec<u8>,
    } = 2,
    FinishUpdate {
        continue_token: String,
        message: Vec<u8>,
    } = 3,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum UpdatePasswordResponse {
    BeginUpdate {
        continue_token: String,
        message: Vec<u8>,
    },
    FinishUpdate {},
}

pub struct PendingUpdate {
    pub time: u64,
    pub email: String,
}

lazy_static! {
    pub static ref PENDING_UPDATES: DashMap<String, PendingUpdate> = DashMap::new();
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    register: web::Json<UpdatePassword>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let register = register.into_inner();
    match register {
        UpdatePassword::BeginUpdate {
            escalation_token,
            message,
        } => {
            validate_escalation(escalation_token, jwt.jwt).await?;
            let user_collection = crate::database::user::get_collection();
            let user = user_collection
                .find_one(doc! {
                    "id": jwt.jwt_content.id.clone()
                })
                .await?
                .ok_or(Error::DatabaseError)?;
            let result = begin_registration(
                user.email.clone(),
                RegistrationRequest::deserialize(&message)?,
            )
            .await?;
            let continue_token = generate_continue_token_long();
            PENDING_UPDATES.insert(
                continue_token.clone(),
                PendingUpdate {
                    time: get_time_secs(),
                    email: user.email.clone(),
                },
            );
            Ok(web::Json(UpdatePasswordResponse::BeginUpdate {
                continue_token,
                message: result,
            }))
        }
        UpdatePassword::FinishUpdate {
            message,
            continue_token,
        } => {
            if let Some(session) = PENDING_UPDATES.get(&continue_token) {
                if get_time_secs() - session.time > 600 {
                    PENDING_UPDATES.remove(&continue_token);
                    return Err(Error::SessionExpired);
                }
                let password_data =
                    finish_registration(RegistrationUpload::deserialize(&message)?)?;
                let binary = Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: password_data,
                };
                let user_collection = crate::database::user::get_collection();
                user_collection
                    .update_one(
                        doc! {
                            "id": session.email.clone()
                        },
                        doc! {
                            "$set": {
                                "password_data": binary,
                            }
                        },
                    )
                    .await?;
                PENDING_UPDATES.remove(&continue_token);
                return Ok(web::Json(UpdatePasswordResponse::FinishUpdate {}));
            }
            Err(Error::InvalidToken)
        }
    }
}
