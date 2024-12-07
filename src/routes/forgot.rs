use actix_web::{web, Responder};
use async_std::task;
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::{self, doc, Binary};
use opaque_ke::{RegistrationRequest, RegistrationUpload};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{Error, Result},
    opaque::{begin_registration, finish_registration},
    utilities::{generate_continue_token_long, get_time_secs, send_reset_email},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "stage")]
#[repr(i8)]
pub enum Forgot {
    VerifyEmail {
        email: String,
    } = 1,
    ResetPassword {
        continue_token: String,
        message: Vec<u8>,
    } = 2,
    FinishReset {
        continue_token: String,
        message: Vec<u8>,
    } = 3,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum ForgotResponse {
    VerifyEmail {},
    ResetPassword {
        continue_token: String,
        message: Vec<u8>,
    },
    FinishReset {},
}

pub struct PendingForgot {
    pub time: u64,
    pub user_id: String,
    pub email: String,
}

lazy_static! {
    pub static ref PENDING_FORGOTS1: DashMap<String, PendingForgot> = DashMap::new();
    pub static ref PENDING_FORGOTS2: DashMap<String, PendingForgot> = DashMap::new();
}

pub async fn handle(forgot: web::Json<Forgot>) -> Result<impl Responder> {
    let forgot = forgot.into_inner();
    match forgot {
        Forgot::VerifyEmail { email } => {
            let collection = crate::database::user::get_collection();
            let result = collection
                .find_one(doc! {
                    "email": email.clone()
                })
                .await?;
            if let Some(result) = result {
                let token = generate_continue_token_long();
                task::spawn(send_reset_email(email.clone(), token.clone()));
                PENDING_FORGOTS1.insert(
                    token,
                    PendingForgot {
                        time: get_time_secs(),
                        user_id: result.id,
                        email,
                    },
                );
            }
            Ok(web::Json(ForgotResponse::VerifyEmail {}))
        }
        Forgot::ResetPassword {
            continue_token,
            message,
        } => {
            let forgot_session = PENDING_FORGOTS1.get(&continue_token);
            let Some(forgot_session) = forgot_session else {
                return Err(Error::SessionExpired);
            };
            if get_time_secs() - forgot_session.time > 3600 {
                drop(forgot_session);
                PENDING_FORGOTS1.remove(&continue_token);
                return Err(Error::SessionExpired);
            }
            let result = begin_registration(
                forgot_session.email.clone(),
                RegistrationRequest::deserialize(&message)?,
            )
            .await?;
            PENDING_FORGOTS1.remove(&continue_token);
            let new_continue_token = generate_continue_token_long();
            PENDING_FORGOTS2.insert(
                new_continue_token.clone(),
                PendingForgot {
                    time: get_time_secs(),
                    user_id: forgot_session.user_id.clone(),
                    email: forgot_session.email.clone(),
                },
            );
            drop(forgot_session);
            Ok(web::Json(ForgotResponse::ResetPassword {
                continue_token: new_continue_token.clone(),
                message: result,
            }))
        }
        Forgot::FinishReset {
            continue_token,
            message,
        } => {
            let Some(session) = PENDING_FORGOTS2.get(&continue_token) else {
                return Err(Error::SessionExpired);
            };
            if get_time_secs() - session.time > 600 {
                PENDING_FORGOTS2.remove(&continue_token);
                return Err(Error::SessionExpired);
            }
            let password_data = finish_registration(RegistrationUpload::deserialize(&message)?)?;
            let bin = Binary {
                bytes: password_data,
                subtype: bson::spec::BinarySubtype::Generic,
            };
            let collection = crate::database::user::get_collection();
            collection
                .update_one(
                    doc! {
                        "id": session.user_id.clone()
                    },
                    doc! {
                        "$set": {
                            "password_data": bin
                        }
                    },
                )
                .await?;
            Ok(web::Json(ForgotResponse::FinishReset {}))
        }
    }
}
