use actix_web::{web, Responder};
use async_std::task;
use bcrypt::{hash, DEFAULT_COST};
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    errors::{Error, Result},
    utilities::{generate_continue_token_long, send_reset_email},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Forgot {
    stage: i8,
    email: Option<String>,
    new_password: Option<String>,
    continue_token: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgotResponse {
    success: bool,
}

pub struct PendingForgot {
    pub time: u64,
    pub user_id: String,
}

lazy_static! {
    pub static ref PENDING_FORGOTS: DashMap<String, PendingForgot> = DashMap::new();
}

pub async fn handle(forgot: web::Json<Forgot>) -> Result<impl Responder> {
    let forgot = forgot.into_inner();
    match forgot.stage {
        1 => {
            let collection = crate::database::user::get_collection();
            let Some(email) = forgot.email else {
                return Err(Error::MissingEmail);
            };
            let result = collection
                .find_one(doc! {
                    "email": email.clone()
                })
                .await?;
            if let Some(result) = result {
                let duration = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Unexpected error: time went backwards");
                let token = generate_continue_token_long();
                task::spawn(send_reset_email(email.clone(), token.clone()));
                PENDING_FORGOTS.insert(
                    token,
                    PendingForgot {
                        time: duration.as_secs(),
                        user_id: result.id,
                    },
                );
            }
            Ok(web::Json(ForgotResponse { success: true }))
        }
        2 => {
            let Some(continue_token) = forgot.continue_token else {
                return Err(Error::MissingContinueToken);
            };
            let forgot_session = PENDING_FORGOTS.get(&continue_token);
            let Some(forgot_session) = forgot_session else {
                return Err(Error::SessionExpired);
            };
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Unexpected error: time went backwards");
            if duration.as_secs() - forgot_session.time > 3600 {
                drop(forgot_session);
                PENDING_FORGOTS.remove(&continue_token);
                return Err(Error::SessionExpired);
            }
            let Some(password) = forgot.new_password else {
                return Err(Error::MissingPassword);
            };
            let new_password_hash =
                hash(password, DEFAULT_COST).expect("Unexpected error: failed to hash");
            let collection = crate::database::user::get_collection();
            collection
                .update_one(
                    doc! {
                        "id": forgot_session.user_id.clone()
                    },
                    doc! {
                        "$set": {
                            "password_hash": new_password_hash
                        }
                    },
                )
                .await?;
            drop(forgot_session);
            PENDING_FORGOTS.remove(&continue_token);
            Ok(web::Json(ForgotResponse { success: true }))
        }
        _ => Err(Error::InvalidStage),
    }
}
